use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use zeroize::Zeroizing;

use crate::config;
use crate::credentials::Credentials;
use crate::tls::TlsMode;

/// Spawn a supervised background task that restarts on panic/error with backoff.
fn spawn_supervised<F, Fut>(name: &'static str, make_task: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let result = tokio::spawn(make_task()).await;
            match result {
                Ok(()) => break, // clean exit
                Err(e) => {
                    tracing::error!("{name} task panicked: {e}. Restarting in 5s...");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });
}

const RATE_LIMIT_WINDOW_SECS: i64 = 60;
const RATE_LIMIT_MAX_REQUESTS: u32 = 10;
const RATE_LIMIT_MAX_ENTRIES: usize = 10_000;
const MAX_INPUT_LEN: usize = 256;

/// Reject inputs with non-printable characters or excessive length.
fn is_valid_input(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_INPUT_LEN
        && s.bytes().all(|b| b >= 0x20 && b != 0x7F)
}

pub struct AppState {
    pub agent_json_cached: bytes::Bytes,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    /// Zeroized on drop. Derived from the private key via HKDF.
    vault_key: Zeroizing<[u8; 32]>,
    /// Only lock inside `spawn_blocking` — never hold across an `.await`.
    pub db: std::sync::Mutex<rusqlite::Connection>,
    pub tls_active: bool,
    pub behind_proxy: bool,
    rate_limiter: std::sync::Mutex<HashMap<IpAddr, (u32, i64)>>,
}

impl AppState {
    pub fn vault_key(&self) -> &[u8; 32] {
        &self.vault_key
    }

    /// Returns true if the request is within rate limits.
    pub fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut map = self.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        // Evict stale entries when the map grows too large to prevent memory exhaustion
        if map.len() >= RATE_LIMIT_MAX_ENTRIES {
            map.retain(|_, (_, window_start)| now - *window_start <= RATE_LIMIT_WINDOW_SECS);
        }
        let entry = map.entry(ip).or_insert((0, now));
        if now - entry.1 > RATE_LIMIT_WINDOW_SECS {
            *entry = (1, now);
            true
        } else if entry.0 >= RATE_LIMIT_MAX_REQUESTS {
            false
        } else {
            entry.0 += 1;
            true
        }
    }
}

#[derive(Serialize)]
struct DepositResponse {
    status: &'static str,
    label: String,
}

#[derive(Serialize)]
struct MagicLinkResponse {
    status: &'static str,
}

/// Max deposit body size: 1 MB
const MAX_BODY_SIZE: usize = 1024 * 1024;

pub async fn run_server(credentials: Credentials) -> Result<()> {
    let agent_json_path = config::agent_json_path()?;
    let agent_json_cached: bytes::Bytes = std::fs::read_to_string(&agent_json_path)
        .with_context(|| format!("Failed to read agent.json at {}", agent_json_path.display()))?
        .into();

    let verifying_key = credentials.verifying_key()?;
    let signing_key = credentials.signing_key()?;
    let mut sk_bytes = Zeroizing::new(signing_key.to_bytes());
    let vault_key = crate::crypto::vault::derive_vault_key(&sk_bytes)?;
    sk_bytes.iter_mut().for_each(|b| *b = 0); // belt-and-suspenders
    drop(sk_bytes);
    let db_conn = crate::db::open()?;

    let addr = SocketAddr::from(([0, 0, 0, 0], credentials.port));
    let tls_mode = TlsMode::from_credentials(&credentials);

    let tls_active = !matches!(tls_mode, TlsMode::None);

    let behind_proxy = credentials.proxy;

    let state = Arc::new(AppState {
        agent_json_cached,
        verifying_key,
        vault_key,
        db: std::sync::Mutex::new(db_conn),
        tls_active,
        behind_proxy,
        rate_limiter: std::sync::Mutex::new(HashMap::with_capacity(256)),
    });

    // Background task: WAL checkpoint every 5 minutes to prevent unbounded WAL growth
    let wal_state = state.clone();
    spawn_supervised("wal-checkpoint", move || {
        let st = wal_state.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let db_ref = st.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let conn = db_ref.db.lock().unwrap_or_else(|e| e.into_inner());
                    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                        tracing::warn!("WAL checkpoint failed: {e}");
                    }
                }).await;
            }
        }
    });

    // Background task: clean expired magic links, old deposit nonces, and stale rate limiter entries
    let cleanup_state = state.clone();
    spawn_supervised("db-cleanup", move || {
        let st = cleanup_state.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                let db_ref = st.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let conn = db_ref.db.lock().unwrap_or_else(|e| e.into_inner());
                    let now = chrono::Utc::now().timestamp();
                    if let Err(e) = conn.execute("DELETE FROM magic_links WHERE expires_at <= ?1", [now]) {
                        tracing::warn!("Failed to clean expired magic links: {e}");
                    }
                    let cutoff = now - 7 * 86400;
                    if let Err(e) = conn.execute("DELETE FROM used_deposits WHERE used_at < ?1", [cutoff]) {
                        tracing::warn!("Failed to clean old deposit nonces: {e}");
                    }
                    // Evict stale rate limiter entries
                    let mut map = db_ref.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
                    let now = chrono::Utc::now().timestamp();
                    map.retain(|_, (_, window_start)| now - *window_start <= RATE_LIMIT_WINDOW_SECS);
                }).await;
            }
        }
    });

    // CORS only on the public agent.json endpoint; deposit and magic link
    // endpoints are called by servers, not browsers, and don't need CORS.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let shutdown_state = state.clone();

    let public_routes = Router::new()
        .route("/.well-known/agent.json", get(serve_agent_json))
        .layer(cors);

    let app = Router::new()
        .route("/", get(root_redirect))
        .merge(public_routes)
        .route("/d/{token}", post(handle_deposit))
        .route("/m/{code}", get(handle_magic_link))
        .route("/_/health", get(handle_health))
        .fallback(handle_404)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state);

    let pid_path = config::pid_path()?;
    config::write_secure(&pid_path, std::process::id().to_string().as_bytes())?;

    match tls_mode {
        TlsMode::None => {
            info!("Listening on {} (HTTP, PID {})", addr, std::process::id());
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("Failed to bind to {addr}"))?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
                .with_graceful_shutdown(shutdown_signal())
                .await
                .context("Server error")?;
        }
        TlsMode::Auto { .. } | TlsMode::Custom { .. } => {
            let is_auto = matches!(tls_mode, TlsMode::Auto { .. });
            let rustls_config = crate::tls::resolve_rustls_config(&tls_mode).await?;
            if is_auto {
                crate::tls::spawn_renewal_watcher(rustls_config.clone());
            }
            // Reload TLS cert on SIGHUP (works for both auto and custom certs)
            #[cfg(unix)]
            {
                let sighup_config = rustls_config.clone();
                tokio::spawn(async move {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut sighup = signal(SignalKind::hangup())
                        .expect("Failed to install SIGHUP handler");
                    loop {
                        sighup.recv().await;
                        let tls_dir = match crate::config::tls_dir() {
                            Ok(d) => d,
                            Err(e) => {
                                tracing::warn!("SIGHUP cert reload failed: {e}");
                                continue;
                            }
                        };
                        let cert_path = tls_dir.join("fullchain.pem");
                        let key_path = tls_dir.join("key.pem");
                        match sighup_config.reload_from_pem_file(&cert_path, &key_path).await {
                            Ok(()) => info!("TLS cert reloaded (SIGHUP)"),
                            Err(e) => tracing::warn!("TLS cert reload failed (SIGHUP): {e}"),
                        }
                    }
                });
            }
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
            });
            let mode_label = if is_auto { "acme.sh" } else { "custom cert" };
            info!("Listening on {} (HTTPS/{}, PID {})", addr, mode_label, std::process::id());
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("TLS server error")?;
        }
    }

    // Final WAL checkpoint before exit to ensure all data is merged
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(conn) = shutdown_state.db.lock() {
            if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                tracing::warn!("Final WAL checkpoint failed: {e}");
            }
        }
    }).await;

    let _ = std::fs::remove_file(&pid_path);
    info!("Server stopped");
    Ok(())
}

async fn root_redirect() -> Redirect {
    Redirect::temporary("/.well-known/agent.json")
}

async fn serve_agent_json(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        state.agent_json_cached.clone(),
    )
        .into_response()
}

// Verify the signed token, store the POST body in the vault under the encoded label.
async fn handle_deposit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: String,
) -> Response {
    let verifying_key = state.verifying_key;

    // Verify signature + expiry (no DB needed yet)
    let payload = match crate::deposit::verify_signature(&token, &verifying_key) {
        Some(p) => p,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Reject empty body or labels with non-printable/overlong content
    if body.is_empty() || !is_valid_input(&payload.label) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Only trust X-Forwarded-For when running behind a known reverse proxy.
    // Parse the rightmost entry as IpAddr to reject spoofed non-IP values.
    let source_ip = if state.behind_proxy {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.rsplit(',')
                    .next()
                    .and_then(|s| s.trim().parse::<IpAddr>().ok())
            })
            .unwrap_or_else(|| addr.ip())
            .to_string()
    } else {
        // Warn once if XFF header is present without proxy mode — likely misconfiguration
        if headers.contains_key("x-forwarded-for") {
            tracing::warn_span!("deposit").in_scope(|| {
                tracing::warn!(
                    "X-Forwarded-For header present but behind_proxy=false; \
                     ignoring header and using direct IP. \
                     If behind a reverse proxy, re-init with --proxy."
                );
            });
        }
        addr.ip().to_string()
    };
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // DB operations in spawn_blocking.
    // Access vault_key via the Arc<AppState> reference inside the closure
    // to avoid copying the key out of its Zeroizing wrapper.
    let state_clone = state.clone();
    let body_clone = body;
    let deposit_result = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db.lock()
            .map_err(|e| anyhow::anyhow!("DB mutex poisoned: {e}"))?;
        crate::deposit::claim_nonce_with_conn(&payload, &conn)?;
        crate::vault::vault_set_with_conn(&conn, &payload.label, &body_clone, state_clone.vault_key())?;
        crate::deposit::log_deposit(&conn, &payload.label, &source_ip, &user_agent)?;
        Ok::<_, anyhow::Error>(payload.label)
    }).await;

    match deposit_result {
        Ok(Ok(label)) => {
            info!("Deposit received: '{label}'");
            let resp = DepositResponse { status: "deposited", label };
            match serde_json::to_string(&resp) {
                Ok(json) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json).into_response(),
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            if msg.contains("Nonce already used") {
                tracing::debug!("Deposit replay rejected");
            } else {
                tracing::error!("Deposit failed: {e}");
            }
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Deposit task panicked: {e}");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn handle_magic_link(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(code): Path<String>,
) -> Response {
    // Per-IP rate limiting to prevent brute-force of magic link codes
    if !state.check_rate_limit(addr.ip()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Reject obviously short codes or codes with non-printable chars before touching the DB
    if code.len() < 20 || !is_valid_input(&code) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let state_clone = state.clone();
    let code_clone = code;
    let result = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db.lock()
            .map_err(|e| anyhow::anyhow!("DB mutex poisoned: {e}"))?;
        Ok::<_, anyhow::Error>(crate::magic_link::claim_with_conn(&code_clone, &conn))
    }).await;

    match result {
        Ok(Ok(Some(_))) => {
            let resp = MagicLinkResponse { status: "verified" };
            match serde_json::to_string(&resp) {
                Ok(json) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json).into_response(),
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("Magic link DB error: {e}");
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("Magic link task panicked: {e}");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Response {
    // Check DB is responsive
    let db_ok = {
        let st = state.clone();
        tokio::task::spawn_blocking(move || {
            let conn = st.db.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute_batch("SELECT 1").is_ok()
        })
        .await
        .unwrap_or(false)
    };

    // Check agent.json is valid JSON
    let agent_ok = serde_json::from_slice::<serde_json::Value>(&state.agent_json_cached).is_ok();

    if db_ok && agent_ok {
        (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], r#"{"status":"ok"}"#).into_response()
    } else {
        let detail = format!(
            r#"{{"status":"degraded","db":{},"agent_json":{}}}"#,
            db_ok, agent_ok
        );
        (StatusCode::SERVICE_UNAVAILABLE, [(header::CONTENT_TYPE, "application/json")], detail).into_response()
    }
}

async fn handle_404() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn security_headers(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'"),
    );
    if state.tls_active {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
    resp
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                if let Err(e) = r {
                    tracing::error!("CTRL+C handler error: {e}");
                }
            }
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    }
    info!("Shutdown signal received");
}
