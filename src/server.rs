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
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use zeroize::Zeroizing;

use std::sync::OnceLock;

use crate::config;
use crate::credentials::Credentials;
use crate::tls::TlsMode;

/// Global AppState — initialized once via OnceLock instead of Box::leak.
/// Provides &'static access without leaking heap memory.
static APP_STATE: OnceLock<AppState> = OnceLock::new();

/// Timeout for DB operations in HTTP handlers. Must exceed SQLite busy_timeout (4s)
/// so that SQLite returns BUSY cleanly before the task gets force-cancelled.
const DB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const MAX_INPUT_LEN: usize = 256;

/// Circuit breaker cool-down: DB operations rejected for this many seconds after last failure.
const DB_CIRCUIT_COOLDOWN_SECS: u64 = 60;

fn epoch_secs() -> u64 {
    config::epoch_secs()
}

/// Const lookup table for printable ASCII validation.
/// No branches per byte, cache-friendly, auto-vectorizes on x86_64.
const ASCII_OK: [bool; 256] = {
    let mut table = [false; 256];
    let mut i: usize = 32; // space
    while i <= 126 {
        table[i] = true;
        i += 1;
    }
    table
};

/// Reject inputs with non-printable or non-ASCII characters.
fn is_valid_input(s: &str) -> bool {
    s.len() > 0
        && s.len() <= MAX_INPUT_LEN
        && s.bytes().all(|b| ASCII_OK[b as usize])
}

pub struct AppState {
    pub agent_json_cached: bytes::Bytes,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    /// Zeroized on drop. Derived from the private key via HKDF.
    vault_key: Zeroizing<[u8; 32]>,
    /// Connection pool — use `db_pool.get()` inside `spawn_blocking`.
    pub db_pool: crate::db::DbPool,
    pub tls_active: bool,
    pub behind_proxy: bool,
    /// In-flight request counter for graceful shutdown drain.
    in_flight: std::sync::atomic::AtomicUsize,
    /// Circuit breaker: epoch second of last DB failure. Circuit open if within cooldown.
    last_db_failure: std::sync::atomic::AtomicU64,
}

impl AppState {
    pub fn vault_key(&self) -> &[u8; 32] {
        &self.vault_key
    }

    /// Record a DB failure timestamp. The first request after the cooldown naturally tests the DB.
    fn record_db_failure(&self) {
        self.last_db_failure.store(epoch_secs(), Ordering::Relaxed);
    }

    /// Record a successful DB operation. Clears the circuit breaker.
    fn record_db_success(&self) {
        if self.last_db_failure.load(Ordering::Relaxed) != 0 {
            self.last_db_failure.store(0, Ordering::Relaxed);
        }
    }

    /// Circuit is open if last failure was within the cooldown window.
    /// No half-open probe needed: the first request after cooldown naturally tests the DB.
    fn is_db_circuit_open(&self) -> bool {
        let last = self.last_db_failure.load(Ordering::Relaxed);
        last != 0 && epoch_secs().saturating_sub(last) < DB_CIRCUIT_COOLDOWN_SECS
    }
}

#[derive(Serialize)]
struct DepositResponse {
    status: &'static str,
    label: String,
}

/// Max deposit body size: 64 KB — sufficient for secrets, API keys, certs.
/// Tighter than the original 1MB to limit allocation before input validation.
const MAX_BODY_SIZE: usize = 64 * 1024;

pub async fn run_server(credentials: Credentials) -> Result<()> {
    // --- Startup checks ---

    // Warn if log file is getting large (risk of disk-full on vault writes)
    if let Ok(log_path) = config::log_path() {
        if let Ok(metadata) = std::fs::metadata(&log_path) {
            let size_mb = metadata.len() / (1024 * 1024);
            if size_mb > 100 {
                tracing::warn!(
                    "Log file is {size_mb}MB ({}), consider rotating",
                    log_path.display()
                );
            }
        }
    }

    // --- State setup ---

    let agent_json_path = config::agent_json_path()?;
    let agent_json_cached: bytes::Bytes = std::fs::read_to_string(&agent_json_path)
        .with_context(|| format!("Failed to read agent.json at {}", agent_json_path.display()))?
        .into();

    let verifying_key = credentials.verifying_key()?;
    let signing_key = credentials.signing_key()?;
    let sk_bytes = Zeroizing::new(signing_key.to_bytes());
    let vault_key = crate::crypto::vault::derive_vault_key(&sk_bytes)?;
    drop(sk_bytes);

    // Pool size: env override or auto-detect from available parallelism (capped 2..8)
    let pool_size = std::env::var("ATOMIC_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| (1..=64).contains(&n))
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get().clamp(2, 8))
                .unwrap_or(4)
        });
    let db_pool = crate::db::open_pool(pool_size)?;

    let addr = SocketAddr::from(([0, 0, 0, 0], credentials.port));
    let tls_mode = TlsMode::from_credentials(&credentials)?;

    let tls_active = !matches!(tls_mode, TlsMode::None);

    let behind_proxy = credentials.proxy;

    APP_STATE.set(AppState {
        agent_json_cached,
        verifying_key,
        vault_key,
        db_pool,
        tls_active,
        behind_proxy,
        in_flight: std::sync::atomic::AtomicUsize::new(0),
        last_db_failure: std::sync::atomic::AtomicU64::new(0),
    }).map_err(|_| anyhow::anyhow!("server already initialized"))?;
    let state: &'static AppState = APP_STATE.get().unwrap();

    // Background task: hourly cleanup of expired deposit data + PRAGMA optimize.
    // WAL checkpointing is handled by wal_autocheckpoint=1000 (set in open_connection).
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let _ = tokio::task::spawn_blocking(move || {
                let conn = match state.db_pool.get() {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("DB cleanup: pool exhausted: {e}");
                        return;
                    }
                };
                let now = epoch_secs() as i64;
                let cutoff = now - 7 * 86400;
                loop {
                    match conn.execute(
                        "DELETE FROM used_deposits WHERE rowid IN \
                         (SELECT rowid FROM used_deposits WHERE used_at < ?1 LIMIT 1000)",
                        [cutoff],
                    ) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(e) => { tracing::warn!("Failed to clean old deposit nonces: {e}"); break; }
                    }
                }
                let log_cutoff = now - 90 * 86400;
                loop {
                    match conn.execute(
                        "DELETE FROM deposit_log WHERE rowid IN \
                         (SELECT rowid FROM deposit_log WHERE deposited_at < ?1 LIMIT 1000)",
                        [log_cutoff],
                    ) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(e) => { tracing::warn!("Failed to clean old deposit log entries: {e}"); break; }
                    }
                }
                let _ = conn.execute_batch("PRAGMA optimize;");
            }).await;
        }
    });

    // CORS only on the public agent.json endpoint; deposit endpoints
    // are called by servers, not browsers, and don't need CORS.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let shutdown_state = state;

    let public_routes = Router::new()
        .route("/.well-known/agent.json", get(serve_agent_json))
        .layer(cors);

    let app = Router::new()
        .route("/", get(root_redirect))
        .merge(public_routes)
        .route("/d/{token}", post(handle_deposit))
        .route("/_/health", get(handle_health))
        .fallback(handle_404)
        .layer(middleware::from_fn_with_state(
            state,
            track_in_flight,
        ))
        .layer(middleware::from_fn(request_timeout))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state,
            security_headers,
        ))
        .with_state(state);

    let pid_path = config::pid_path()?;
    // Acquire flock — prevents double-start races. Lock released on process exit (even crash).
    let _pid_lock = config::acquire_pid_lock(&pid_path)?;

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
        TlsMode::Custom { .. } => {
            let rustls_config = crate::tls::resolve_rustls_config(&tls_mode).await?;
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
            });
            info!("Listening on {} (HTTPS, PID {})", addr, std::process::id());
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("TLS server error")?;
        }
    }

    // Drain phase: wait for in-flight requests to complete before checkpointing WAL.
    // The graceful shutdown above stops new connections; this ensures handlers finish.
    {
        let drain_start = std::time::Instant::now();
        let drain_timeout = std::time::Duration::from_secs(30);
        loop {
            let remaining = shutdown_state.in_flight.load(Ordering::SeqCst);
            if remaining == 0 {
                break;
            }
            if drain_start.elapsed() > drain_timeout {
                tracing::warn!("Drain timeout: {remaining} requests still in-flight");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // Signal pool to reject new acquisitions and wake any threads waiting on Condvar.
    shutdown_state.db_pool.shutdown();

    // Final WAL checkpoint after all handlers have drained.
    // Timeout prevents indefinite hang if the DB is stuck.
    let checkpoint_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            match shutdown_state.db_pool.get() {
                Ok(conn) => {
                    // RESTART checkpoints and resets the WAL header without truncating.
                    // Safer than TRUNCATE which can block indefinitely if readers exist.
                    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(RESTART);") {
                        tracing::warn!("Final WAL RESTART checkpoint failed: {e}, falling back to PASSIVE");
                        if let Err(e2) = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
                            tracing::warn!("Final WAL PASSIVE checkpoint also failed: {e2}");
                        }
                    }
                }
                Err(e) => tracing::warn!("Final WAL checkpoint skipped: {e}"),
            }
        })
    ).await;
    if checkpoint_result.is_err() {
        tracing::error!("Final WAL checkpoint timed out (5s) — data is consistent but may remain in WAL file");
    }

    let _ = std::fs::remove_file(&pid_path);
    info!("Server stopped");
    Ok(())
}

async fn root_redirect() -> Redirect {
    Redirect::temporary("/.well-known/agent.json")
}

async fn serve_agent_json(State(state): State<&'static AppState>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        state.agent_json_cached.clone(),
    )
        .into_response()
}

// Verify the signed token, store the POST body in the vault under the encoded label.
async fn handle_deposit(
    State(state): State<&'static AppState>,
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

    // Circuit breaker: reject immediately if DB is known-broken (disk full, corrupt, etc.)
    // Returns uniform 404 to prevent information leakage about internal state.
    if state.is_db_circuit_open() {
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

    // DB operations in spawn_blocking with timeout to prevent unbounded task accumulation.
    // Access vault_key via the &'static AppState reference inside the closure
    // to avoid copying the key out of its Zeroizing wrapper.
    let body_clone = body;
    let deposit_result = tokio::time::timeout(
        DB_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            let conn = state.db_pool.get()?;
            crate::deposit::claim_nonce_with_conn(&payload, &conn)?;
            crate::vault::vault_set_with_conn(&conn, &payload.label, &body_clone, state.vault_key())?;
            crate::deposit::log_deposit(&conn, &payload.label, &source_ip, &user_agent)?;
            Ok::<_, anyhow::Error>(payload.label)
        })
    ).await;

    match deposit_result {
        Err(_elapsed) => {
            tracing::error!("Deposit handler timed out");
            state.record_db_failure();
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(Ok(Ok(label))) => {
            state.record_db_success();
            info!("Deposit received: '{label}'");
            let resp = DepositResponse { status: "deposited", label };
            match serde_json::to_string(&resp) {
                Ok(json) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json).into_response(),
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        Ok(Ok(Err(e))) => {
            let msg = e.to_string();
            if msg.contains("Nonce already used") {
                tracing::debug!("Deposit replay rejected");
            } else {
                tracing::error!("Deposit failed: {e}");
                state.record_db_failure();
            }
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("Deposit task panicked: {e}");
            state.record_db_failure();
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn handle_health(State(state): State<&'static AppState>) -> Response {
    // Check DB is responsive (with timeout)
    let db_ok = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::task::spawn_blocking({
            move || match state.db_pool.get() {
                Ok(conn) => conn.execute_batch("SELECT 1").is_ok(),
                Err(_) => false,
            }
        })
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or(false);

    // Check agent.json is valid JSON
    let agent_ok = serde_json::from_slice::<serde_json::Value>(&state.agent_json_cached).is_ok();

    // Check WAL size is under control (< 50MB)
    let wal_ok = crate::config::atomic_dir()
        .map(|d| d.join("atomic.db-wal"))
        .ok()
        .and_then(|p| std::fs::metadata(&p).ok())
        .map(|m| m.len() < 50 * 1024 * 1024)
        .unwrap_or(true); // WAL not existing is fine

    // Check disk space (>100MB free) to prevent SQLite "disk full" corruption
    let disk_ok = crate::config::atomic_dir()
        .ok()
        .and_then(|d| fs2::available_space(&d).ok())
        .map(|avail| avail > 100 * 1024 * 1024)
        .unwrap_or(true); // If we can't check, assume ok

    if db_ok && agent_ok && wal_ok && disk_ok {
        (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], r#"{"status":"ok"}"#).into_response()
    } else {
        let detail = format!(
            r#"{{"status":"degraded","db":{},"agent_json":{},"wal_size_ok":{},"disk_space_ok":{}}}"#,
            db_ok, agent_ok, wal_ok, disk_ok
        );
        (StatusCode::SERVICE_UNAVAILABLE, [(header::CONTENT_TYPE, "application/json")], detail).into_response()
    }
}

async fn handle_404() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Track in-flight requests for graceful shutdown drain.
async fn track_in_flight(
    State(state): State<&'static AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    state.in_flight.fetch_add(1, Ordering::Relaxed);
    let resp = next.run(req).await;
    state.in_flight.fetch_sub(1, Ordering::Relaxed);
    resp
}

/// Global request timeout (30s) — defense-in-depth against slow clients or stuck handlers.
async fn request_timeout(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    match tokio::time::timeout(std::time::Duration::from_secs(30), next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

async fn security_headers(
    State(state): State<&'static AppState>,
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
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
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
