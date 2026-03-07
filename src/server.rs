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
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::config;
use crate::credentials::Credentials;
use crate::tls::TlsMode;

pub struct AppState {
    pub agent_json_cached: bytes::Bytes,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub vault_key: [u8; 32],
    pub db: std::sync::Mutex<rusqlite::Connection>,
    pub tls_active: bool,
}

#[derive(Serialize)]
struct DepositResponse {
    status: &'static str,
    label: String,
}

#[derive(Serialize)]
struct MagicLinkResponse {
    status: &'static str,
    code: String,
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
    let vault_key = crate::crypto::vault::derive_vault_key(&signing_key.to_bytes())?;
    let db_conn = crate::db::open()?;

    let addr = SocketAddr::from(([0, 0, 0, 0], credentials.port));
    let tls_mode = TlsMode::from_credentials(&credentials);

    let tls_active = !matches!(tls_mode, TlsMode::None);

    let state = Arc::new(AppState {
        agent_json_cached,
        verifying_key,
        vault_key,
        db: std::sync::Mutex::new(db_conn),
        tls_active,
    });

    // Background task: clean expired magic links + old deposit nonces every hour
    let db_clone = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            let db_ref = db_clone.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(conn) = db_ref.db.lock() {
                    let now = chrono::Utc::now().timestamp();
                    let _ = conn.execute("DELETE FROM magic_links WHERE expires_at <= ?1", [now]);
                    let cutoff = now - 7 * 86400;
                    let _ = conn.execute("DELETE FROM used_deposits WHERE used_at < ?1", [cutoff]);
                }
            }).await;
        }
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root_redirect))
        .route("/.well-known/agent.json", get(serve_agent_json))
        .route("/d/{token}", post(handle_deposit))
        .route("/m/{code}", get(handle_magic_link))
        .fallback(handle_404)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(cors)
        .with_state(state);

    let pid_path = config::pid_path()?;
    std::fs::write(&pid_path, std::process::id().to_string())
        .with_context(|| format!("Failed to write PID file {}", pid_path.display()))?;

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
        TlsMode::Auto { .. } => {
            let rustls_config = crate::tls::resolve_rustls_config(&tls_mode).await?;
            crate::tls::spawn_renewal_watcher(rustls_config.clone());
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            info!("Listening on {} (HTTPS/acme.sh, PID {})", addr, std::process::id());
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("TLS server error")?;
        }
        TlsMode::Custom { .. } => {
            let rustls_config = crate::tls::resolve_rustls_config(&tls_mode).await?;
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            info!("Listening on {} (HTTPS/custom cert, PID {})", addr, std::process::id());
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .context("TLS server error")?;
        }
    }

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
    let vault_key = state.vault_key;

    // Verify signature + expiry (no DB needed yet)
    let payload = match crate::deposit::verify_signature(&token, &verifying_key) {
        Some(p) => p,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    if body.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // DB operations in spawn_blocking
    let label = payload.label.clone();
    let state_clone = state.clone();
    let body_clone = body;
    let deposit_result = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db.lock()
            .map_err(|e| anyhow::anyhow!("DB mutex poisoned: {e}"))?;
        crate::deposit::claim_nonce_with_conn(&payload, &conn)?;
        crate::vault::vault_set_with_conn(&conn, &payload.label, &body_clone, &vault_key)?;
        crate::deposit::log_deposit(&conn, &payload.label, &source_ip, &user_agent)
    }).await;

    match deposit_result {
        Ok(Ok(())) => {},
        Ok(Err(e)) => {
            let err_msg = format!("{e}");
            if err_msg.contains("replay") || err_msg.contains("Nonce already used") {
                return StatusCode::NOT_FOUND.into_response();
            }
            tracing::error!("Deposit failed: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(e) => {
            tracing::error!("Deposit task panicked: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    info!("Deposit received: '{label}'");

    let resp = DepositResponse { status: "deposited", label };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&resp).unwrap(),
    )
        .into_response()
}

async fn handle_magic_link(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> Response {
    let state_clone = state.clone();
    let code_clone = code;
    let result = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db.lock()
            .map_err(|e| anyhow::anyhow!("DB mutex poisoned: {e}"))?;
        Ok::<_, anyhow::Error>(crate::magic_link::claim_with_conn(&code_clone, &conn))
    }).await;

    match result {
        Ok(Ok(Some(verified_code))) => {
            let resp = MagicLinkResponse { status: "verified", code: verified_code };
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_string(&resp).unwrap(),
            )
                .into_response()
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            tracing::error!("Magic link DB error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(e) => {
            tracing::error!("Magic link task panicked: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
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
    if state.tls_active {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
    resp
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    info!("Shutdown signal received");
}
