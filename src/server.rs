use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::config;
use crate::credentials::Credentials;
use crate::deposit::DepositManager;

pub struct AppState {
    pub agent_json_path: std::path::PathBuf,
    pub deposit_manager: DepositManager,
    pub credentials: Credentials,
}

pub async fn run_server(credentials: Credentials) -> Result<()> {
    let agent_json_path = config::agent_json_path()?;
    let deposit_manager = DepositManager::new(100);
    let addr = SocketAddr::from(([0, 0, 0, 0], credentials.port));

    let state = Arc::new(AppState {
        agent_json_path,
        deposit_manager,
        credentials,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root_redirect))
        .route("/.well-known/agent.json", get(serve_agent_json))
        .route("/d/{token}", post(handle_deposit))
        .fallback(handle_404)
        .layer(cors)
        .with_state(state);

    let pid_path = config::pid_path()?;
    std::fs::write(&pid_path, std::process::id().to_string())
        .with_context(|| format!("Failed to write PID file {}", pid_path.display()))?;

    info!("Listening on {} (PID {})", addr, std::process::id());
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    let _ = std::fs::remove_file(&pid_path);
    info!("Server stopped");
    Ok(())
}

// Naked domain -> agent.json
async fn root_redirect() -> Redirect {
    Redirect::temporary("/.well-known/agent.json")
}

async fn serve_agent_json(State(state): State<Arc<AppState>>) -> Response {
    match std::fs::read_to_string(&state.agent_json_path) {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// Claim the one-time token, store the body in the vault.
async fn handle_deposit(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    body: String,
) -> Response {
    let label = match state.deposit_manager.claim(&token).await {
        Some(label) => label,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty body").into_response();
    }

    let signing_key = match state.credentials.signing_key() {
        Ok(k) => k,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let vault_path = match config::vault_path() {
        Ok(p) => p,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut vault = match crate::vault::VaultStore::load(&vault_path, &signing_key.to_bytes()) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    vault.set(label.clone(), body);

    if vault.save(&vault_path).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let _ = append_deposit_log(&label);
    info!("Deposit received: '{}'", label);

    let response = serde_json::json!({
        "status": "deposited",
        "label": label,
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        response.to_string(),
    )
        .into_response()
}

fn append_deposit_log(label: &str) -> Result<()> {
    use std::io::Write;
    let log_path = config::deposits_log_path()?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(
        file,
        "{}\t{}\tdeposited",
        chrono::Utc::now().to_rfc3339(),
        label,
    )?;
    Ok(())
}

async fn handle_404() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    info!("Shutdown signal received");
}
