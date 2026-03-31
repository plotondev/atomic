use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use serde::Serialize;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use zeroize::Zeroizing;

use crate::config;
use crate::credentials::Credentials;
use crate::tls::TlsMode;

/// Max restarts within the circuit breaker window before we abort the process.
const SUPERVISOR_MAX_RESTARTS: u32 = 5;
/// Circuit breaker window: if SUPERVISOR_MAX_RESTARTS occur within this duration, fail-fast.
const SUPERVISOR_WINDOW_SECS: u64 = 300; // 5 minutes

/// Timeout for DB operations in HTTP handlers. Must exceed SQLite busy_timeout (4s)
/// so that SQLite returns BUSY cleanly before the task gets force-cancelled.
const DB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn a supervised background task that restarts on panic/error with exponential backoff.
/// Circuit breaker: if 5 restarts occur within 5 minutes, enter max backoff (320s) instead
/// of killing the process — process::exit skips destructors, preventing Zeroizing from
/// wiping vault keys and the final WAL checkpoint from running.
fn spawn_supervised<F, Fut>(name: &'static str, make_task: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut retries: u32 = 0;
        let mut window_start = std::time::Instant::now();
        let mut window_restarts: u32 = 0;
        let mut circuit_open = false;
        loop {
            let result = tokio::spawn(make_task()).await;
            match result {
                Ok(()) => break, // clean exit
                Err(e) => {
                    let now = std::time::Instant::now();
                    // Reset circuit breaker window if enough time has passed
                    if now.duration_since(window_start).as_secs() > SUPERVISOR_WINDOW_SECS {
                        window_start = now;
                        window_restarts = 0;
                        if circuit_open {
                            tracing::info!("{name}: circuit breaker reset after quiet period");
                            circuit_open = false;
                            retries = 0;
                        }
                    }
                    window_restarts += 1;
                    if window_restarts >= SUPERVISOR_MAX_RESTARTS && !circuit_open {
                        tracing::error!(
                            "{name}: circuit breaker OPEN — {SUPERVISOR_MAX_RESTARTS} failures in {SUPERVISOR_WINDOW_SECS}s, entering max backoff"
                        );
                        circuit_open = true;
                    }

                    let delay_secs = if circuit_open {
                        320 // Max backoff while circuit is open
                    } else {
                        5_u64.saturating_mul(1u64 << retries.min(6)) // 5s, 10s, 20s, ..., 320s
                    };
                    tracing::error!("{name} task panicked: {e}. Restarting in {delay_secs}s ({window_restarts}/{SUPERVISOR_MAX_RESTARTS} in window)...");
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    retries = retries.saturating_add(1);
                }
            }
        }
    });
}

const RATE_LIMIT_WINDOW_SECS: u64 = 60;
const RATE_LIMIT_MAX_REQUESTS: u32 = 10;
const RATE_LIMIT_MAX_ENTRIES: usize = 10_000;
const MAGIC_LINK_GLOBAL_MAX_PER_SEC: u32 = 20;
const MAX_INPUT_LEN: usize = 256;

/// Consecutive DB failures before the circuit breaker opens.
const DB_CIRCUIT_THRESHOLD: u32 = 5;
/// How long (seconds) the circuit stays open before allowing a probe request.
const DB_CIRCUIT_OPEN_SECS: u64 = 30;

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
    /// Connection pool — use `db_pool.get()` inside `spawn_blocking`.
    pub db_pool: crate::db::DbPool,
    pub tls_active: bool,
    pub behind_proxy: bool,
    /// Sharded concurrent map — no global mutex contention under high concurrency.
    /// Uses monotonic Instant (not wall clock) to prevent clock-skew manipulation.
    rate_limiter: DashMap<IpAddr, (u32, std::time::Instant)>,
    /// Global rate limit for magic link claims (epoch second of current window).
    magic_link_window: std::sync::atomic::AtomicI64,
    /// Count of magic link claims in the current 1-second window.
    magic_link_count: std::sync::atomic::AtomicU32,
    /// Circuit breaker: consecutive DB operation failure count.
    db_fail_count: std::sync::atomic::AtomicU32,
    /// Circuit breaker: epoch second when circuit opened (0 = closed).
    db_circuit_opened_at: std::sync::atomic::AtomicU64,
}

impl AppState {
    pub fn vault_key(&self) -> &[u8; 32] {
        &self.vault_key
    }

    /// Returns true if the request is within rate limits.
    /// Uses DashMap (sharded locks) so concurrent requests don't serialize on a global mutex.
    /// Monotonic Instant prevents clock-skew attacks from resetting windows.
    pub fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        // Hard cap: if full, try to evict one expired entry before rejecting.
        // Prevents attackers from permanently blocking legitimate IPs by filling the map.
        if self.rate_limiter.len() >= RATE_LIMIT_MAX_ENTRIES {
            let stale_key = self.rate_limiter.iter()
                .find(|entry| now.duration_since(entry.value().1) > window)
                .map(|entry| *entry.key());
            match stale_key {
                Some(key) => { self.rate_limiter.remove(&key); }
                None => return false,
            }
        }
        let mut entry = self.rate_limiter.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > window {
            *entry = (1, now);
            true
        } else if entry.0 >= RATE_LIMIT_MAX_REQUESTS {
            false
        } else {
            entry.0 += 1;
            true
        }
    }

    /// Record a DB operation failure. Opens the circuit after DB_CIRCUIT_THRESHOLD consecutive failures.
    fn record_db_failure(&self) {
        let count = self.db_fail_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if count >= DB_CIRCUIT_THRESHOLD {
            let now = epoch_secs();
            let prev = self.db_circuit_opened_at.load(std::sync::atomic::Ordering::Relaxed);
            if prev == 0 {
                self.db_circuit_opened_at.store(now, std::sync::atomic::Ordering::Relaxed);
                tracing::error!("DB circuit breaker OPEN after {count} consecutive failures");
            }
        }
    }

    /// Record a successful DB operation. Resets the circuit breaker.
    fn record_db_success(&self) {
        self.db_fail_count.store(0, std::sync::atomic::Ordering::Relaxed);
        if self.db_circuit_opened_at.load(std::sync::atomic::Ordering::Relaxed) != 0 {
            self.db_circuit_opened_at.store(0, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("DB circuit breaker closed after successful operation");
        }
    }

    /// Returns true if the circuit is open (DB operations should be rejected).
    fn is_db_circuit_open(&self) -> bool {
        let opened_at = self.db_circuit_opened_at.load(std::sync::atomic::Ordering::Relaxed);
        if opened_at == 0 {
            return false;
        }
        // Allow a probe request after the cool-down period (half-open state)
        epoch_secs().saturating_sub(opened_at) < DB_CIRCUIT_OPEN_SECS
    }

    /// Global rate limit for magic link claim attempts (across all IPs).
    /// Prevents distributed brute-force even if each IP stays under per-IP limits.
    fn check_magic_link_global_rate(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        let window = self.magic_link_window.load(std::sync::atomic::Ordering::Relaxed);
        if window != now {
            self.magic_link_window.store(now, std::sync::atomic::Ordering::Relaxed);
            self.magic_link_count.store(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        let count = self.magic_link_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count < MAGIC_LINK_GLOBAL_MAX_PER_SEC
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
    // --- Startup checks ---

    // Enforce file descriptor limit: raise soft limit toward 65535 if below 4096.
    // Without enough fds, a connection spike causes "too many open files" crashes.
    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
            let current = rlim.rlim_cur;
            if current < 4096 {
                let target = rlim.rlim_max.min(65535);
                if target >= 4096 {
                    rlim.rlim_cur = target;
                    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } == 0 {
                        tracing::info!("Raised RLIMIT_NOFILE soft limit: {current} → {target}");
                    } else {
                        tracing::warn!(
                            "Failed to raise RLIMIT_NOFILE from {current} to {target}"
                        );
                    }
                } else {
                    anyhow::bail!(
                        "RLIMIT_NOFILE hard limit is {} (need ≥4096). Raise with: ulimit -n 4096",
                        rlim.rlim_max
                    );
                }
            }
        }
    }

    // Fix 8: Warn if log file is getting large (risk of disk-full on vault writes)
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
    let mut sk_bytes = Zeroizing::new(signing_key.to_bytes());
    let vault_key = crate::crypto::vault::derive_vault_key(&sk_bytes)?;
    sk_bytes.iter_mut().for_each(|b| *b = 0); // belt-and-suspenders
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
    let tls_mode = TlsMode::from_credentials(&credentials);

    let tls_active = !matches!(tls_mode, TlsMode::None);

    let behind_proxy = credentials.proxy;

    let state = Arc::new(AppState {
        agent_json_cached,
        verifying_key,
        vault_key,
        db_pool,
        tls_active,
        behind_proxy,
        rate_limiter: DashMap::with_capacity(256),
        magic_link_window: std::sync::atomic::AtomicI64::new(0),
        magic_link_count: std::sync::atomic::AtomicU32::new(0),
        db_fail_count: std::sync::atomic::AtomicU32::new(0),
        db_circuit_opened_at: std::sync::atomic::AtomicU64::new(0),
    });

    // Background task: WAL checkpoint every 5 minutes (PASSIVE to avoid blocking writers;
    // the hourly cleanup task runs TRUNCATE to actually reclaim WAL disk space).
    let wal_state = state.clone();
    spawn_supervised("wal-checkpoint", move || {
        let st = wal_state.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let db_ref = st.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    // Check WAL file size: escalate from PASSIVE to TRUNCATE if >40MB
                    // to prevent unbounded WAL growth under heavy reader load.
                    let wal_large = crate::config::atomic_dir()
                        .map(|d| d.join("atomic.db-wal"))
                        .ok()
                        .and_then(|p| std::fs::metadata(&p).ok())
                        .map(|m| m.len() > 40 * 1024 * 1024)
                        .unwrap_or(false);

                    match db_ref.db_pool.get() {
                        Ok(conn) => {
                            if wal_large {
                                tracing::warn!("WAL exceeds 40MB, forcing TRUNCATE checkpoint");
                                if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                                    tracing::warn!("WAL TRUNCATE checkpoint failed: {e}, falling back to RESTART");
                                    let _ = conn.execute_batch("PRAGMA wal_checkpoint(RESTART);");
                                }
                            } else if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);") {
                                tracing::warn!("WAL checkpoint failed: {e}");
                            }
                        }
                        Err(e) => tracing::warn!("WAL checkpoint: pool exhausted: {e}"),
                    }
                }).await;
            }
        }
    });

    // Background task: clean expired magic links, old deposit nonces, and rate limiter entries
    let cleanup_state = state.clone();
    spawn_supervised("db-cleanup", move || {
        let st = cleanup_state.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                let db_ref = st.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let conn = match db_ref.db_pool.get() {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("DB cleanup: pool exhausted: {e}");
                            return;
                        }
                    };
                    let now = chrono::Utc::now().timestamp();
                    // Paginated deletes: batch 1000 rows at a time to avoid holding
                    // the WAL write lock for extended periods under heavy load.
                    loop {
                        match conn.execute(
                            "DELETE FROM magic_links WHERE rowid IN \
                             (SELECT rowid FROM magic_links WHERE expires_at <= ?1 LIMIT 1000)",
                            [now],
                        ) {
                            Ok(0) => break,
                            Ok(_) => continue,
                            Err(e) => { tracing::warn!("Failed to clean expired magic links: {e}"); break; }
                        }
                    }
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
                    // Purge deposit log entries older than 90 days to prevent unbounded disk growth
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
                    // TRUNCATE checkpoint hourly to reclaim WAL disk space
                    if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                        tracing::warn!("Hourly WAL TRUNCATE checkpoint failed: {e}");
                    }
                    // Let SQLite update its query planner statistics
                    let _ = conn.execute_batch("PRAGMA optimize;");
                }).await;
            }
        }
    });

    // Background task: evict stale rate limiter entries every 5 minutes.
    // More aggressive than hourly to bound DashMap memory under sustained attack.
    let rl_state = state.clone();
    spawn_supervised("rate-limiter-evict", move || {
        let st = rl_state.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                // Offload O(n) DashMap scan to the blocking pool to avoid stalling
                // the async executor under 100k+ entries.
                let st2 = st.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let cutoff = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
                    let now = std::time::Instant::now();
                    st2.rate_limiter.retain(|_, (_, window_start)| now.duration_since(*window_start) <= cutoff);
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
        .layer(middleware::from_fn(request_timeout))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(middleware::from_fn_with_state(
            state.clone(),
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

    // Final WAL checkpoint before exit to ensure all data is merged.
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

    // Circuit breaker: reject immediately if DB is known-broken (disk full, corrupt, etc.)
    if state.is_db_circuit_open() {
        return (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "30")]).into_response();
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
    // Access vault_key via the Arc<AppState> reference inside the closure
    // to avoid copying the key out of its Zeroizing wrapper.
    let state_clone = state.clone();
    let body_clone = body;
    let deposit_result = tokio::time::timeout(
        DB_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            let conn = state_clone.db_pool.get()?;
            crate::deposit::claim_nonce_with_conn(&payload, &conn)?;
            crate::vault::vault_set_with_conn(&conn, &payload.label, &body_clone, state_clone.vault_key())?;
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

async fn handle_magic_link(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(code): Path<String>,
) -> Response {
    // Per-IP rate limiting to prevent brute-force of magic link codes
    if !state.check_rate_limit(addr.ip()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    // Global rate limit: cap total claim attempts across all IPs
    if !state.check_magic_link_global_rate() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Reject obviously short codes or codes with non-printable chars before touching the DB
    if code.len() < 20 || !is_valid_input(&code) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Circuit breaker: reject immediately if DB is known-broken
    if state.is_db_circuit_open() {
        return (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "30")]).into_response();
    }

    let state_clone = state.clone();
    let code_clone = code;
    let result = tokio::time::timeout(
        DB_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            let conn = state_clone.db_pool.get()?;
            Ok::<_, anyhow::Error>(crate::magic_link::claim_with_conn(&code_clone, &conn))
        })
    ).await;

    match result {
        Err(_elapsed) => {
            tracing::error!("Magic link handler timed out");
            state.record_db_failure();
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(Ok(Ok(Some(_)))) => {
            state.record_db_success();
            let resp = MagicLinkResponse { status: "verified" };
            match serde_json::to_string(&resp) {
                Ok(json) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], json).into_response(),
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        Ok(Ok(Ok(None))) => {
            state.record_db_success();
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(Ok(Err(e))) => {
            tracing::error!("Magic link DB error: {e}");
            state.record_db_failure();
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("Magic link task panicked: {e}");
            state.record_db_failure();
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn handle_health(State(state): State<Arc<AppState>>) -> Response {
    // Check DB is responsive (with timeout)
    let db_ok = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::task::spawn_blocking({
            let st = state.clone();
            move || match st.db_pool.get() {
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
