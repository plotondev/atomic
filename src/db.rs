use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::config;

/// Zero-dependency connection pool for SQLite.
/// Uses a bounded sync_channel to distribute pre-opened connections.
/// WAL mode allows concurrent readers; the pool prevents serialization
/// behind a single Mutex<Connection>.
pub struct DbPool {
    sender: mpsc::SyncSender<Connection>,
    receiver: std::sync::Mutex<mpsc::Receiver<Connection>>,
}

/// RAII guard that returns the connection to the pool on drop.
/// Tracks hold time to detect potential connection leaks.
pub struct PooledConn<'a> {
    pool: &'a DbPool,
    conn: Option<Connection>,
    acquired_at: Instant,
}

impl<'a> std::ops::Deref for PooledConn<'a> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("PooledConn used after take")
    }
}

impl Drop for PooledConn<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.conn.take() {
            let held = self.acquired_at.elapsed();
            if held > Duration::from_secs(60) {
                // Cooperatively interrupt any in-flight query before closing.
                // This lets SQLite roll back cleanly instead of leaving the WAL
                // in an undefined state from an aborted transaction.
                c.get_interrupt_handle().interrupt();
                tracing::warn!("SQLite connection held for {:?}, interrupted and dropping", held);
                return;
            }
            if held > Duration::from_secs(30) {
                tracing::warn!("SQLite connection held for {:?}, possible leak", held);
            }
            let _ = self.pool.sender.try_send(c);
        }
    }
}

impl DbPool {
    /// Get a connection from the pool, blocking up to 5 seconds.
    pub fn get(&self) -> Result<PooledConn<'_>> {
        let rx = self.receiver.lock().unwrap_or_else(|e| e.into_inner());
        let conn = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| anyhow::anyhow!("DB pool exhausted (5s timeout)"))?;
        Ok(PooledConn {
            pool: self,
            conn: Some(conn),
            acquired_at: Instant::now(),
        })
    }
}

fn ensure_db_file(db_path: &Path) -> Result<()> {
    #[cfg(unix)]
    if !db_path.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(db_path)
            .with_context(|| format!("Failed to create database at {}", db_path.display()))?;
    }
    Ok(())
}

fn open_connection(db_path: &Path) -> Result<Connection> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

    // WAL mode: fast reads, lets multiple processes access the file
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "cache_size", "-64000")?;
    // 4s busy_timeout: lower than the 5s tokio::time::timeout on handlers,
    // so SQLite returns BUSY cleanly before the task gets cancelled.
    conn.pragma_update(None, "busy_timeout", "4000")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "journal_size_limit", "67108864")?;
    conn.pragma_update(None, "wal_autocheckpoint", "1000")?;
    conn.pragma_update(None, "mmap_size", "67108864")?;

    Ok(conn)
}

/// Open a connection pool with `size` connections, each configured for WAL mode.
/// Migrations run once on the first connection.
pub fn open_pool(size: usize) -> Result<DbPool> {
    let db_path = config::atomic_dir()?.join("atomic.db");
    ensure_db_file(&db_path)?;

    let first = open_connection(&db_path)?;
    migrate(&first)?;

    let (tx, rx) = mpsc::sync_channel(size);
    tx.send(first).expect("channel just created");

    for _ in 1..size {
        tx.send(open_connection(&db_path)?).expect("channel just created");
    }

    Ok(DbPool {
        sender: tx,
        receiver: std::sync::Mutex::new(rx),
    })
}

/// Open a single connection (for CLI commands that don't need a pool).
pub fn open() -> Result<Connection> {
    let db_path = config::atomic_dir()?.join("atomic.db");
    ensure_db_file(&db_path)?;
    let conn = open_connection(&db_path)?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    // Migrate magic_links from old schema (plaintext `code`) to new (hashed `code_hash`).
    // Magic links are short-lived, so dropping the table is safe.
    let has_old_schema = conn
        .prepare("SELECT code FROM magic_links LIMIT 0")
        .is_ok();
    if has_old_schema {
        conn.execute_batch("DROP TABLE magic_links;")
            .context("Failed to migrate magic_links table")?;
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS magic_links (
            code_hash  TEXT PRIMARY KEY,
            hint       TEXT NOT NULL DEFAULT '',
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS used_deposits (
            nonce      TEXT PRIMARY KEY,
            label      TEXT NOT NULL,
            used_at    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vault_secrets (
            label      TEXT PRIMARY KEY,
            value      BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS deposit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            label      TEXT NOT NULL,
            source_ip  TEXT,
            user_agent TEXT,
            deposited_at INTEGER NOT NULL
        );",
    )
    .context("Failed to run migrations")?;
    Ok(())
}
