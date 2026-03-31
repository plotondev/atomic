use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::config;

pub fn open() -> Result<Connection> {
    let db_path = config::atomic_dir()?.join("atomic.db");

    // Pre-create DB file with restricted permissions (0600) before SQLite opens it
    #[cfg(unix)]
    if !db_path.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&db_path)
            .with_context(|| format!("Failed to create database at {}", db_path.display()))?;
    }

    let conn = Connection::open(&db_path)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

    // WAL mode: fast reads, lets multiple processes access the file
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?; // NORMAL is safe with WAL mode
    conn.pragma_update(None, "cache_size", "-2000")?;
    conn.pragma_update(None, "busy_timeout", "5000")?; // Wait 5s for locks under contention
    conn.pragma_update(None, "journal_size_limit", "67108864")?; // Cap WAL at 64MB

    // CREATE TABLE IF NOT EXISTS is idempotent — safe to run every time
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
