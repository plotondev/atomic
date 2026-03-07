use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::config;

pub fn open() -> Result<Connection> {
    let db_path = config::atomic_dir()?.join("atomic.db");
    let conn = Connection::open(&db_path)
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;

    // WAL mode: fast reads, lets multiple processes access the file
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "cache_size", "-2000")?;

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
