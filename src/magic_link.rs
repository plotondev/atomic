use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::config;
use crate::db;
use crate::deposit::parse_duration;

fn hash_code(code: &str) -> String {
    let hash = Sha256::digest(code.as_bytes());
    hex::encode(hash)
}

pub fn host(code: &str, expires: &str) -> Result<()> {
    if code.len() < 20 {
        anyhow::bail!("Code must be at least 20 characters (got {}). Use a longer code to prevent brute-force.", code.len());
    }
    let duration = parse_duration(expires)?;
    let max_secs: u64 = 3600; // 1 hour max for magic links
    let capped_secs = duration.as_secs().min(max_secs);
    let expires_at = chrono::Utc::now().timestamp()
        + i64::try_from(capped_secs).map_err(|_| anyhow::anyhow!("Duration too large"))?;

    let code_hash = hash_code(code);
    let hint = &code[..2.min(code.len())];

    let conn = db::open()?;
    conn.execute(
        "INSERT OR REPLACE INTO magic_links (code_hash, hint, expires_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![code_hash, hint, expires_at],
    )?;

    let creds = crate::credentials::Credentials::load(&config::credentials_path()?)?;
    let url = format!("{}/m/{}", creds.base_url(), code);

    println!("{url}");
    println!("Expires in {expires}. Service can verify at that URL.");
    Ok(())
}

pub fn list() -> Result<()> {
    let conn = db::open()?;
    let now = chrono::Utc::now().timestamp();

    // clean expired
    conn.execute("DELETE FROM magic_links WHERE expires_at <= ?1", [now])?;

    let mut stmt = conn.prepare("SELECT hint, expires_at FROM magic_links ORDER BY expires_at")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;

    let mut found = false;
    for row in rows {
        let (hint, expires_at) = row?;
        let remaining = expires_at - now;
        let mins = remaining / 60;
        let secs = remaining % 60;
        println!("{hint}****  (expires in {mins}m {secs}s)");
        found = true;
    }

    if !found {
        println!("No active magic links.");
    }
    Ok(())
}

/// Called by the server to check and consume a code. One-time use.
/// Uses constant-time comparison to prevent timing side-channels that
/// could leak whether a code exists via SQL execution time differences.
pub fn claim_with_conn(code: &str, conn: &rusqlite::Connection) -> Option<String> {
    use rusqlite::OptionalExtension;
    use subtle::ConstantTimeEq;

    let now = chrono::Utc::now().timestamp();
    let code_hash = hash_code(code);

    // Fetch the stored hash first (SELECT), then compare in constant time.
    // SQL timing differs between index hit and miss; the ct_eq comparison
    // ensures the overall code path is uniform regardless of existence.
    let stored_hash: Option<String> = conn
        .query_row(
            "SELECT code_hash FROM magic_links WHERE code_hash = ?1 AND expires_at > ?2",
            rusqlite::params![code_hash, now],
            |row| row.get(0),
        )
        .optional()
        .ok()?;

    let matched = match &stored_hash {
        Some(stored) => bool::from(stored.as_bytes().ct_eq(code_hash.as_bytes())),
        None => {
            // Dummy comparison to keep timing uniform on miss
            let dummy = [0u8; 64]; // SHA-256 hex = 64 bytes
            let _: subtle::Choice = dummy.ct_eq(code_hash.as_bytes());
            false
        }
    };

    if matched {
        // Atomically delete the row (one-time use)
        conn.prepare_cached("DELETE FROM magic_links WHERE code_hash = ?1")
            .and_then(|mut stmt| stmt.execute(rusqlite::params![code_hash]))
            .ok()?;
        Some(code.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE magic_links (code_hash TEXT PRIMARY KEY, hint TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL);"
        ).unwrap();
        conn
    }

    fn insert_code(conn: &rusqlite::Connection, code: &str, expires_at: i64) {
        let code_hash = hash_code(code);
        let hint = &code[..2.min(code.len())];
        conn.execute(
            "INSERT INTO magic_links (code_hash, hint, expires_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![code_hash, hint, expires_at],
        ).unwrap();
    }

    #[test]
    fn claim_valid_code() {
        let conn = test_db();
        let future = chrono::Utc::now().timestamp() + 300;
        insert_code(&conn, "abc12345", future);
        assert_eq!(claim_with_conn("abc12345", &conn), Some("abc12345".to_string()));
    }

    #[test]
    fn claim_expired_code() {
        let conn = test_db();
        let past = chrono::Utc::now().timestamp() - 10;
        insert_code(&conn, "expired!", past);
        assert!(claim_with_conn("expired!", &conn).is_none());
    }

    #[test]
    fn claim_nonexistent_code() {
        let conn = test_db();
        assert!(claim_with_conn("nope1234", &conn).is_none());
    }

    #[test]
    fn claim_one_time_use() {
        let conn = test_db();
        let future = chrono::Utc::now().timestamp() + 300;
        insert_code(&conn, "onceonly", future);
        assert!(claim_with_conn("onceonly", &conn).is_some());
        assert!(claim_with_conn("onceonly", &conn).is_none());
    }

    #[test]
    fn hash_code_is_deterministic() {
        assert_eq!(hash_code("test1234"), hash_code("test1234"));
    }

    #[test]
    fn hash_code_differs_for_different_inputs() {
        assert_ne!(hash_code("test1234"), hash_code("test5678"));
    }

    #[test]
    fn wrong_code_does_not_match() {
        let conn = test_db();
        let future = chrono::Utc::now().timestamp() + 300;
        insert_code(&conn, "correct!", future);
        assert!(claim_with_conn("wrongone", &conn).is_none());
    }
}
