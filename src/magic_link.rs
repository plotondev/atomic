use anyhow::Result;

use crate::config;
use crate::db;
use crate::deposit::parse_duration;

pub fn host(code: &str, expires: &str) -> Result<()> {
    let duration = parse_duration(expires)?;
    let expires_at = chrono::Utc::now().timestamp()
        + i64::try_from(duration.as_secs()).map_err(|_| anyhow::anyhow!("Duration too large"))?;

    let conn = db::open()?;
    conn.execute(
        "INSERT OR REPLACE INTO magic_links (code, expires_at) VALUES (?1, ?2)",
        rusqlite::params![code, expires_at],
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

    let mut stmt = conn.prepare("SELECT code, expires_at FROM magic_links ORDER BY expires_at")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;

    let mut found = false;
    for row in rows {
        let (code, expires_at) = row?;
        let remaining = expires_at - now;
        let mins = remaining / 60;
        let secs = remaining % 60;
        println!("{code}  (expires in {mins}m {secs}s)");
        found = true;
    }

    if !found {
        println!("No active magic links.");
    }
    Ok(())
}

/// Called by the server to check and consume a code. One-time use.
/// Uses a provided connection reference instead of opening its own.
pub fn claim_with_conn(code: &str, conn: &rusqlite::Connection) -> Option<String> {
    let now = chrono::Utc::now().timestamp();

    // try to delete the matching code and check if it existed
    let deleted = conn
        .execute(
            "DELETE FROM magic_links WHERE code = ?1 AND expires_at > ?2",
            rusqlite::params![code, now],
        )
        .ok()?;

    if deleted > 0 {
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
            "CREATE TABLE magic_links (code TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);"
        ).unwrap();
        conn
    }

    #[test]
    fn claim_valid_code() {
        let conn = test_db();
        let future = chrono::Utc::now().timestamp() + 300;
        conn.execute(
            "INSERT INTO magic_links (code, expires_at) VALUES (?1, ?2)",
            rusqlite::params!["abc123", future],
        ).unwrap();
        assert_eq!(claim_with_conn("abc123", &conn), Some("abc123".to_string()));
    }

    #[test]
    fn claim_expired_code() {
        let conn = test_db();
        let past = chrono::Utc::now().timestamp() - 10;
        conn.execute(
            "INSERT INTO magic_links (code, expires_at) VALUES (?1, ?2)",
            rusqlite::params!["expired", past],
        ).unwrap();
        assert!(claim_with_conn("expired", &conn).is_none());
    }

    #[test]
    fn claim_nonexistent_code() {
        let conn = test_db();
        assert!(claim_with_conn("nope", &conn).is_none());
    }

    #[test]
    fn claim_one_time_use() {
        let conn = test_db();
        let future = chrono::Utc::now().timestamp() + 300;
        conn.execute(
            "INSERT INTO magic_links (code, expires_at) VALUES (?1, ?2)",
            rusqlite::params!["once", future],
        ).unwrap();
        assert!(claim_with_conn("once", &conn).is_some());
        assert!(claim_with_conn("once", &conn).is_none());
    }
}

