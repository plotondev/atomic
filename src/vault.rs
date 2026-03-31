use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::crypto::vault as crypto_vault;
use crate::db;

pub fn vault_set_with_conn(conn: &rusqlite::Connection, label: &str, value: &str, vault_key: &[u8; 32]) -> Result<()> {
    let encrypted = crypto_vault::encrypt(vault_key, value.as_bytes())?;
    conn.prepare_cached(
        "INSERT OR REPLACE INTO vault_secrets (label, value) VALUES (?1, ?2)",
    )?.execute(
        rusqlite::params![label, encrypted],
    ).context("Failed to store secret")?;
    Ok(())
}

pub fn vault_set(label: &str, value: &str, vault_key: &[u8; 32]) -> Result<()> {
    let conn = db::open()?;
    vault_set_with_conn(&conn, label, value, vault_key)
}

pub fn vault_get(label: &str, vault_key: &[u8; 32]) -> Result<Option<Zeroizing<Box<str>>>> {
    let conn = db::open()?;
    let mut stmt = conn
        .prepare("SELECT value FROM vault_secrets WHERE label = ?1")
        .context("Failed to prepare query")?;
    let result: Option<Vec<u8>> = match stmt.query_row(rusqlite::params![label], |row| row.get(0)) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e).context("Failed to query vault"),
    };
    match result {
        Some(encrypted) => {
            let plaintext = crypto_vault::decrypt(vault_key, &encrypted)?;
            // Box<str> is 2 words (ptr, len) vs String's 3 (ptr, len, cap).
            // No slack capacity means zeroize wipes exactly the used bytes.
            let value = Zeroizing::new(
                std::str::from_utf8(&plaintext)
                    .context("Vault value is not valid UTF-8")?
                    .to_string()
                    .into_boxed_str(),
            );
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

pub fn vault_list() -> Result<Vec<String>> {
    let conn = db::open()?;
    let mut stmt = conn
        .prepare("SELECT label FROM vault_secrets ORDER BY label")
        .context("Failed to prepare query")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .context("Failed to query vault labels")?;
    let mut labels = Vec::new();
    for row in rows {
        labels.push(row?);
    }
    Ok(labels)
}

pub fn vault_delete(label: &str) -> Result<bool> {
    let conn = db::open()?;
    let deleted = conn
        .execute(
            "DELETE FROM vault_secrets WHERE label = ?1",
            rusqlite::params![label],
        )
        .context("Failed to delete secret")?;
    Ok(deleted > 0)
}

pub fn vault_count() -> Result<usize> {
    let conn = db::open()?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM vault_secrets", [], |row| row.get(0))?;
    Ok(count as usize)
}

/// Reject labels with non-printable characters or excessive length.
fn is_valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes().all(|b| b >= 0x20 && b != 0x7F)
}

pub fn cmd_set(label: &str, value: &str, vault_key: &[u8; 32]) -> Result<()> {
    if !is_valid_label(label) {
        bail!("Label must be non-empty, at most 256 printable characters");
    }
    vault_set(label, value, vault_key)?;
    println!("Stored '{label}'");
    Ok(())
}

pub fn cmd_get(label: &str, vault_key: &[u8; 32]) -> Result<()> {
    match vault_get(label, vault_key)? {
        Some(value) => {
            print!("{}", &*value); // no trailing newline, so it works in $()
            Ok(())
        }
        None => bail!("Label '{label}' not found in vault"),
    }
}

pub fn cmd_list() -> Result<()> {
    let labels = vault_list()?;
    if labels.is_empty() {
        println!("Vault is empty");
        return Ok(());
    }
    for label in labels {
        println!("{label}");
    }
    Ok(())
}

pub fn cmd_delete(label: &str) -> Result<()> {
    if vault_delete(label)? {
        println!("Deleted '{label}'");
    } else {
        bail!("Label '{label}' not found in vault");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::vault as cv;

    fn test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vault_secrets (label TEXT PRIMARY KEY, value BLOB NOT NULL);"
        ).unwrap();
        conn
    }

    fn test_key() -> [u8; 32] {
        *cv::derive_vault_key(&[42u8; 32]).unwrap()
    }

    #[test]
    fn vault_set_get_roundtrip() {
        let key = test_key();
        let conn = test_db();
        vault_set_with_conn(&conn, "api_key", "sk-12345", &key).unwrap();
        let mut stmt = conn.prepare("SELECT value FROM vault_secrets WHERE label = ?1").unwrap();
        let encrypted: Vec<u8> = stmt.query_row(["api_key"], |row| row.get(0)).unwrap();
        let decrypted = cv::decrypt(&key, &encrypted).unwrap();
        assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "sk-12345");
    }

    #[test]
    fn vault_set_overwrites() {
        let key = test_key();
        let conn = test_db();
        vault_set_with_conn(&conn, "k", "v1", &key).unwrap();
        vault_set_with_conn(&conn, "k", "v2", &key).unwrap();
        let mut stmt = conn.prepare("SELECT value FROM vault_secrets WHERE label = ?1").unwrap();
        let encrypted: Vec<u8> = stmt.query_row(["k"], |row| row.get(0)).unwrap();
        let decrypted = cv::decrypt(&key, &encrypted).unwrap();
        assert_eq!(std::str::from_utf8(&decrypted).unwrap(), "v2");
    }

    #[test]
    fn cmd_set_rejects_empty_label() {
        let key = test_key();
        assert!(cmd_set("", "val", &key).is_err());
    }

    #[test]
    fn cmd_set_rejects_long_label() {
        let key = test_key();
        let label = "a".repeat(257);
        assert!(cmd_set(&label, "val", &key).is_err());
    }
}
