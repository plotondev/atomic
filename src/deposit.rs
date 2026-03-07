use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::crypto::signing;

// The payload encoded into the signed URL token.
#[derive(Debug, Serialize, Deserialize)]
pub struct DepositPayload {
    pub label: String,
    pub nonce: String,
    pub expires_at: i64, // unix timestamp
}

// Create a signed deposit token. The token is self-contained:
// base64url(json_payload) + "." + base64url(ed25519_signature)
pub fn create_signed_token(
    label: &str,
    expires_in: Duration,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String> {
    let nonce = generate_nonce();
    let max_expiry: u64 = 24 * 3600; // 24 hours
    let secs = expires_in.as_secs().min(max_expiry);
    let expires_at = chrono::Utc::now().timestamp() + i64::try_from(secs)
        .map_err(|_| anyhow::anyhow!("Duration too large"))?;

    let payload = DepositPayload {
        label: label.to_string(),
        nonce,
        expires_at,
    };

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64URL.encode(payload_json.as_bytes());
    let sig = signing::sign(signing_key, payload_b64.as_bytes());
    let sig_b64 = B64URL.encode(sig.to_bytes());

    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Verify signature and expiry only (no DB access). Returns the payload if valid.
pub fn verify_signature(
    token: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Option<DepositPayload> {
    match try_verify_signature(token, verifying_key) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::debug!("Deposit verify failed: {}", e);
            None
        }
    }
}

fn try_verify_signature(
    token: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<DepositPayload> {
    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("No '.' separator in token"))?;

    let sig_bytes = B64URL.decode(sig_b64)?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("Bad signature bytes: {e}"))?;

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(payload_b64.as_bytes(), &sig)
        .map_err(|e| anyhow::anyhow!("Signature invalid: {e}"))?;

    let payload_json = B64URL.decode(payload_b64)?;
    let payload: DepositPayload = serde_json::from_slice(&payload_json)?;

    let now = chrono::Utc::now().timestamp();
    if payload.expires_at <= now {
        anyhow::bail!("Token expired (expires_at={}, now={})", payload.expires_at, now);
    }

    Ok(payload)
}

/// Claim the nonce using a provided connection reference.
pub fn claim_nonce_with_conn(
    payload: &DepositPayload,
    conn: &rusqlite::Connection,
) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO used_deposits (nonce, label, used_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![payload.nonce, payload.label, now],
    )?;

    if inserted == 0 {
        anyhow::bail!("Nonce already used (replay)");
    }

    Ok(())
}

/// Record deposit metadata in the database.
pub fn log_deposit(
    conn: &rusqlite::Connection,
    label: &str,
    source_ip: &str,
    user_agent: &str,
) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO deposit_log (label, source_ip, user_agent, deposited_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![label, source_ip, user_agent, now],
    )?;
    Ok(())
}

/// List deposit log entries, optionally filtered by label.
pub fn list_deposits(label_filter: Option<&str>) -> Result<()> {
    let conn = crate::db::open()?;

    let query = match label_filter {
        Some(_) => "SELECT label, source_ip, user_agent, deposited_at FROM deposit_log WHERE label = ?1 ORDER BY deposited_at DESC",
        None => "SELECT label, source_ip, user_agent, deposited_at FROM deposit_log ORDER BY deposited_at DESC",
    };
    let mut stmt = conn.prepare(query)?;

    let mut rows = if let Some(label) = label_filter {
        stmt.query(rusqlite::params![label])?
    } else {
        stmt.query([])?
    };

    let mut found = false;
    while let Some(row) = rows.next()? {
        let label: String = row.get(0)?;
        let ip: String = row.get(1)?;
        let ua: String = row.get(2)?;
        let ts: i64 = row.get(3)?;
        let time = chrono::DateTime::from_timestamp(ts, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| ts.to_string());
        println!("{time}  {label}");
        println!("  IP:         {ip}");
        if !ua.is_empty() {
            println!("  User-Agent: {ua}");
        }
        println!();
        found = true;
    }

    if !found {
        println!("No deposits yet.");
    }
    Ok(())
}

fn generate_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// Accepts "10m", "1h", "30s".
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration string");
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        anyhow::bail!("Duration must end with 's' (seconds), 'm' (minutes), or 'h' (hours)");
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid number in duration: '{num_str}'"))?;

    Ok(Duration::from_secs(
        num.checked_mul(multiplier)
            .ok_or_else(|| anyhow::anyhow!("Duration too large"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing as s;

    #[test]
    fn parse_duration_values() {
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn signed_token_roundtrip() {
        let (sk, _vk) = s::generate_keypair();
        let token = create_signed_token("test_key", Duration::from_secs(300), &sk).unwrap();

        // Token has two parts separated by "."
        assert!(token.contains('.'));

        // Decode the payload part to verify contents
        let (payload_b64, _) = token.split_once('.').unwrap();
        let payload_json = B64URL.decode(payload_b64).unwrap();
        let payload: DepositPayload = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload.label, "test_key");
        assert!(!payload.nonce.is_empty());
    }

    #[test]
    fn wrong_key_rejects() {
        let (sk, _) = s::generate_keypair();
        let (_, wrong_vk) = s::generate_keypair();
        let token = create_signed_token("key", Duration::from_secs(300), &sk).unwrap();
        assert!(verify_signature(&token, &wrong_vk).is_none());
    }

    #[test]
    fn tampered_token_rejects() {
        let (sk, vk) = s::generate_keypair();
        let token = create_signed_token("key", Duration::from_secs(300), &sk).unwrap();
        // Flip a byte in the payload using safe code
        let mut bytes = token.into_bytes();
        bytes[5] ^= 0x01;
        let token = String::from_utf8(bytes).unwrap();
        assert!(verify_signature(&token, &vk).is_none());
    }

    #[test]
    fn expired_token_rejects() {
        let (sk, vk) = s::generate_keypair();
        // Already expired
        let token = create_signed_token("key", Duration::from_secs(0), &sk).unwrap();
        assert!(verify_signature(&token, &vk).is_none());
    }

    #[test]
    fn verify_signature_valid_roundtrip() {
        let (sk, vk) = s::generate_keypair();
        let token = create_signed_token("mykey", Duration::from_secs(300), &sk).unwrap();
        let payload = verify_signature(&token, &vk).unwrap();
        assert_eq!(payload.label, "mykey");
        assert!(!payload.nonce.is_empty());
    }

    #[test]
    fn verify_signature_no_separator() {
        let (_, vk) = s::generate_keypair();
        assert!(verify_signature("no-dot-here", &vk).is_none());
    }

    #[test]
    fn verify_signature_invalid_base64() {
        let (_, vk) = s::generate_keypair();
        assert!(verify_signature("not!valid.also!invalid", &vk).is_none());
    }

    #[test]
    fn expiry_capped_at_24h() {
        let (sk, _) = s::generate_keypair();
        let token = create_signed_token("key", Duration::from_secs(48 * 3600), &sk).unwrap();
        let (payload_b64, _) = token.split_once('.').unwrap();
        let payload_json = B64URL.decode(payload_b64).unwrap();
        let payload: DepositPayload = serde_json::from_slice(&payload_json).unwrap();
        let now = chrono::Utc::now().timestamp();
        // Should be capped at ~24h, not 48h
        assert!(payload.expires_at <= now + 24 * 3600 + 5);
        assert!(payload.expires_at > now + 23 * 3600); // but at least ~23h
    }

    #[test]
    fn parse_duration_zero_values() {
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("0m").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("0h").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn parse_duration_trims_whitespace() {
        assert_eq!(parse_duration("  10m  ").unwrap(), Duration::from_secs(600));
    }

    fn test_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE used_deposits (nonce TEXT PRIMARY KEY, label TEXT NOT NULL, used_at INTEGER NOT NULL);"
        ).unwrap();
        conn
    }

    #[test]
    fn claim_nonce_first_use_succeeds() {
        let conn = test_db();
        let payload = DepositPayload {
            label: "test".into(),
            nonce: "unique_nonce_123".into(),
            expires_at: chrono::Utc::now().timestamp() + 300,
        };
        assert!(claim_nonce_with_conn(&payload, &conn).is_ok());
    }

    #[test]
    fn claim_nonce_replay_rejected() {
        let conn = test_db();
        let payload = DepositPayload {
            label: "test".into(),
            nonce: "replay_nonce".into(),
            expires_at: chrono::Utc::now().timestamp() + 300,
        };
        claim_nonce_with_conn(&payload, &conn).unwrap();
        let err = claim_nonce_with_conn(&payload, &conn).unwrap_err();
        assert!(err.to_string().contains("Nonce already used"));
    }
}
