use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::crypto::token::generate_deposit_token;

#[derive(Debug)]
pub struct PendingDeposit {
    pub label: String,
    pub token_hash: String,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub struct DepositManager {
    pending: Arc<Mutex<HashMap<String, PendingDeposit>>>,
    max_pending: usize,
}

impl DepositManager {
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            max_pending,
        }
    }

    // Creates a deposit slot and returns the raw token for the URL.
    // Expired entries get cleaned up on each call.
    pub async fn create_deposit_url(
        &self,
        label: String,
        expires_in: Duration,
    ) -> anyhow::Result<String> {
        let mut pending = self.pending.lock().await;

        let now = Instant::now();
        pending.retain(|_, d| d.expires_at > now);

        if pending.len() >= self.max_pending {
            anyhow::bail!(
                "Too many pending deposits (max {}). Wait for some to expire.",
                self.max_pending
            );
        }

        let token = generate_deposit_token();
        let token_hash = hash_token(&token);

        pending.insert(
            token_hash.clone(),
            PendingDeposit {
                label,
                token_hash: token_hash.clone(),
                expires_at: now + expires_in,
            },
        );

        Ok(token)
    }

    // Looks up the token, removes it (one-time use), returns the label if valid.
    pub async fn claim(&self, token: &str) -> Option<String> {
        let token_hash = hash_token(token);
        let mut pending = self.pending.lock().await;
        let now = Instant::now();

        if let Some(deposit) = pending.remove(&token_hash) {
            if deposit.expires_at > now {
                return Some(deposit.label);
            }
        }
        None
    }

    pub async fn pending_count(&self) -> usize {
        let pending = self.pending.lock().await;
        let now = Instant::now();
        pending.values().filter(|d| d.expires_at > now).count()
    }
}

// We store the hash, not the raw token, so a memory dump doesn't leak URLs.
fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    hex::encode(hash)
}

// Accepts "10m", "1h", "30s".
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration string");
    }

    let (num_str, unit) = if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with('s') {
        (&s[..s.len() - 1], "s")
    } else {
        anyhow::bail!("Duration must end with 's' (seconds), 'm' (minutes), or 'h' (hours)");
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid number in duration: '{}'", num_str))?;

    match unit {
        "s" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn create_then_claim() {
        let dm = DepositManager::new(100);
        let token = dm
            .create_deposit_url("test_key".to_string(), Duration::from_secs(60))
            .await
            .unwrap();

        assert!(token.starts_with("dt_"));
        assert_eq!(dm.pending_count().await, 1);

        let label = dm.claim(&token).await.unwrap();
        assert_eq!(label, "test_key");

        // one-time: second claim fails
        assert!(dm.claim(&token).await.is_none());
        assert_eq!(dm.pending_count().await, 0);
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let dm = DepositManager::new(100);
        let token = dm
            .create_deposit_url("expired_key".to_string(), Duration::from_millis(1))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(dm.claim(&token).await.is_none());
    }
}
