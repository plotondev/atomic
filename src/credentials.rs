use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::signing;

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub domain: String,
    pub private_key: String,
    pub public_key: String,
    pub port: u16,
    pub no_tls: bool,
}

impl Credentials {
    pub fn new(
        domain: String,
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
        port: u16,
        no_tls: bool,
    ) -> Self {
        Self {
            domain,
            private_key: signing::encode_private_key(signing_key),
            public_key: signing::encode_public_key(verifying_key),
            port,
            no_tls,
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        signing::decode_private_key(&self.private_key)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        signing::decode_public_key(&self.public_key)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("Failed to serialize credentials")?;
        std::fs::write(path, json).with_context(|| format!("Failed to write {}", path.display()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&data).context("Failed to parse credentials")
    }

    pub fn base_url(&self) -> String {
        if self.no_tls {
            if self.port == 80 {
                format!("http://{}", self.domain)
            } else {
                format!("http://{}:{}", self.domain, self.port)
            }
        } else if self.port == 443 {
            format!("https://{}", self.domain)
        } else {
            format!("https://{}:{}", self.domain, self.port)
        }
    }
}
