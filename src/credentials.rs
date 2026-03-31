use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

use crate::crypto::signing;

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub domain: String,
    pub private_key: String,
    pub public_key: String,
    pub port: u16,
    pub no_tls: bool,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    #[serde(default)]
    pub proxy: bool,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("domain", &self.domain)
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .field("port", &self.port)
            .field("no_tls", &self.no_tls)
            .field("proxy", &self.proxy)
            .finish()
    }
}

impl Credentials {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: String,
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
        port: u16,
        no_tls: bool,
        tls_cert: Option<String>,
        tls_key: Option<String>,
        proxy: bool,
    ) -> Self {
        Self {
            domain,
            private_key: signing::encode_private_key(signing_key),
            public_key: signing::encode_public_key(verifying_key),
            port,
            no_tls,
            tls_cert,
            tls_key,
            proxy,
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        Ok(signing::decode_private_key(&self.private_key)?)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        Ok(signing::decode_public_key(&self.public_key)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // Write directly into a Zeroizing<Vec<u8>> so the private key material
        // in the serialized JSON is zeroed on drop, not left in freed heap memory.
        let mut buf = zeroize::Zeroizing::new(Vec::new());
        serde_json::to_writer_pretty(&mut *buf, self).context("Failed to serialize credentials")?;
        crate::config::write_secure(path, &buf)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = zeroize::Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path.display()))?,
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing;

    fn make_creds(domain: &str, port: u16, no_tls: bool) -> Credentials {
        let (sk, vk) = signing::generate_keypair();
        Credentials::new(domain.into(), &sk, &vk, port, no_tls, None, None, false)
    }

    #[test]
    fn base_url_https_default_port() {
        assert_eq!(make_creds("a.com", 443, false).base_url(), "https://a.com");
    }

    #[test]
    fn base_url_https_custom_port() {
        assert_eq!(make_creds("a.com", 8443, false).base_url(), "https://a.com:8443");
    }

    #[test]
    fn base_url_http_default_port() {
        assert_eq!(make_creds("a.com", 80, true).base_url(), "http://a.com");
    }

    #[test]
    fn base_url_http_custom_port() {
        assert_eq!(make_creds("a.com", 8080, true).base_url(), "http://a.com:8080");
    }

    #[test]
    fn credentials_roundtrip_keys() {
        let (sk, vk) = signing::generate_keypair();
        let creds = Credentials::new("test.com".into(), &sk, &vk, 443, false, None, None, false);
        let decoded_sk = creds.signing_key().unwrap();
        let decoded_vk = creds.verifying_key().unwrap();
        assert_eq!(sk.to_bytes(), decoded_sk.to_bytes());
        assert_eq!(vk, decoded_vk);
    }

    #[test]
    fn credentials_save_load_roundtrip() {
        let (sk, vk) = signing::generate_keypair();
        let creds = Credentials::new("rt.example.com".into(), &sk, &vk, 443, false, None, None, false);
        let tmp = std::env::temp_dir().join(format!("atomic_test_creds_{}", std::process::id()));
        creds.save(&tmp).unwrap();
        let loaded = Credentials::load(&tmp).unwrap();
        assert_eq!(loaded.domain, "rt.example.com");
        assert_eq!(loaded.public_key, creds.public_key);
        assert_eq!(loaded.private_key, creds.private_key);
        assert_eq!(loaded.port, 443);
        assert!(!loaded.no_tls);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn credentials_load_nonexistent_fails() {
        let result = Credentials::load(std::path::Path::new("/tmp/does_not_exist_atomic_xyz"));
        assert!(result.is_err());
    }
}
