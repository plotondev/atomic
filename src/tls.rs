use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use tracing::info;

pub enum TlsMode {
    Custom { cert_path: String, key_path: String },
    None,
}

impl TlsMode {
    pub fn from_credentials(creds: &crate::credentials::Credentials) -> Result<Self> {
        if creds.no_tls {
            Ok(TlsMode::None)
        } else if let (Some(cert), Some(key)) = (&creds.tls_cert, &creds.tls_key) {
            Ok(TlsMode::Custom {
                cert_path: cert.clone(),
                key_path: key.clone(),
            })
        } else {
            anyhow::bail!(
                "TLS requires --tls-cert and --tls-key, or use --no-tls for plain HTTP"
            )
        }
    }
}

pub async fn resolve_rustls_config(mode: &TlsMode) -> Result<RustlsConfig> {
    match mode {
        TlsMode::Custom { cert_path, key_path } => {
            info!("Loading TLS cert from {}", cert_path);
            RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .context("Failed to load TLS cert/key")
        }
        TlsMode::None => {
            unreachable!("resolve_rustls_config called with TlsMode::None")
        }
    }
}
