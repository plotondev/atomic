use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentJson {
    pub v: u32,
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub status: String,
    pub deposit: String,
    pub created_at: String,
}

impl AgentJson {
    pub fn new(domain: &str, public_key: &str, base_url: &str) -> Self {
        Self {
            v: 1,
            id: domain.to_string(),
            name: domain.to_string(),
            public_key: public_key.to_string(),
            status: "active".to_string(),
            deposit: format!("{}/d/", base_url),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).context("Failed to serialize agent.json")?;
        std::fs::write(path, json).with_context(|| format!("Failed to write {}", path.display()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&data).context("Failed to parse agent.json")
    }
}
