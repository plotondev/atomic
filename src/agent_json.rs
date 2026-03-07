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
            deposit: format!("{base_url}/d/"),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).context("Failed to serialize agent.json")?;
        crate::config::write_secure(path, json.as_bytes())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&data).context("Failed to parse agent.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_json_new_fields() {
        let agent = AgentJson::new("test.com", "ed25519:abc", "https://test.com");
        assert_eq!(agent.v, 1);
        assert_eq!(agent.id, "test.com");
        assert_eq!(agent.name, "test.com");
        assert_eq!(agent.public_key, "ed25519:abc");
        assert_eq!(agent.status, "active");
        assert_eq!(agent.deposit, "https://test.com/d/");
        assert!(!agent.created_at.is_empty());
    }

    #[test]
    fn agent_json_save_load_roundtrip() {
        let agent = AgentJson::new("rt.example.com", "ed25519:xyz", "https://rt.example.com");
        let tmp = std::env::temp_dir().join(format!("atomic_test_agent_{}", std::process::id()));
        agent.save(&tmp).unwrap();
        let loaded = AgentJson::load(&tmp).unwrap();
        assert_eq!(loaded.id, "rt.example.com");
        assert_eq!(loaded.public_key, "ed25519:xyz");
        assert_eq!(loaded.status, "active");
        assert_eq!(loaded.v, 1);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn agent_json_valid_json_schema() {
        let agent = AgentJson::new("test.com", "ed25519:pk", "https://test.com");
        let json = serde_json::to_value(&agent).unwrap();
        assert!(json.get("v").unwrap().is_number());
        assert!(json.get("id").unwrap().is_string());
        assert!(json.get("name").unwrap().is_string());
        assert!(json.get("public_key").unwrap().is_string());
        assert!(json.get("status").unwrap().is_string());
        assert!(json.get("deposit").unwrap().is_string());
        assert!(json.get("created_at").unwrap().is_string());
    }
}
