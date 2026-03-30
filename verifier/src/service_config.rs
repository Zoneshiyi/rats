use anyhow::Result;
use serde::Deserialize;

use crate::config::VerifierConfig;

#[derive(Clone, Debug, Deserialize)]
pub struct VerifierServiceConfig {
    pub addr: String,
    #[serde(flatten)]
    pub verifier: VerifierConfig,
}

impl VerifierServiceConfig {
    pub fn load() -> Result<Self> {
        let path = std::env::var("RATS_VERIFIER_CONFIG")
            .or_else(|_| std::env::var("RATS_VERIFIER_SERVICE_CONFIG"))
            .unwrap_or("configs/verifier.toml".to_string());
        let content = std::fs::read_to_string(path)?;
        let mut config = toml::from_str::<Self>(&content)?;
        if let Ok(addr) = std::env::var("RATS_VERIFIER_ADDR") {
            config.addr = addr;
        }
        Ok(config)
    }
}
