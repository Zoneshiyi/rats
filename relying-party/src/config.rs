use anyhow::Result;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct RelyingPartyConfig {
    pub addr: String,
    pub mode: String,
    pub nonce: String,
}

impl RelyingPartyConfig {
    pub fn load() -> Result<Self> {
        let path =
            std::env::var("RATS_RP_CONFIG").unwrap_or("configs/relying-party.toml".to_string());
        let content = std::fs::read_to_string(path)?;
        let mut config = toml::from_str::<Self>(&content)?;
        if let Ok(addr) = std::env::var("RATS_RP_ADDR") {
            config.addr = addr;
        }
        if let Ok(mode) = std::env::var("RATS_RP_MODE") {
            config.mode = mode;
        }
        if let Ok(nonce) = std::env::var("RATS_RP_NONCE") {
            config.nonce = nonce;
        }
        Ok(config)
    }
}
