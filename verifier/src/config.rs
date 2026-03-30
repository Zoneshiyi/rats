use anyhow::Result;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Clone, Debug, Deserialize)]
pub struct VerifierConfig {
    pub verifier_build: String,
    pub verifier_developer: String,
    pub signing_key_path: String,
    pub cca_trust_anchors_path: String,
    pub cca_reference_values_path: String,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            verifier_build: "verifier-1.0.0".to_string(),
            verifier_developer: "https://veraison-project.org".to_string(),
            signing_key_path: "test_certs/server.pkcs8.pem".to_string(),
            cca_trust_anchors_path: "test_data/cca/ta.json".to_string(),
            cca_reference_values_path: "test_data/cca/rv.json".to_string(),
        }
    }
}

static CONFIG: OnceLock<VerifierConfig> = OnceLock::new();

pub fn set_global(config: VerifierConfig) {
    let _ = CONFIG.set(config);
}

pub fn set_global_from_file(path: &str) -> Result<()> {
    let config = load_from_file(path)?;
    set_global(config);
    Ok(())
}

pub fn get() -> &'static VerifierConfig {
    CONFIG.get_or_init(|| load_default_file().unwrap_or_else(|_| VerifierConfig::default()))
}

fn load_from_file(path: &str) -> Result<VerifierConfig> {
    let content = std::fs::read_to_string(resolve_path(path))?;
    let config = toml::from_str::<VerifierConfig>(&content)?;
    Ok(config)
}

pub fn read_text(path: &str) -> Result<String> {
    Ok(std::fs::read_to_string(resolve_path(path))?)
}

pub fn read_binary(path: &str) -> Result<Vec<u8>> {
    Ok(std::fs::read(resolve_path(path))?)
}

fn load_default_file() -> Result<VerifierConfig> {
    for path in default_config_candidates() {
        if path.exists() {
            return load_from_file(path.to_string_lossy().as_ref());
        }
    }
    Err(anyhow::anyhow!("verifier config file not found"))
}

fn resolve_path(path: &str) -> PathBuf {
    for candidate in path_candidates(path) {
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from(path)
}

fn default_config_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("configs/verifier.toml"),
        PathBuf::from("../configs/verifier.toml"),
        PathBuf::from("../../configs/verifier.toml"),
    ]
}

fn path_candidates(path: &str) -> Vec<PathBuf> {
    vec![
        PathBuf::from(path),
        PathBuf::from("..").join(path),
        PathBuf::from("../..").join(path),
    ]
}
