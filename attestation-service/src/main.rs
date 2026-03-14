use anyhow::{Result, bail};
use attestation_service::{AttestationService, FileBackedAttester};
use kbs_types::Tee;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::var("RATS_ATTESTATION_ADDR").unwrap_or("127.0.0.1:50051".to_string());
    let tee = parse_tee()?;
    let service = Arc::new(AttestationService::new(tee, Arc::new(FileBackedAttester)));
    service.serve(&addr).await
}

fn parse_tee() -> Result<Tee> {
    let value = std::env::var("RATS_TEE").unwrap_or("cca".to_string());
    match value.to_ascii_lowercase().as_str() {
        "cca" => Ok(Tee::Cca),
        "tdx" => Ok(Tee::Tdx),
        _ => bail!("unsupported RATS_TEE value"),
    }
}
