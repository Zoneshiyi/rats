use anyhow::{Result, bail};
use attestation_service::{AttestationService, FileBackedAttester, into_grpc_service};
use kbs_types::Tee;
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::var("RATS_ATTESTATION_ADDR").unwrap_or("127.0.0.1:50051".to_string());
    let socket_addr: std::net::SocketAddr = addr.parse()?;
    let tee = parse_tee()?;
    let service = Arc::new(AttestationService::new(tee, Arc::new(FileBackedAttester)));
    Server::builder()
        .add_service(into_grpc_service(service))
        .serve(socket_addr)
        .await?;
    Ok(())
}

fn parse_tee() -> Result<Tee> {
    let value = std::env::var("RATS_TEE").unwrap_or("cca".to_string());
    match value.to_ascii_lowercase().as_str() {
        "cca" => Ok(Tee::Cca),
        "tdx" => Ok(Tee::Tdx),
        _ => bail!("unsupported RATS_TEE value"),
    }
}
