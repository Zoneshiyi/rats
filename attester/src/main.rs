use anyhow::Result;
use attester::config::AttesterConfig;
use attester::{AttesterService, FileBackedAttester, into_grpc_service};
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AttesterConfig::load()?;
    let socket_addr: std::net::SocketAddr = config.addr.parse()?;
    let tee = config.parse_tee()?;
    let attester = FileBackedAttester::new(
        config.cca_evidence_path,
        config.tdx_evidence_path,
        config.csv_evidence_path,
        config.kunpeng_evidence_path,
    );
    let service = Arc::new(AttesterService::new(
        tee,
        config.verifier_addr,
        Arc::new(attester),
    ));
    Server::builder()
        .add_service(into_grpc_service(service))
        .serve(socket_addr)
        .await?;
    Ok(())
}
