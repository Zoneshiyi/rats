use anyhow::Result;
use attester::config::{AttesterConfig, EvidenceSource};
use attester::{
    Attester, AttesterApplicationService, FileBackedAttester, GrpcVerifierGateway,
    GuestComponentsRestAttester, into_grpc_service,
};
use std::sync::Arc;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<()> {
    let config = AttesterConfig::load()?;
    let socket_addr: std::net::SocketAddr = config.addr.parse()?;
    let tee = config.parse_tee()?;
    let attester: Arc<dyn Attester> = match config.parse_evidence_source()? {
        EvidenceSource::File => Arc::new(FileBackedAttester::new(
            config.cca_evidence_path,
            config.tdx_evidence_path,
            config.csv_evidence_path,
            config.kunpeng_evidence_path,
        )),
        EvidenceSource::GuestComponentsRest => {
            Arc::new(GuestComponentsRestAttester::new(config.aa_evidence_url))
        }
    };
    let service = Arc::new(AttesterApplicationService::new(
        tee,
        attester,
        Arc::new(GrpcVerifierGateway::new(config.verifier_addr)),
    ));
    Server::builder()
        .add_service(into_grpc_service(service))
        .serve(socket_addr)
        .await?;
    Ok(())
}
