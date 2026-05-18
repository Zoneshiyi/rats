use anyhow::Result;
use attester::config::{AttesterConfig, EvidenceSource};
use attester::{
    Attester, AttesterApplicationService, FileBackedAttester, GrpcVerifierGateway,
    GuestComponentsGrpcAttester, GuestComponentsRestAttester, into_grpc_service,
};
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = AttesterConfig::load()?;
    let socket_addr: std::net::SocketAddr = config.addr.parse()?;
    let tee = config.parse_tee()?;
    let evidence_source = config.parse_evidence_source()?;
    let attester: Arc<dyn Attester> = match evidence_source {
        EvidenceSource::File => Arc::new(FileBackedAttester::new(
            config.cca_evidence_path,
            config.tdx_evidence_path,
            config.csv_evidence_path,
            config.kunpeng_evidence_path,
        )),
        EvidenceSource::GuestComponentsRest => {
            Arc::new(GuestComponentsRestAttester::new(config.aa_evidence_url))
        }
        EvidenceSource::GuestComponentsGrpc => {
            Arc::new(GuestComponentsGrpcAttester::new(config.aa_evidence_url))
        }
    };
    let service = Arc::new(AttesterApplicationService::new_with_evidence_source(
        tee,
        evidence_source.as_token_value(),
        attester,
        Arc::new(GrpcVerifierGateway::new(config.verifier_addr)),
    ));
    info!(
        addr = %socket_addr,
        tee = ?tee,
        evidence_source = evidence_source.as_token_value(),
        "starting attester service"
    );
    Server::builder()
        .add_service(into_grpc_service(service))
        .serve(socket_addr)
        .await?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
