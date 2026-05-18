use anyhow::Result;
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;
use verifier::api::into_grpc_service;
use verifier::config::set_global;
use verifier::service::{ServiceConfig, VerifierApplicationService};
use verifier::service_config::VerifierServiceConfig;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = VerifierServiceConfig::load()?;
    set_global(config.verifier.clone());
    let socket_addr: std::net::SocketAddr = config.addr.parse()?;
    let service_config = ServiceConfig::from_runtime_config(&config.verifier)?;
    let service = Arc::new(VerifierApplicationService::with_defaults(service_config));

    info!(addr = %socket_addr, "starting verifier service");
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
