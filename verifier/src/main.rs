use anyhow::Result;
use std::sync::Arc;
use tonic::transport::Server;
use verifier::api::into_grpc_service;
use verifier::config::set_global;
use verifier::service::{ServiceConfig, VerifierApplicationService};
use verifier::service_config::VerifierServiceConfig;

#[tokio::main]
async fn main() -> Result<()> {
    let config = VerifierServiceConfig::load()?;
    set_global(config.verifier.clone());
    let socket_addr: std::net::SocketAddr = config.addr.parse()?;
    let service_config = ServiceConfig::from_runtime_config(&config.verifier)?;
    let service = Arc::new(VerifierApplicationService::with_defaults(service_config));

    Server::builder()
        .add_service(into_grpc_service(service))
        .serve(socket_addr)
        .await?;
    Ok(())
}
