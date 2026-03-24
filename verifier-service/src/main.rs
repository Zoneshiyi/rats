use anyhow::Result;
use kbs_types::Tee as KbsTee;
use protos::verifier_service_server::{VerifierService, VerifierServiceServer};
use protos::{ErrorCode, Tee, VerifierRequest, VerifierResponse};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use verifier::to_verifier;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::var("RATS_VERIFIER_ADDR").unwrap_or("127.0.0.1:50061".to_string());
    let socket_addr: std::net::SocketAddr = addr.parse()?;
    Server::builder()
        .add_service(VerifierServiceServer::new(GrpcVerifierService))
        .serve(socket_addr)
        .await?;
    Ok(())
}

struct GrpcVerifierService;

#[tonic::async_trait]
impl VerifierService for GrpcVerifierService {
    async fn verify(
        &self,
        request: Request<VerifierRequest>,
    ) -> Result<Response<VerifierResponse>, Status> {
        let req = request.into_inner();
        let tee = proto_tee_to_kbs(req.tee).map_err(Status::invalid_argument)?;
        let verifier = to_verifier(&tee).map_err(internal_status)?;
        let token = verifier.verify(&req.evidence).await.map_err(internal_status)?;
        Ok(Response::new(VerifierResponse {
            error_code: ErrorCode::Ok as i32,
            attestation_token: token.into_bytes(),
        }))
    }
}

fn proto_tee_to_kbs(tee: i32) -> Result<KbsTee, String> {
    match Tee::try_from(tee).unwrap_or(Tee::Unspecified) {
        Tee::Cca => Ok(KbsTee::Cca),
        Tee::Tdx => Ok(KbsTee::Tdx),
        Tee::Unspecified => Err("unsupported tee".to_string()),
    }
}

fn internal_status<E: std::fmt::Display>(err: E) -> Status {
    Status::internal(err.to_string())
}
