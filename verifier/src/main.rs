use anyhow::Result;
use protos::challenge;
use protos::verifier_service_server::{VerifierService, VerifierServiceServer};
use protos::{
    ErrorCode, Mode, Tee, VerifierChallengeRequest, VerifierChallengeResponse, VerifierRequest,
    VerifierResponse,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use verifier::config::{get as verifier_config, read_binary, set_global};
use verifier::service_config::VerifierServiceConfig;
use verifier::to_verifier;

#[tokio::main]
async fn main() -> Result<()> {
    let config = VerifierServiceConfig::load()?;
    set_global(config.verifier.clone());
    let socket_addr: std::net::SocketAddr = config.addr.parse()?;
    Server::builder()
        .add_service(VerifierServiceServer::new(GrpcVerifierService))
        .serve(socket_addr)
        .await?;
    Ok(())
}

struct GrpcVerifierService;

#[tonic::async_trait]
impl VerifierService for GrpcVerifierService {
    async fn issue_challenge(
        &self,
        request: Request<VerifierChallengeRequest>,
    ) -> Result<Response<VerifierChallengeResponse>, Status> {
        let req = request.into_inner();
        let tee = Tee::try_from(req.tee).unwrap_or(Tee::Unspecified);
        if tee == Tee::Unspecified {
            return Err(Status::invalid_argument("unsupported tee"));
        }
        let mode = Mode::try_from(req.mode).unwrap_or(Mode::Unspecified);
        if mode == Mode::Unspecified {
            return Err(Status::invalid_argument("unsupported mode"));
        }

        let config = verifier_config();
        if !req.nonce.is_empty() && !config.allow_test_nonce {
            return Err(Status::invalid_argument("custom nonce is disabled"));
        }
        let signing_key =
            read_binary(&config.challenge_signing_key_path).map_err(internal_status)?;
        let requested_nonce = (!req.nonce.is_empty()).then_some(req.nonce.as_slice());
        let (nonce, challenge_token) = challenge::issue(
            req.tee,
            req.mode,
            requested_nonce,
            config.challenge_ttl_secs,
            &signing_key,
        )
        .map_err(internal_status)?;

        Ok(Response::new(VerifierChallengeResponse {
            error_code: ErrorCode::Ok as i32,
            nonce,
            challenge_token,
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifierRequest>,
    ) -> Result<Response<VerifierResponse>, Status> {
        let req = request.into_inner();
        let tee = Tee::try_from(req.tee).unwrap_or(Tee::Unspecified);
        if tee == Tee::Unspecified {
            return Err(Status::invalid_argument("unsupported tee"));
        }
        let config = verifier_config();
        let signing_key =
            read_binary(&config.challenge_signing_key_path).map_err(internal_status)?;
        let challenge = challenge::verify(&req.challenge_token, Some(req.tee), None, &signing_key)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let verifier = to_verifier(&tee).map_err(internal_status)?;
        let token = verifier
            .verify(&req.evidence, &challenge)
            .await
            .map_err(internal_status)?;
        Ok(Response::new(VerifierResponse {
            error_code: ErrorCode::Ok as i32,
            attestation_token: token.into_bytes(),
        }))
    }
}

fn internal_status<E: std::fmt::Display>(err: E) -> Status {
    Status::internal(err.to_string())
}
