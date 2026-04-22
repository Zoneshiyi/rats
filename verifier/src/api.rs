use std::sync::Arc;

use protos::verifier_service_server::{VerifierService, VerifierServiceServer};
use protos::{
    ErrorCode, Mode, Tee, VerifierChallengeRequest, VerifierChallengeResponse, VerifierRequest,
    VerifierResponse,
};
use tonic::{Request, Response, Status};

use crate::service::{
    IssueChallengeInput, ServiceError, ServiceErrorKind, VerifierApplicationService,
    VerifyEvidenceInput,
};

pub fn into_grpc_service(
    service: Arc<VerifierApplicationService>,
) -> VerifierServiceServer<GrpcVerifierService> {
    VerifierServiceServer::new(GrpcVerifierService { service })
}

pub struct GrpcVerifierService {
    service: Arc<VerifierApplicationService>,
}

#[tonic::async_trait]
impl VerifierService for GrpcVerifierService {
    async fn issue_challenge(
        &self,
        request: Request<VerifierChallengeRequest>,
    ) -> Result<Response<VerifierChallengeResponse>, Status> {
        let req = request.into_inner();
        let response = self
            .service
            .issue_challenge(IssueChallengeInput {
                tee: Tee::try_from(req.tee).unwrap_or(Tee::Unspecified),
                mode: Mode::try_from(req.mode).unwrap_or(Mode::Unspecified) as i32,
                requested_nonce: req.nonce,
            })
            .await
            .map_err(map_service_error)?;

        Ok(Response::new(VerifierChallengeResponse {
            error_code: ErrorCode::Ok as i32,
            nonce: response.nonce,
            challenge_token: response.challenge_token,
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifierRequest>,
    ) -> Result<Response<VerifierResponse>, Status> {
        let req = request.into_inner();
        let response = self
            .service
            .verify(VerifyEvidenceInput {
                tee: Tee::try_from(req.tee).unwrap_or(Tee::Unspecified),
                evidence: req.evidence,
                challenge_token: req.challenge_token,
            })
            .await
            .map_err(map_service_error)?;

        Ok(Response::new(VerifierResponse {
            error_code: ErrorCode::Ok as i32,
            attestation_token: response.attestation_token,
        }))
    }
}

fn map_service_error(err: ServiceError) -> Status {
    match err.kind() {
        ServiceErrorKind::InvalidArgument => Status::invalid_argument(err.message().to_string()),
        ServiceErrorKind::Internal => Status::internal(err.message().to_string()),
    }
}
