use anyhow::Result;
use async_trait::async_trait;
use kbs_types::Tee;
use protos::attestation_response;
use protos::attestation_service_server::{
    AttestationService as AttestationServiceApi, AttestationServiceServer,
};
use protos::verifier_service_client::VerifierServiceClient;
use protos::{
    AttestationRequest, AttestationResponse, ErrorCode, Evidence, EvidenceList, Mode,
    Tee as ProtoTee, VerifierRequest, VerificationRequest, VerificationResponse,
};
use std::sync::Arc;
use tokio::fs;
use tonic::{Request, Response, Status};

#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub init_data: Vec<u8>,
    pub runtime_data: Vec<u8>,
}

impl AttestationEvidence {
    fn to_proto(&self) -> Evidence {
        Evidence {
            init_data: self.init_data.clone(),
            runtime_data: self.runtime_data.clone(),
        }
    }
}

#[async_trait]
pub trait Attester {
    async fn get_evidence(&self, tee: Tee, nonce: &[u8]) -> Result<Vec<AttestationEvidence>>;
}

#[derive(Debug, Default)]
pub struct FileBackedAttester;

impl FileBackedAttester {
    async fn load_runtime_data(&self, tee: Tee) -> Result<Vec<u8>> {
        let env_key = match tee {
            Tee::Cca => "RATS_CCA_EVIDENCE_PATH",
            Tee::Tdx => "RATS_TDX_EVIDENCE_PATH",
            _ => "RATS_EVIDENCE_PATH",
        };

        if let Ok(path) = std::env::var(env_key) {
            let bytes = fs::read(path).await?;
            return Ok(bytes);
        }

        let fallback = match tee {
            Tee::Cca => b"mock-cca-evidence".to_vec(),
            Tee::Tdx => b"mock-tdx-evidence".to_vec(),
            _ => b"mock-evidence".to_vec(),
        };
        Ok(fallback)
    }
}

#[async_trait]
impl Attester for FileBackedAttester {
    async fn get_evidence(&self, tee: Tee, nonce: &[u8]) -> Result<Vec<AttestationEvidence>> {
        let runtime_data = self.load_runtime_data(tee).await?;
        Ok(vec![AttestationEvidence {
            init_data: nonce.to_vec(),
            runtime_data,
        }])
    }
}

pub struct AttestationService {
    tee: Tee,
    attester: Arc<dyn Attester + Send + Sync>,
}

impl AttestationService {
    pub fn new(tee: Tee, attester: Arc<dyn Attester + Send + Sync>) -> Self {
        Self { tee, attester }
    }

    pub async fn attestation_evaluate(&self, req: &AttestationRequest) -> AttestationResponse {
        let mode = Mode::try_from(req.mode).unwrap_or(Mode::Unspecified);
        let evidences = match self.attester.get_evidence(self.tee, &req.nonce).await {
            Ok(v) => v,
            Err(_) => return attestation_error(ErrorCode::Internal),
        };

        match mode {
            Mode::Passport => {
                let raw = match evidences.first() {
                    Some(item) => item.runtime_data.as_slice(),
                    None => return attestation_error(ErrorCode::Internal),
                };
                match verify_by_tee(self.tee, raw).await {
                    Ok(token) => attestation_with_token(token.into_bytes()),
                    Err(_) => attestation_error(ErrorCode::Internal),
                }
            }
            Mode::BackgroundCheck | Mode::Mix => {
                let list = EvidenceList {
                    evidence: evidences.iter().map(AttestationEvidence::to_proto).collect(),
                };
                attestation_with_evidence(list)
            }
            Mode::Unspecified => attestation_error(ErrorCode::UnsupportedMode),
        }
    }

    pub async fn verification_evaluate(&self, req: &VerificationRequest) -> VerificationResponse {
        let evidence = match req.evidence.first() {
            Some(v) => v,
            None => return verification_error(ErrorCode::InvalidArgument),
        };

        match verify_by_tee(self.tee, &evidence.runtime_data).await {
            Ok(token) => {
                VerificationResponse {
                    error_code: ErrorCode::Ok as i32,
                    attestation_token: token.into_bytes(),
                }
            }
            Err(_) => verification_error(ErrorCode::Internal),
        }
    }
}

pub fn into_grpc_service(
    service: Arc<AttestationService>,
) -> AttestationServiceServer<GrpcAttestationService> {
    AttestationServiceServer::new(GrpcAttestationService { service })
}

async fn verify_by_tee(tee: Tee, raw_evidence: &[u8]) -> Result<String> {
    let addr = std::env::var("RATS_VERIFIER_ADDR").unwrap_or("127.0.0.1:50061".to_string());
    let endpoint = format!("http://{}", addr);
    let mut client = VerifierServiceClient::connect(endpoint).await?;
    let tee = match tee {
        Tee::Cca => ProtoTee::Cca,
        Tee::Tdx => ProtoTee::Tdx,
        _ => ProtoTee::Unspecified,
    };
    let req = VerifierRequest {
        tee: tee as i32,
        evidence: raw_evidence.to_vec(),
    };
    let response = client.verify(Request::new(req)).await?.into_inner();
    if response.error_code != ErrorCode::Ok as i32 {
        return Err(anyhow::anyhow!(
            "verifier service failed with code {}",
            response.error_code
        ));
    }
    Ok(String::from_utf8(response.attestation_token)?)
}

fn attestation_with_evidence(evidence_list: EvidenceList) -> AttestationResponse {
    AttestationResponse {
        error_code: ErrorCode::Ok as i32,
        result: Some(attestation_response::Result::EvidenceList(evidence_list)),
    }
}

fn attestation_with_token(token: Vec<u8>) -> AttestationResponse {
    AttestationResponse {
        error_code: ErrorCode::Ok as i32,
        result: Some(attestation_response::Result::AttestationToken(token)),
    }
}

fn attestation_error(error_code: ErrorCode) -> AttestationResponse {
    AttestationResponse {
        error_code: error_code as i32,
        result: None,
    }
}

fn verification_error(error_code: ErrorCode) -> VerificationResponse {
    VerificationResponse {
        error_code: error_code as i32,
        attestation_token: Vec::new(),
    }
}

pub struct GrpcAttestationService {
    service: Arc<AttestationService>,
}

#[tonic::async_trait]
impl AttestationServiceApi for GrpcAttestationService {
    async fn attestation_evaluate(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let req = request.into_inner();
        let resp = self.service.attestation_evaluate(&req).await;
        Ok(Response::new(resp))
    }

    async fn verification_evaluate(
        &self,
        request: Request<VerificationRequest>,
    ) -> Result<Response<VerificationResponse>, Status> {
        let req = request.into_inner();
        let resp = self.service.verification_evaluate(&req).await;
        Ok(Response::new(resp))
    }
}
