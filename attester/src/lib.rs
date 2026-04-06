use anyhow::Result;
use async_trait::async_trait;
use protos::attestation_response;
use protos::attestation_service_server::{
    AttestationService as AttestationServiceApi, AttestationServiceServer,
};
use protos::challenge::decode as decode_challenge_token;
use protos::verifier_service_client::VerifierServiceClient;
use protos::{
    AttestationRequest, AttestationResponse, ChallengeRequest, ChallengeResponse, ErrorCode,
    Evidence, EvidenceList, Mode, Tee, VerificationRequest, VerificationResponse,
    VerifierChallengeRequest, VerifierRequest,
};
use std::sync::Arc;
use tokio::fs;
use tonic::{Request, Response, Status};

pub mod config;

#[derive(Debug, Clone)]
pub struct AttesterEvidence {
    pub init_data: Vec<u8>,
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttestationChallenge {
    pub tee: Tee,
    pub mode: Mode,
    pub nonce: Vec<u8>,
    pub challenge_token: Vec<u8>,
}

impl AttesterEvidence {
    fn to_proto(&self) -> Evidence {
        Evidence {
            init_data: self.init_data.clone(),
            runtime_data: self.runtime_data.clone(),
        }
    }
}

#[async_trait]
pub trait Attester {
    async fn get_evidence(
        &self,
        tee: Tee,
        challenge: &AttestationChallenge,
    ) -> Result<Vec<AttesterEvidence>>;
}

#[derive(Debug)]
pub struct FileBackedAttester {
    cca_evidence_path: String,
    tdx_evidence_path: String,
    csv_evidence_path: String,
    kunpeng_evidence_path: String,
}

impl FileBackedAttester {
    pub fn new(
        cca_evidence_path: String,
        tdx_evidence_path: String,
        csv_evidence_path: String,
        kunpeng_evidence_path: String,
    ) -> Self {
        Self {
            cca_evidence_path,
            tdx_evidence_path,
            csv_evidence_path,
            kunpeng_evidence_path,
        }
    }

    async fn load_runtime_data(&self, tee: Tee) -> Result<Vec<u8>> {
        let path = match tee {
            Tee::Cca => &self.cca_evidence_path,
            Tee::Tdx => &self.tdx_evidence_path,
            Tee::Csv => &self.csv_evidence_path,
            Tee::Kunpeng => &self.kunpeng_evidence_path,
            _ => {
                return Err(anyhow::anyhow!("unsupported tee for file-backed attester"));
            }
        };
        Ok(fs::read(path).await?)
    }
}

#[async_trait]
impl Attester for FileBackedAttester {
    async fn get_evidence(
        &self,
        tee: Tee,
        challenge: &AttestationChallenge,
    ) -> Result<Vec<AttesterEvidence>> {
        let runtime_data = self.load_runtime_data(tee).await?;
        Ok(vec![AttesterEvidence {
            init_data: challenge.nonce.clone(),
            runtime_data,
        }])
    }
}

pub struct AttesterService {
    tee: Tee,
    verifier_addr: String,
    attester: Arc<dyn Attester + Send + Sync>,
}

impl AttesterService {
    pub fn new(tee: Tee, verifier_addr: String, attester: Arc<dyn Attester + Send + Sync>) -> Self {
        Self {
            tee,
            verifier_addr,
            attester,
        }
    }

    pub async fn attestation_evaluate(&self, req: &AttestationRequest) -> AttestationResponse {
        let challenge = match self.decode_challenge(Some(req.mode), &req.challenge_token) {
            Ok(challenge) => challenge,
            Err(_) => return attestation_error(ErrorCode::InvalidArgument),
        };
        let mode = challenge.mode;
        let evidences = match self.attester.get_evidence(self.tee, &challenge).await {
            Ok(v) => v,
            Err(_) => return attestation_error(ErrorCode::Internal),
        };

        match mode {
            Mode::Passport => {
                let raw = match evidences.first() {
                    Some(item) => item.runtime_data.as_slice(),
                    None => return attestation_error(ErrorCode::Internal),
                };
                match verify_by_tee(
                    self.tee,
                    raw,
                    &challenge.challenge_token,
                    &self.verifier_addr,
                )
                .await
                {
                    Ok(token) => attestation_with_token(token.into_bytes()),
                    Err(_) => attestation_error(ErrorCode::Internal),
                }
            }
            Mode::BackgroundCheck | Mode::Mix => {
                let list = EvidenceList {
                    evidence: evidences.iter().map(AttesterEvidence::to_proto).collect(),
                };
                attestation_with_evidence(list)
            }
            Mode::Unspecified => attestation_error(ErrorCode::UnsupportedMode),
        }
    }

    pub async fn verification_evaluate(&self, req: &VerificationRequest) -> VerificationResponse {
        if self.decode_challenge(None, &req.challenge_token).is_err() {
            return verification_error(ErrorCode::InvalidArgument);
        }
        let evidence = match req.evidence.first() {
            Some(v) => v,
            None => return verification_error(ErrorCode::InvalidArgument),
        };

        match verify_by_tee(
            self.tee,
            &evidence.runtime_data,
            &req.challenge_token,
            &self.verifier_addr,
        )
        .await
        {
            Ok(token) => VerificationResponse {
                error_code: ErrorCode::Ok as i32,
                attestation_token: token.into_bytes(),
            },
            Err(_) => verification_error(ErrorCode::Internal),
        }
    }

    pub async fn get_challenge(&self, req: &ChallengeRequest) -> ChallengeResponse {
        let mode = Mode::try_from(req.mode).unwrap_or(Mode::Unspecified);
        if mode == Mode::Unspecified {
            return ChallengeResponse {
                error_code: ErrorCode::InvalidArgument as i32,
                nonce: Vec::new(),
                challenge_token: Vec::new(),
            };
        }

        match issue_challenge(self.tee, mode, &req.nonce, &self.verifier_addr).await {
            Ok((nonce, challenge_token)) => ChallengeResponse {
                error_code: ErrorCode::Ok as i32,
                nonce,
                challenge_token,
            },
            Err(_) => ChallengeResponse {
                error_code: ErrorCode::Internal as i32,
                nonce: Vec::new(),
                challenge_token: Vec::new(),
            },
        }
    }

    fn decode_challenge(
        &self,
        expected_mode: Option<i32>,
        challenge_token: &[u8],
    ) -> Result<AttestationChallenge> {
        let claims = decode_challenge_token(challenge_token)?;
        if claims.tee != self.tee as i32 {
            return Err(anyhow::anyhow!("challenge tee mismatch"));
        }
        if let Some(mode) = expected_mode
            && claims.mode != mode
        {
            return Err(anyhow::anyhow!("challenge mode mismatch"));
        }
        Ok(AttestationChallenge {
            tee: self.tee,
            mode: Mode::try_from(claims.mode).unwrap_or(Mode::Unspecified),
            nonce: claims.nonce_bytes()?,
            challenge_token: challenge_token.to_vec(),
        })
    }
}

pub fn into_grpc_service(
    service: Arc<AttesterService>,
) -> AttestationServiceServer<GrpcAttesterService> {
    AttestationServiceServer::new(GrpcAttesterService { service })
}

async fn issue_challenge(
    tee: Tee,
    mode: Mode,
    requested_nonce: &[u8],
    verifier_addr: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let endpoint = format!("http://{}", verifier_addr);
    let mut client = VerifierServiceClient::connect(endpoint).await?;
    let req = VerifierChallengeRequest {
        tee: tee as i32,
        mode: mode as i32,
        nonce: requested_nonce.to_vec(),
    };
    let response = client
        .issue_challenge(Request::new(req))
        .await?
        .into_inner();
    if response.error_code != ErrorCode::Ok as i32 {
        return Err(anyhow::anyhow!(
            "verifier issue challenge failed with code {}",
            response.error_code
        ));
    }
    Ok((response.nonce, response.challenge_token))
}

async fn verify_by_tee(
    tee: Tee,
    raw_evidence: &[u8],
    challenge_token: &[u8],
    verifier_addr: &str,
) -> Result<String> {
    let endpoint = format!("http://{}", verifier_addr);
    let mut client = VerifierServiceClient::connect(endpoint).await?;
    let req = VerifierRequest {
        tee: tee as i32,
        evidence: raw_evidence.to_vec(),
        challenge_token: challenge_token.to_vec(),
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

pub struct GrpcAttesterService {
    service: Arc<AttesterService>,
}

#[tonic::async_trait]
impl AttestationServiceApi for GrpcAttesterService {
    async fn get_challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        let resp = self.service.get_challenge(&req).await;
        Ok(Response::new(resp))
    }

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
