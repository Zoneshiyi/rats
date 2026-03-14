use anyhow::{Result, bail};
use async_trait::async_trait;
use kbs_types::Tee;
use protobuf::{EnumOrUnknown, Message};
use protos::attestation_response;
use protos::rpc_request;
use protos::rpc_response;
use protos::{
    AttestationRequest, AttestationResponse, ErrorCode, Evidence, EvidenceList, Mode, RpcMethod,
    RpcRequest, RpcResponse, VerificationRequest, VerificationResponse,
};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use verifier::to_verifier;

#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub init_data: Vec<u8>,
    pub runtime_data: Vec<u8>,
}

impl AttestationEvidence {
    fn to_proto(&self) -> Evidence {
        let mut evidence = Evidence::new();
        evidence.init_data = self.init_data.clone();
        evidence.runtime_data = self.runtime_data.clone();
        evidence
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
        let mode = req.mode.enum_value_or_default();
        let evidences = match self.attester.get_evidence(self.tee, &req.nonce).await {
            Ok(v) => v,
            Err(_) => return attestation_error(ErrorCode::ErrorCode_INTERNAL),
        };

        match mode {
            Mode::MODE_PASSPORT => {
                let raw = match evidences.first() {
                    Some(item) => item.runtime_data.as_slice(),
                    None => return attestation_error(ErrorCode::ErrorCode_INTERNAL),
                };
                match verify_by_tee(self.tee, raw).await {
                    Ok(token) => attestation_with_token(token.into_bytes()),
                    Err(_) => attestation_error(ErrorCode::ErrorCode_INTERNAL),
                }
            }
            Mode::MODE_BACKGROUND_CHECK | Mode::MODE_MIX => {
                let mut list = EvidenceList::new();
                list.evidence = evidences.iter().map(AttestationEvidence::to_proto).collect();
                attestation_with_evidence(list)
            }
            Mode::MODE_UNSPECIFIED => attestation_error(ErrorCode::ErrorCode_UNSUPPORTED_MODE),
        }
    }

    pub async fn verification_evaluate(&self, req: &VerificationRequest) -> VerificationResponse {
        let evidence = match req.evidence.first() {
            Some(v) => v,
            None => return verification_error(ErrorCode::ErrorCode_INVALID_ARGUMENT),
        };

        match verify_by_tee(self.tee, &evidence.runtime_data).await {
            Ok(token) => {
                let mut response = VerificationResponse::new();
                response.error_code = EnumOrUnknown::new(ErrorCode::ErrorCode_OK);
                response.attestation_token = token.into_bytes();
                response
            }
            Err(_) => verification_error(ErrorCode::ErrorCode_INTERNAL),
        }
    }

    pub async fn serve(self: Arc<Self>, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (mut stream, _) = listener.accept().await?;
            let service = Arc::clone(&self);
            tokio::spawn(async move {
                if handle_connection(&service, &mut stream).await.is_err() {}
            });
        }
    }
}

pub struct RelyingPartyClient {
    addr: String,
}

impl RelyingPartyClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn attest(&self, mode: Mode, nonce: Vec<u8>) -> Result<AttestationResponse> {
        let mut request = AttestationRequest::new();
        request.mode = EnumOrUnknown::new(mode);
        request.nonce = nonce;

        let mut rpc = RpcRequest::new();
        rpc.method = EnumOrUnknown::new(RpcMethod::RPC_METHOD_ATTESTATION_EVALUATE);
        rpc.payload = Some(rpc_request::Payload::AttestationRequest(request));

        let mut stream = TcpStream::connect(&self.addr).await?;
        write_message(&mut stream, &rpc).await?;

        let response: RpcResponse = read_message(&mut stream).await?;
        let payload = response
            .payload
            .ok_or_else(|| anyhow::anyhow!("missing rpc response payload"))?;
        match payload {
            rpc_response::Payload::AttestationResponse(resp) => Ok(resp),
            _ => bail!("unexpected rpc response payload"),
        }
    }

    pub async fn verify(&self, evidence: Vec<Evidence>) -> Result<VerificationResponse> {
        let mut request = VerificationRequest::new();
        request.evidence = evidence;

        let mut rpc = RpcRequest::new();
        rpc.method = EnumOrUnknown::new(RpcMethod::RPC_METHOD_VERIFICATION_EVALUATE);
        rpc.payload = Some(rpc_request::Payload::VerificationRequest(request));

        let mut stream = TcpStream::connect(&self.addr).await?;
        write_message(&mut stream, &rpc).await?;

        let response: RpcResponse = read_message(&mut stream).await?;
        let payload = response
            .payload
            .ok_or_else(|| anyhow::anyhow!("missing rpc response payload"))?;
        match payload {
            rpc_response::Payload::VerificationResponse(resp) => Ok(resp),
            _ => bail!("unexpected rpc response payload"),
        }
    }
}

async fn verify_by_tee(tee: Tee, raw_evidence: &[u8]) -> Result<String> {
    let verifier = to_verifier(&tee)?;
    verifier.verify(raw_evidence).await
}

fn attestation_with_evidence(evidence_list: EvidenceList) -> AttestationResponse {
    let mut response = AttestationResponse::new();
    response.error_code = EnumOrUnknown::new(ErrorCode::ErrorCode_OK);
    response.result = Some(attestation_response::Result::EvidenceList(evidence_list));
    response
}

fn attestation_with_token(token: Vec<u8>) -> AttestationResponse {
    let mut response = AttestationResponse::new();
    response.error_code = EnumOrUnknown::new(ErrorCode::ErrorCode_OK);
    response.result = Some(attestation_response::Result::AttestationToken(token));
    response
}

fn attestation_error(error_code: ErrorCode) -> AttestationResponse {
    let mut response = AttestationResponse::new();
    response.error_code = EnumOrUnknown::new(error_code);
    response
}

fn verification_error(error_code: ErrorCode) -> VerificationResponse {
    let mut response = VerificationResponse::new();
    response.error_code = EnumOrUnknown::new(error_code);
    response
}

async fn handle_connection(service: &AttestationService, stream: &mut TcpStream) -> Result<()> {
    let request: RpcRequest = read_message(stream).await?;
    let method = request.method.enum_value_or_default();
    let response = match method {
        RpcMethod::RPC_METHOD_ATTESTATION_EVALUATE => {
            let payload = request.payload.ok_or_else(|| anyhow::anyhow!("missing payload"))?;
            let req = match payload {
                rpc_request::Payload::AttestationRequest(v) => v,
                _ => {
                    let mut rpc = RpcResponse::new();
                    rpc.method =
                        EnumOrUnknown::new(RpcMethod::RPC_METHOD_ATTESTATION_EVALUATE);
                    rpc.payload = Some(rpc_response::Payload::AttestationResponse(
                        attestation_error(ErrorCode::ErrorCode_INVALID_ARGUMENT),
                    ));
                    write_message(stream, &rpc).await?;
                    return Ok(());
                }
            };
            let attestation_response = service.attestation_evaluate(&req).await;
            let mut rpc = RpcResponse::new();
            rpc.method = EnumOrUnknown::new(RpcMethod::RPC_METHOD_ATTESTATION_EVALUATE);
            rpc.payload = Some(rpc_response::Payload::AttestationResponse(
                attestation_response,
            ));
            rpc
        }
        RpcMethod::RPC_METHOD_VERIFICATION_EVALUATE => {
            let payload = request.payload.ok_or_else(|| anyhow::anyhow!("missing payload"))?;
            let req = match payload {
                rpc_request::Payload::VerificationRequest(v) => v,
                _ => {
                    let mut rpc = RpcResponse::new();
                    rpc.method =
                        EnumOrUnknown::new(RpcMethod::RPC_METHOD_VERIFICATION_EVALUATE);
                    rpc.payload = Some(rpc_response::Payload::VerificationResponse(
                        verification_error(ErrorCode::ErrorCode_INVALID_ARGUMENT),
                    ));
                    write_message(stream, &rpc).await?;
                    return Ok(());
                }
            };
            let verification_response = service.verification_evaluate(&req).await;
            let mut rpc = RpcResponse::new();
            rpc.method = EnumOrUnknown::new(RpcMethod::RPC_METHOD_VERIFICATION_EVALUATE);
            rpc.payload = Some(rpc_response::Payload::VerificationResponse(
                verification_response,
            ));
            rpc
        }
        RpcMethod::RPC_METHOD_UNSPECIFIED => {
            let mut rpc = RpcResponse::new();
            rpc.method = EnumOrUnknown::new(RpcMethod::RPC_METHOD_UNSPECIFIED);
            rpc.payload = Some(rpc_response::Payload::AttestationResponse(
                attestation_error(ErrorCode::ErrorCode_INVALID_ARGUMENT),
            ));
            rpc
        }
    };
    write_message(stream, &response).await?;
    Ok(())
}

async fn write_message<T: Message>(stream: &mut TcpStream, message: &T) -> Result<()> {
    let bytes = message.write_to_bytes()?;
    let len = u32::try_from(bytes.len())?;
    stream.write_u32(len).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_message<T: Message + Default>(stream: &mut TcpStream) -> Result<T> {
    let len = stream.read_u32().await?;
    let mut bytes = vec![0u8; len as usize];
    stream.read_exact(&mut bytes).await?;
    Ok(T::parse_from_bytes(&bytes)?)
}
