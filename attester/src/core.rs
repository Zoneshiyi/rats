use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use protos::attestation_agent::{
    GetEvidenceRequest, attestation_agent_service_client::AttestationAgentServiceClient,
};
use protos::challenge::decode as decode_challenge_token;
use protos::{Evidence, Mode, Tee};
use serde::Deserialize;
use tokio::fs;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttesterEvidence {
    pub init_data: Vec<u8>,
    pub runtime_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationChallenge {
    pub tee: Tee,
    pub mode: Mode,
    pub nonce: Vec<u8>,
    pub challenge_token: Vec<u8>,
}

impl AttesterEvidence {
    pub fn to_proto(&self) -> Evidence {
        Evidence {
            init_data: self.init_data.clone(),
            runtime_data: self.runtime_data.clone(),
        }
    }
}

#[async_trait]
pub trait Attester: Send + Sync {
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
            _ => return Err(anyhow!("unsupported tee for file-backed attester")),
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

#[derive(Debug, Clone)]
pub struct GuestComponentsRestAttester {
    evidence_url: String,
    client: reqwest::Client,
}

impl GuestComponentsRestAttester {
    pub fn new(evidence_url: impl Into<String>) -> Self {
        Self {
            evidence_url: normalize_evidence_url(evidence_url.into()),
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuestComponentsGrpcAttester {
    endpoint: String,
}

impl GuestComponentsGrpcAttester {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

#[async_trait]
impl Attester for GuestComponentsGrpcAttester {
    async fn get_evidence(
        &self,
        tee: Tee,
        challenge: &AttestationChallenge,
    ) -> Result<Vec<AttesterEvidence>> {
        if let Err(err) = validate_aa_runtime_data(&challenge.nonce) {
            warn!(
                tee = ?tee,
                runtime_data_len = challenge.nonce.len(),
                error = %err,
                "rejected guest-components gRPC runtime data"
            );
            return Err(err);
        }

        info!(
            tee = ?tee,
            endpoint = %self.endpoint,
            runtime_data_len = challenge.nonce.len(),
            "requesting guest-components gRPC evidence"
        );
        let connect_result = AttestationAgentServiceClient::connect(self.endpoint.clone()).await;
        if let Err(err) = &connect_result {
            warn!(
                tee = ?tee,
                endpoint = %self.endpoint,
                error = %err,
                "failed to connect to guest-components AA"
            );
        }
        let mut client = connect_result.with_context(|| {
            format!(
                "failed to connect to guest-components AA at {}",
                self.endpoint
            )
        })?;
        let response_result = client
            .get_evidence(GetEvidenceRequest {
                runtime_data: challenge.nonce.clone(),
            })
            .await;
        if let Err(err) = &response_result {
            warn!(
                tee = ?tee,
                endpoint = %self.endpoint,
                error = %err,
                "guest-components gRPC evidence request failed"
            );
        }
        let response = response_result.with_context(|| {
            format!(
                "failed to request guest-components gRPC evidence from {}",
                self.endpoint
            )
        })?;
        let evidence = response.into_inner().evidence;
        let raw_evidence_len = evidence.len();
        let runtime_data = match normalize_guest_components_evidence(tee, &evidence) {
            Ok(runtime_data) => runtime_data,
            Err(err) => {
                warn!(
                    tee = ?tee,
                    endpoint = %self.endpoint,
                    raw_evidence_len,
                    error = %err,
                    "failed to normalize guest-components gRPC evidence"
                );
                return Err(err);
            }
        };
        info!(
            tee = ?tee,
            endpoint = %self.endpoint,
            raw_evidence_len,
            normalized_evidence_len = runtime_data.len(),
            "received guest-components gRPC evidence"
        );
        Ok(vec![AttesterEvidence {
            init_data: challenge.nonce.clone(),
            runtime_data,
        }])
    }
}

#[async_trait]
impl Attester for GuestComponentsRestAttester {
    async fn get_evidence(
        &self,
        tee: Tee,
        challenge: &AttestationChallenge,
    ) -> Result<Vec<AttesterEvidence>> {
        let runtime_data = std::str::from_utf8(&challenge.nonce).context(
            "guest-components REST evidence requires a UTF-8 challenge nonce; use the default challenge or an ASCII --nonce",
        )?;
        info!(
            tee = ?tee,
            url = %self.evidence_url,
            runtime_data_len = challenge.nonce.len(),
            "requesting guest-components REST evidence"
        );
        let response_result = self
            .client
            .get(&self.evidence_url)
            .query(&[("runtime_data", runtime_data)])
            .send()
            .await;
        if let Err(err) = &response_result {
            warn!(
                tee = ?tee,
                url = %self.evidence_url,
                error = %err,
                "guest-components REST evidence request failed"
            );
        }
        let response = response_result.with_context(|| {
            format!(
                "failed to request guest-components evidence from {}",
                self.evidence_url
            )
        })?;
        let status = response.status();
        let body_result = response.bytes().await;
        if let Err(err) = &body_result {
            warn!(
                tee = ?tee,
                url = %self.evidence_url,
                status = %status,
                error = %err,
                "failed to read guest-components REST evidence response"
            );
        }
        let body = body_result
            .context("failed to read guest-components evidence response")?
            .to_vec();
        if !status.is_success() {
            warn!(
                tee = ?tee,
                url = %self.evidence_url,
                status = %status,
                body_len = body.len(),
                "guest-components REST evidence request returned non-success status"
            );
            bail!(
                "guest-components evidence request failed with {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }

        let raw_evidence_len = body.len();
        let runtime_data = match normalize_guest_components_evidence(tee, &body) {
            Ok(runtime_data) => runtime_data,
            Err(err) => {
                warn!(
                    tee = ?tee,
                    url = %self.evidence_url,
                    raw_evidence_len,
                    error = %err,
                    "failed to normalize guest-components REST evidence"
                );
                return Err(err);
            }
        };
        info!(
            tee = ?tee,
            url = %self.evidence_url,
            raw_evidence_len,
            normalized_evidence_len = runtime_data.len(),
            "received guest-components REST evidence"
        );
        Ok(vec![AttesterEvidence {
            init_data: challenge.nonce.clone(),
            runtime_data,
        }])
    }
}

fn validate_aa_runtime_data(runtime_data: &[u8]) -> Result<()> {
    if runtime_data.len() > 64 {
        bail!(
            "guest-components AA runtime_data must be at most 64 bytes for CCA/TDX/CSV report data fields"
        );
    }
    Ok(())
}

fn normalize_evidence_url(raw: String) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.ends_with("/aa/evidence") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/aa/evidence")
    }
}

fn normalize_guest_components_evidence(tee: Tee, raw: &[u8]) -> Result<Vec<u8>> {
    match tee {
        Tee::Cca => {
            #[derive(Deserialize)]
            struct CcaEvidence {
                token: JsonBytes,
            }

            Ok(serde_json::from_slice::<CcaEvidence>(raw)
                .context("failed to parse guest-components CCA evidence")?
                .token
                .into_vec()?)
        }
        Tee::Tdx => {
            #[derive(Deserialize)]
            struct TdxEvidence {
                quote: String,
            }

            let evidence = serde_json::from_slice::<TdxEvidence>(raw)
                .context("failed to parse guest-components TDX evidence")?;
            decode_base64(&evidence.quote).context("failed to decode guest-components TDX quote")
        }
        Tee::Csv => Ok(raw.to_vec()),
        Tee::Kunpeng => bail!("guest-components evidence does not support Kunpeng"),
        _ => bail!("unsupported tee for guest-components attester"),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonBytes {
    Bytes(Vec<u8>),
    Base64(String),
}

impl JsonBytes {
    fn into_vec(self) -> Result<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Base64(value) => decode_base64(&value),
        }
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
        .context("decode base64 evidence field")
}

pub fn decode_attestation_challenge(
    tee: Tee,
    expected_mode: Option<i32>,
    challenge_token: &[u8],
) -> Result<AttestationChallenge> {
    let claims = decode_challenge_token(challenge_token)?;
    if claims.tee != tee as i32 {
        return Err(anyhow!("challenge tee mismatch"));
    }
    if let Some(mode) = expected_mode
        && claims.mode != mode
    {
        return Err(anyhow!("challenge mode mismatch"));
    }

    Ok(AttestationChallenge {
        tee,
        mode: Mode::try_from(claims.mode).unwrap_or(Mode::Unspecified),
        nonce: claims.nonce_bytes()?,
        challenge_token: challenge_token.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use protos::attestation_agent::{
        BindInitDataRequest, BindInitDataResponse, ExtendRuntimeMeasurementRequest,
        ExtendRuntimeMeasurementResponse, GetAdditionalEvidenceRequest, GetAdditionalTeesRequest,
        GetAdditionalTeesResponse, GetEvidenceRequest, GetEvidenceResponse, GetTeeTypeRequest,
        GetTeeTypeResponse, GetTokenRequest, GetTokenResponse,
        attestation_agent_service_server::{
            AttestationAgentService, AttestationAgentServiceServer,
        },
    };
    use protos::challenge;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    #[tokio::test]
    async fn file_backed_attester_returns_nonce_as_init_data() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "rats-attester-{}-evidence.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        tokio::fs::write(&path, b"evidence").await?;

        let attester = FileBackedAttester::new(
            path.to_string_lossy().to_string(),
            path.to_string_lossy().to_string(),
            path.to_string_lossy().to_string(),
            path.to_string_lossy().to_string(),
        );
        let challenge = AttestationChallenge {
            tee: Tee::Csv,
            mode: Mode::Passport,
            nonce: b"expected-nonce".to_vec(),
            challenge_token: b"token".to_vec(),
        };

        let evidence = attester.get_evidence(Tee::Csv, &challenge).await?;
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].init_data, b"expected-nonce");
        assert_eq!(evidence[0].runtime_data, b"evidence");

        let _ = tokio::fs::remove_file(path).await;
        Ok(())
    }

    #[test]
    fn decode_attestation_challenge_rejects_tee_mismatch() -> Result<()> {
        let (_nonce, token) = challenge::issue(
            Tee::Csv as i32,
            Mode::Passport as i32,
            Some(b"expected-nonce"),
            60,
            b"test-key",
        )?;

        let err = decode_attestation_challenge(Tee::Tdx, Some(Mode::Passport as i32), &token)
            .expect_err("tee mismatch should fail");
        assert!(err.to_string().contains("tee mismatch"));
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_extracts_cca_token_fixture() -> Result<()> {
        let token = include_bytes!("../../test_data/cca/cca-token.cbor");
        let body = serde_json::to_vec(&serde_json::json!({ "token": token.as_slice() }))?;
        let (url, request) = spawn_evidence_server(body).await?;
        let attester = GuestComponentsRestAttester::new(url);
        let evidence = attester
            .get_evidence(Tee::Cca, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].init_data, b"expected-nonce");
        assert_eq!(evidence[0].runtime_data, token);
        assert!(
            request
                .await??
                .contains("GET /aa/evidence?runtime_data=expected-nonce ")
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_grpc_attester_rejects_oversized_runtime_data() {
        let attester = GuestComponentsGrpcAttester::new("http://127.0.0.1:50000");
        let err = attester
            .get_evidence(Tee::Tdx, &test_challenge(&[0u8; 65]))
            .await
            .expect_err("oversized runtime_data should fail before RPC");

        assert!(err.to_string().contains("at most 64 bytes"));
    }

    #[tokio::test]
    async fn guest_components_grpc_attester_extracts_cca_token_from_mock_aa() -> Result<()> {
        let token = include_bytes!("../../test_data/cca/cca-token.cbor");
        let body = serde_json::to_vec(&serde_json::json!({ "token": token.as_slice() }))?;
        let (endpoint, runtime_data_requests) =
            spawn_mock_aa_server(b"expected-nonce".to_vec(), body).await?;
        let attester = GuestComponentsGrpcAttester::new(endpoint);
        let evidence = attester
            .get_evidence(Tee::Cca, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].init_data, b"expected-nonce");
        assert_eq!(evidence[0].runtime_data, token);
        assert_eq!(
            *runtime_data_requests.lock().unwrap(),
            vec![b"expected-nonce".to_vec()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_grpc_attester_extracts_tdx_quote_from_mock_aa() -> Result<()> {
        let quote = include_bytes!("../../test_data/tdx/tdx_quote_4.dat");
        let body = serde_json::to_vec(&serde_json::json!({
            "quote": STANDARD.encode(quote),
        }))?;
        let (endpoint, runtime_data_requests) =
            spawn_mock_aa_server(b"expected-nonce".to_vec(), body).await?;
        let attester = GuestComponentsGrpcAttester::new(endpoint);
        let evidence = attester
            .get_evidence(Tee::Tdx, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].runtime_data, quote);
        assert_eq!(
            *runtime_data_requests.lock().unwrap(),
            vec![b"expected-nonce".to_vec()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_grpc_attester_passes_csv_evidence_through_from_mock_aa() -> Result<()>
    {
        let csv_evidence = include_bytes!("../../test_data/csv/csv_evidence.json").to_vec();
        let (endpoint, runtime_data_requests) =
            spawn_mock_aa_server(b"expected-nonce".to_vec(), csv_evidence.clone()).await?;
        let attester = GuestComponentsGrpcAttester::new(endpoint);
        let evidence = attester
            .get_evidence(Tee::Csv, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].runtime_data, csv_evidence);
        assert_eq!(
            *runtime_data_requests.lock().unwrap(),
            vec![b"expected-nonce".to_vec()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_grpc_attester_reports_rpc_error() -> Result<()> {
        let (endpoint, runtime_data_requests) =
            spawn_failing_mock_aa_server(b"expected-nonce".to_vec(), "aa unavailable").await?;
        let attester = GuestComponentsGrpcAttester::new(endpoint);
        let err = attester
            .get_evidence(Tee::Tdx, &test_challenge(b"expected-nonce"))
            .await
            .expect_err("gRPC status errors should be reported");

        assert!(
            err.to_string()
                .contains("failed to request guest-components gRPC evidence")
        );
        assert!(format!("{err:#}").contains("aa unavailable"));
        assert_eq!(
            *runtime_data_requests.lock().unwrap(),
            vec![b"expected-nonce".to_vec()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_extracts_cca_base64_token() -> Result<()> {
        let token = include_bytes!("../../test_data/cca/cca-token.cbor");
        let body = serde_json::to_vec(&serde_json::json!({
            "token": STANDARD.encode(token),
        }))?;
        let (url, _request) = spawn_evidence_server(body).await?;
        let attester = GuestComponentsRestAttester::new(url);
        let evidence = attester
            .get_evidence(Tee::Cca, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].runtime_data, token);
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_extracts_tdx_quote_fixture() -> Result<()> {
        let quote = include_bytes!("../../test_data/tdx/tdx_quote_4.dat");
        let body = serde_json::to_vec(&serde_json::json!({
            "quote": STANDARD.encode(quote),
        }))?;
        let (url, _request) = spawn_evidence_server(body).await?;
        let attester = GuestComponentsRestAttester::new(url);
        let evidence = attester
            .get_evidence(Tee::Tdx, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].runtime_data, quote);
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_passes_csv_evidence_through() -> Result<()> {
        let csv_evidence = include_bytes!("../../test_data/csv/csv_evidence.json");
        let (url, _request) = spawn_evidence_server(csv_evidence.to_vec()).await?;
        let attester = GuestComponentsRestAttester::new(url);
        let evidence = attester
            .get_evidence(Tee::Csv, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].runtime_data, csv_evidence);
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_accepts_api_root_url() -> Result<()> {
        let (url, request) = spawn_evidence_server(br#"{"quote":"AQIDBA=="}"#.to_vec()).await?;
        let root_url = url.trim_end_matches("/aa/evidence").to_string();
        let attester = GuestComponentsRestAttester::new(root_url);
        let evidence = attester
            .get_evidence(Tee::Tdx, &test_challenge(b"expected-nonce"))
            .await?;

        assert_eq!(evidence[0].runtime_data, vec![1, 2, 3, 4]);
        assert!(
            request
                .await??
                .contains("GET /aa/evidence?runtime_data=expected-nonce ")
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_reports_http_error() -> Result<()> {
        let (url, _request) =
            spawn_evidence_server_with_status(503, b"aa unavailable".to_vec()).await?;
        let attester = GuestComponentsRestAttester::new(url);

        let err = attester
            .get_evidence(Tee::Tdx, &test_challenge(b"expected-nonce"))
            .await
            .expect_err("non-success status should fail");

        assert!(err.to_string().contains("503"));
        assert!(err.to_string().contains("aa unavailable"));
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_rejects_invalid_tdx_quote() -> Result<()> {
        let (url, _request) =
            spawn_evidence_server(br#"{"quote":"not-base64!!!"}"#.to_vec()).await?;
        let attester = GuestComponentsRestAttester::new(url);

        let err = attester
            .get_evidence(Tee::Tdx, &test_challenge(b"expected-nonce"))
            .await
            .expect_err("invalid quote encoding should fail");

        assert!(
            err.to_string()
                .contains("failed to decode guest-components TDX quote")
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_rejects_invalid_cca_shape() -> Result<()> {
        let (url, _request) = spawn_evidence_server(br#"{"token":{"bad":true}}"#.to_vec()).await?;
        let attester = GuestComponentsRestAttester::new(url);

        let err = attester
            .get_evidence(Tee::Cca, &test_challenge(b"expected-nonce"))
            .await
            .expect_err("invalid token shape should fail");

        assert!(
            err.to_string()
                .contains("failed to parse guest-components CCA evidence")
        );
        Ok(())
    }

    #[tokio::test]
    async fn guest_components_rest_attester_rejects_non_utf8_nonce() -> Result<()> {
        let attester = GuestComponentsRestAttester::new("http://127.0.0.1:1/aa/evidence");

        let err = attester
            .get_evidence(Tee::Tdx, &test_challenge(&[0xff; 8]))
            .await
            .expect_err("non-UTF-8 nonce should fail before HTTP request");

        assert!(err.to_string().contains("requires a UTF-8 challenge nonce"));
        Ok(())
    }

    #[test]
    fn guest_components_evidence_normalizer_rejects_unsupported_tee() {
        let err = normalize_guest_components_evidence(Tee::Kunpeng, b"{}")
            .expect_err("Kunpeng is not supported by guest-components adapter");

        assert!(
            err.to_string()
                .contains("guest-components evidence does not support Kunpeng")
        );
    }

    #[test]
    fn guest_components_evidence_normalizer_rejects_unspecified_tee() {
        let err = normalize_guest_components_evidence(Tee::Unspecified, b"{}")
            .expect_err("unspecified TEE should fail");

        assert!(err.to_string().contains("unsupported tee"));
    }

    #[derive(Clone)]
    struct MockAaService {
        expected_runtime_data: Vec<u8>,
        evidence: Vec<u8>,
        error_message: Option<&'static str>,
        runtime_data_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[tonic::async_trait]
    impl AttestationAgentService for MockAaService {
        async fn get_evidence(
            &self,
            request: Request<GetEvidenceRequest>,
        ) -> std::result::Result<Response<GetEvidenceResponse>, Status> {
            let runtime_data = request.into_inner().runtime_data;
            self.runtime_data_requests
                .lock()
                .unwrap()
                .push(runtime_data.clone());

            if let Some(message) = self.error_message {
                return Err(Status::unavailable(message));
            }
            if runtime_data != self.expected_runtime_data {
                return Err(Status::invalid_argument("unexpected runtime_data"));
            }

            Ok(Response::new(GetEvidenceResponse {
                evidence: self.evidence.clone(),
            }))
        }

        async fn get_additional_evidence(
            &self,
            _request: Request<GetAdditionalEvidenceRequest>,
        ) -> std::result::Result<Response<GetEvidenceResponse>, Status> {
            Err(Status::unimplemented("not needed by attester tests"))
        }

        async fn get_token(
            &self,
            _request: Request<GetTokenRequest>,
        ) -> std::result::Result<Response<GetTokenResponse>, Status> {
            Err(Status::unimplemented("not needed by attester tests"))
        }

        async fn extend_runtime_measurement(
            &self,
            _request: Request<ExtendRuntimeMeasurementRequest>,
        ) -> std::result::Result<Response<ExtendRuntimeMeasurementResponse>, Status> {
            Err(Status::unimplemented("not needed by attester tests"))
        }

        async fn bind_init_data(
            &self,
            _request: Request<BindInitDataRequest>,
        ) -> std::result::Result<Response<BindInitDataResponse>, Status> {
            Err(Status::unimplemented("not needed by attester tests"))
        }

        async fn get_tee_type(
            &self,
            _request: Request<GetTeeTypeRequest>,
        ) -> std::result::Result<Response<GetTeeTypeResponse>, Status> {
            Err(Status::unimplemented("not needed by attester tests"))
        }

        async fn get_additional_tees(
            &self,
            _request: Request<GetAdditionalTeesRequest>,
        ) -> std::result::Result<Response<GetAdditionalTeesResponse>, Status> {
            Err(Status::unimplemented("not needed by attester tests"))
        }
    }

    async fn spawn_mock_aa_server(
        expected_runtime_data: Vec<u8>,
        evidence: Vec<u8>,
    ) -> Result<(String, Arc<Mutex<Vec<Vec<u8>>>>)> {
        spawn_mock_aa_server_with_result(expected_runtime_data, evidence, None).await
    }

    async fn spawn_failing_mock_aa_server(
        expected_runtime_data: Vec<u8>,
        message: &'static str,
    ) -> Result<(String, Arc<Mutex<Vec<Vec<u8>>>>)> {
        spawn_mock_aa_server_with_result(expected_runtime_data, Vec::new(), Some(message)).await
    }

    async fn spawn_mock_aa_server_with_result(
        expected_runtime_data: Vec<u8>,
        evidence: Vec<u8>,
        error_message: Option<&'static str>,
    ) -> Result<(String, Arc<Mutex<Vec<Vec<u8>>>>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let runtime_data_requests = Arc::new(Mutex::new(Vec::new()));
        let service = MockAaService {
            expected_runtime_data,
            evidence,
            error_message,
            runtime_data_requests: runtime_data_requests.clone(),
        };

        tokio::spawn(async move {
            if let Err(err) = Server::builder()
                .add_service(AttestationAgentServiceServer::new(service))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
            {
                panic!("mock AA gRPC server failed: {err}");
            }
        });

        Ok((format!("http://{addr}"), runtime_data_requests))
    }

    fn test_challenge(nonce: &[u8]) -> AttestationChallenge {
        AttestationChallenge {
            tee: Tee::Cca,
            mode: Mode::Passport,
            nonce: nonce.to_vec(),
            challenge_token: b"token".to_vec(),
        }
    }

    async fn spawn_evidence_server(
        body: Vec<u8>,
    ) -> Result<(String, tokio::task::JoinHandle<Result<String>>)> {
        spawn_evidence_server_with_status(200, body).await
    }

    async fn spawn_evidence_server_with_status(
        status: u16,
        body: Vec<u8>,
    ) -> Result<(String, tokio::task::JoinHandle<Result<String>>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await?;
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let header = format!(
                "HTTP/1.1 {status} {}\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n",
                reason_phrase(status),
                body.len()
            );
            socket.write_all(header.as_bytes()).await?;
            socket.write_all(&body).await?;
            Ok(request)
        });

        Ok((format!("http://{addr}/aa/evidence"), handle))
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            503 => "Service Unavailable",
            _ => "Status",
        }
    }
}
