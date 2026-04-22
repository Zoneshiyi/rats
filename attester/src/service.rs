use anyhow::Result;
use async_trait::async_trait;
use protos::{Mode, Tee};
use std::sync::Arc;

use crate::core::{AttestationChallenge, Attester, AttesterEvidence, decode_attestation_challenge};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub nonce: Vec<u8>,
    pub challenge_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationOutcome {
    AttestationToken(Vec<u8>),
    EvidenceList(Vec<AttesterEvidence>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub attestation_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceErrorKind {
    InvalidArgument,
    UnsupportedMode,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    kind: ServiceErrorKind,
    message: String,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::InvalidArgument,
            message: message.into(),
        }
    }

    pub fn unsupported_mode(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::UnsupportedMode,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::Internal,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> &ServiceErrorKind {
        &self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[async_trait]
pub trait VerifierGateway: Send + Sync {
    async fn issue_challenge(
        &self,
        tee: Tee,
        mode: Mode,
        requested_nonce: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    async fn verify(&self, tee: Tee, raw_evidence: &[u8], challenge_token: &[u8])
    -> Result<String>;
}

pub struct AttesterApplicationService {
    tee: Tee,
    attester: Arc<dyn Attester>,
    verifier_gateway: Arc<dyn VerifierGateway>,
}

impl AttesterApplicationService {
    pub fn new(
        tee: Tee,
        attester: Arc<dyn Attester>,
        verifier_gateway: Arc<dyn VerifierGateway>,
    ) -> Self {
        Self {
            tee,
            attester,
            verifier_gateway,
        }
    }

    pub async fn issue_challenge(
        &self,
        mode: Mode,
        requested_nonce: Vec<u8>,
    ) -> std::result::Result<IssuedChallenge, ServiceError> {
        if mode == Mode::Unspecified {
            return Err(ServiceError::invalid_argument("unsupported mode"));
        }

        let (nonce, challenge_token) = self
            .verifier_gateway
            .issue_challenge(self.tee, mode, &requested_nonce)
            .await
            .map_err(|err| ServiceError::internal(err.to_string()))?;

        Ok(IssuedChallenge {
            nonce,
            challenge_token,
        })
    }

    pub async fn attestation_evaluate(
        &self,
        mode: Mode,
        challenge_token: Vec<u8>,
    ) -> std::result::Result<AttestationOutcome, ServiceError> {
        let challenge = self.decode_challenge(Some(mode as i32), &challenge_token)?;
        let evidence = self
            .attester
            .get_evidence(self.tee, &challenge)
            .await
            .map_err(|err| ServiceError::internal(err.to_string()))?;

        match challenge.mode {
            Mode::Passport => {
                let raw = evidence
                    .first()
                    .ok_or_else(|| ServiceError::internal("missing evidence"))?;
                let token = self
                    .verifier_gateway
                    .verify(self.tee, &raw.runtime_data, &challenge.challenge_token)
                    .await
                    .map_err(|err| ServiceError::internal(err.to_string()))?;
                Ok(AttestationOutcome::AttestationToken(token.into_bytes()))
            }
            Mode::BackgroundCheck | Mode::Mix => Ok(AttestationOutcome::EvidenceList(evidence)),
            Mode::Unspecified => Err(ServiceError::unsupported_mode("unsupported mode")),
        }
    }

    pub async fn verification_evaluate(
        &self,
        evidence: Vec<AttesterEvidence>,
        challenge_token: Vec<u8>,
    ) -> std::result::Result<VerificationResult, ServiceError> {
        self.decode_challenge(None, &challenge_token)?;
        let evidence = evidence
            .first()
            .ok_or_else(|| ServiceError::invalid_argument("missing evidence"))?;

        let token = self
            .verifier_gateway
            .verify(self.tee, &evidence.runtime_data, &challenge_token)
            .await
            .map_err(|err| ServiceError::internal(err.to_string()))?;

        Ok(VerificationResult {
            attestation_token: token.into_bytes(),
        })
    }

    fn decode_challenge(
        &self,
        expected_mode: Option<i32>,
        challenge_token: &[u8],
    ) -> std::result::Result<AttestationChallenge, ServiceError> {
        decode_attestation_challenge(self.tee, expected_mode, challenge_token)
            .map_err(|err| ServiceError::invalid_argument(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use protos::challenge;
    use std::sync::Mutex;

    struct FakeAttester {
        result: Mutex<Option<Result<Vec<AttesterEvidence>>>>,
    }

    impl FakeAttester {
        fn new(result: Result<Vec<AttesterEvidence>>) -> Self {
            Self {
                result: Mutex::new(Some(result)),
            }
        }
    }

    #[async_trait]
    impl Attester for FakeAttester {
        async fn get_evidence(
            &self,
            _tee: Tee,
            _challenge: &AttestationChallenge,
        ) -> Result<Vec<AttesterEvidence>> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing attester result")))
        }
    }

    struct FakeVerifierGateway {
        issue_result: Mutex<Option<Result<(Vec<u8>, Vec<u8>)>>>,
        verify_result: Mutex<Option<Result<String>>>,
    }

    impl FakeVerifierGateway {
        fn new(issue_result: Result<(Vec<u8>, Vec<u8>)>, verify_result: Result<String>) -> Self {
            Self {
                issue_result: Mutex::new(Some(issue_result)),
                verify_result: Mutex::new(Some(verify_result)),
            }
        }
    }

    #[async_trait]
    impl VerifierGateway for FakeVerifierGateway {
        async fn issue_challenge(
            &self,
            _tee: Tee,
            _mode: Mode,
            _requested_nonce: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            self.issue_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing issue result")))
        }

        async fn verify(
            &self,
            _tee: Tee,
            _raw_evidence: &[u8],
            _challenge_token: &[u8],
        ) -> Result<String> {
            self.verify_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing verify result")))
        }
    }

    fn challenge_token(mode: Mode) -> Result<Vec<u8>> {
        let (_nonce, token) = challenge::issue(
            Tee::Csv as i32,
            mode as i32,
            Some(b"expected-nonce"),
            60,
            b"test-key",
        )?;
        Ok(token)
    }

    #[tokio::test]
    async fn issue_challenge_rejects_unspecified_mode() {
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(Vec::new()))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok(String::new()),
            )),
        );

        let result = service.issue_challenge(Mode::Unspecified, Vec::new()).await;
        assert_eq!(
            result.expect_err("mode should be rejected").kind(),
            &ServiceErrorKind::InvalidArgument
        );
    }

    #[tokio::test]
    async fn attestation_evaluate_returns_token_for_passport() -> Result<()> {
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(vec![AttesterEvidence {
                init_data: b"nonce".to_vec(),
                runtime_data: b"evidence".to_vec(),
            }]))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok("signed-token".to_string()),
            )),
        );

        let result = service
            .attestation_evaluate(Mode::Passport, challenge_token(Mode::Passport)?)
            .await?;

        assert_eq!(
            result,
            AttestationOutcome::AttestationToken(b"signed-token".to_vec())
        );
        Ok(())
    }

    #[tokio::test]
    async fn attestation_evaluate_returns_evidence_for_background_check() -> Result<()> {
        let evidence = AttesterEvidence {
            init_data: b"nonce".to_vec(),
            runtime_data: b"evidence".to_vec(),
        };
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(vec![evidence.clone()]))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok("unused".to_string()),
            )),
        );

        let result = service
            .attestation_evaluate(
                Mode::BackgroundCheck,
                challenge_token(Mode::BackgroundCheck)?,
            )
            .await?;

        assert_eq!(result, AttestationOutcome::EvidenceList(vec![evidence]));
        Ok(())
    }

    #[tokio::test]
    async fn verification_evaluate_rejects_missing_evidence() -> Result<()> {
        let service = AttesterApplicationService::new(
            Tee::Csv,
            Arc::new(FakeAttester::new(Ok(Vec::new()))),
            Arc::new(FakeVerifierGateway::new(
                Ok((Vec::new(), Vec::new())),
                Ok("unused".to_string()),
            )),
        );

        let result = service
            .verification_evaluate(Vec::new(), challenge_token(Mode::Passport)?)
            .await;

        assert_eq!(
            result.expect_err("missing evidence should fail").kind(),
            &ServiceErrorKind::InvalidArgument
        );
        Ok(())
    }
}
