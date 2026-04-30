use anyhow::Result;
use protos::Tee;
use protos::challenge::{self, ChallengeTokenClaims};
use std::sync::Arc;

use crate::config::VerifierConfig;
use crate::core::{AppraisalPolicy, DefaultVerifierFactory, VerificationContext, VerifierFactory};

#[derive(Debug, Clone)]
pub struct IssueChallengeInput {
    pub tee: Tee,
    pub mode: i32,
    pub requested_nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    pub nonce: Vec<u8>,
    pub challenge_token: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VerifyEvidenceInput {
    pub tee: Tee,
    pub evidence: Vec<u8>,
    pub challenge_token: Vec<u8>,
    pub evidence_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    pub attestation_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventKind {
    ChallengeIssued,
    VerificationAccepted,
    VerificationRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub kind: AuditEventKind,
    pub tee: Tee,
    pub mode: i32,
    pub challenge_id: String,
    pub evidence_source: String,
    pub reason: Option<String>,
}

impl AuditEvent {
    pub fn challenge_issued(tee: Tee, claims: &ChallengeTokenClaims) -> Self {
        Self {
            kind: AuditEventKind::ChallengeIssued,
            tee,
            mode: claims.mode,
            challenge_id: claims.challenge_id(),
            evidence_source: "not_applicable".to_string(),
            reason: None,
        }
    }

    pub fn verification_accepted(tee: Tee, context: &VerificationContext) -> Self {
        Self {
            kind: AuditEventKind::VerificationAccepted,
            tee,
            mode: context.challenge.mode,
            challenge_id: context.challenge_id(),
            evidence_source: context.evidence_source().to_string(),
            reason: None,
        }
    }

    pub fn verification_rejected(
        tee: Tee,
        context: &VerificationContext,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            kind: AuditEventKind::VerificationRejected,
            tee,
            mode: context.challenge.mode,
            challenge_id: context.challenge_id(),
            evidence_source: context.evidence_source().to_string(),
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceErrorKind {
    InvalidArgument,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    kind: ServiceErrorKind,
    message: String,
}

impl ServiceError {
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self {
            kind: ServiceErrorKind::InvalidArgument,
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

pub trait ChallengeTokenManager: Send + Sync {
    fn issue(
        &self,
        tee: i32,
        mode: i32,
        requested_nonce: Option<&[u8]>,
        ttl_secs: u64,
        signing_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)>;

    fn verify(
        &self,
        challenge_token: &[u8],
        expected_tee: Option<i32>,
        expected_mode: Option<i32>,
        signing_key: &[u8],
    ) -> Result<ChallengeTokenClaims>;
}

#[derive(Default)]
pub struct DefaultChallengeTokenManager;

impl ChallengeTokenManager for DefaultChallengeTokenManager {
    fn issue(
        &self,
        tee: i32,
        mode: i32,
        requested_nonce: Option<&[u8]>,
        ttl_secs: u64,
        signing_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        challenge::issue(tee, mode, requested_nonce, ttl_secs, signing_key)
    }

    fn verify(
        &self,
        challenge_token: &[u8],
        expected_tee: Option<i32>,
        expected_mode: Option<i32>,
        signing_key: &[u8],
    ) -> Result<ChallengeTokenClaims> {
        challenge::verify(challenge_token, expected_tee, expected_mode, signing_key)
    }
}

#[derive(Clone)]
pub struct ServiceConfig {
    pub challenge_ttl_secs: u64,
    pub allow_test_nonce: bool,
    pub challenge_signing_key: Vec<u8>,
    pub appraisal_policy: AppraisalPolicy,
}

impl ServiceConfig {
    pub fn from_runtime_config(config: &VerifierConfig) -> Result<Self> {
        Ok(Self {
            challenge_ttl_secs: config.challenge_ttl_secs,
            allow_test_nonce: config.allow_test_nonce,
            challenge_signing_key: crate::config::read_binary(&config.challenge_signing_key_path)?,
            appraisal_policy: AppraisalPolicy::from_runtime_config(config)?,
        })
    }
}

pub struct VerifierApplicationService {
    config: ServiceConfig,
    verifier_factory: Arc<dyn VerifierFactory>,
    challenge_tokens: Arc<dyn ChallengeTokenManager>,
}

impl VerifierApplicationService {
    pub fn new(
        config: ServiceConfig,
        verifier_factory: Arc<dyn VerifierFactory>,
        challenge_tokens: Arc<dyn ChallengeTokenManager>,
    ) -> Self {
        Self {
            config,
            verifier_factory,
            challenge_tokens,
        }
    }

    pub fn with_defaults(config: ServiceConfig) -> Self {
        Self::new(
            config,
            Arc::new(DefaultVerifierFactory),
            Arc::new(DefaultChallengeTokenManager),
        )
    }

    pub async fn issue_challenge(
        &self,
        input: IssueChallengeInput,
    ) -> std::result::Result<IssuedChallenge, ServiceError> {
        if input.tee == Tee::Unspecified {
            return Err(ServiceError::invalid_argument("unsupported tee"));
        }
        if input.mode == 0 {
            return Err(ServiceError::invalid_argument("unsupported mode"));
        }
        if !input.requested_nonce.is_empty() && !self.config.allow_test_nonce {
            return Err(ServiceError::invalid_argument("custom nonce is disabled"));
        }

        let requested_nonce =
            (!input.requested_nonce.is_empty()).then_some(input.requested_nonce.as_slice());
        let (nonce, challenge_token) = self
            .challenge_tokens
            .issue(
                input.tee as i32,
                input.mode,
                requested_nonce,
                self.config.challenge_ttl_secs,
                &self.config.challenge_signing_key,
            )
            .map_err(|err| ServiceError::internal(err.to_string()))?;

        Ok(IssuedChallenge {
            nonce,
            challenge_token,
        })
    }

    pub async fn verify(
        &self,
        input: VerifyEvidenceInput,
    ) -> std::result::Result<VerifiedToken, ServiceError> {
        if input.tee == Tee::Unspecified {
            return Err(ServiceError::invalid_argument("unsupported tee"));
        }

        let challenge = self
            .challenge_tokens
            .verify(
                &input.challenge_token,
                Some(input.tee as i32),
                None,
                &self.config.challenge_signing_key,
            )
            .map_err(|err| ServiceError::invalid_argument(err.to_string()))?;

        let verifier = self
            .verifier_factory
            .resolve(input.tee)
            .map_err(|err| ServiceError::internal(err.to_string()))?;
        let context = VerificationContext::new(challenge, input.evidence_source)
            .with_appraisal_policy(self.config.appraisal_policy.clone());
        let token = match verifier.verify(&input.evidence, &context).await {
            Ok(token) => {
                let _event = AuditEvent::verification_accepted(input.tee, &context);
                token
            }
            Err(err) => {
                let _event =
                    AuditEvent::verification_rejected(input.tee, &context, err.to_string());
                return Err(ServiceError::internal(err.to_string()));
            }
        };

        Ok(VerifiedToken {
            attestation_token: token.into_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use async_trait::async_trait;
    use protos::challenge::ChallengeTokenClaims;
    use std::sync::Mutex;

    struct FakeChallengeTokens {
        issue_result: Mutex<Option<Result<IssueResult>>>,
        verify_result: Mutex<Option<Result<ChallengeTokenClaims>>>,
    }

    type IssueResult = (Vec<u8>, Vec<u8>);

    impl FakeChallengeTokens {
        fn new(
            issue_result: Result<IssueResult>,
            verify_result: Result<ChallengeTokenClaims>,
        ) -> Self {
            Self {
                issue_result: Mutex::new(Some(issue_result)),
                verify_result: Mutex::new(Some(verify_result)),
            }
        }
    }

    impl ChallengeTokenManager for FakeChallengeTokens {
        fn issue(
            &self,
            _tee: i32,
            _mode: i32,
            _requested_nonce: Option<&[u8]>,
            _ttl_secs: u64,
            _signing_key: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            self.issue_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing issue result")))
        }

        fn verify(
            &self,
            _challenge_token: &[u8],
            _expected_tee: Option<i32>,
            _expected_mode: Option<i32>,
            _signing_key: &[u8],
        ) -> Result<ChallengeTokenClaims> {
            self.verify_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing verify result")))
        }
    }

    #[derive(Default)]
    struct FakeVerifierFactory {
        result: std::sync::Mutex<Option<Result<Box<dyn crate::core::Verifier + Send + Sync>>>>,
    }

    impl FakeVerifierFactory {
        fn with_result(result: Result<Box<dyn crate::core::Verifier + Send + Sync>>) -> Self {
            Self {
                result: std::sync::Mutex::new(Some(result)),
            }
        }
    }

    impl VerifierFactory for FakeVerifierFactory {
        fn resolve(&self, _tee: Tee) -> Result<Box<dyn crate::core::Verifier + Send + Sync>> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing verifier result")))
        }
    }

    struct FakeVerifier {
        result: Mutex<Option<Result<String>>>,
        seen_evidence_source: Option<Arc<Mutex<Option<String>>>>,
    }

    impl FakeVerifier {
        fn new(result: Result<String>) -> Self {
            Self {
                result: Mutex::new(Some(result)),
                seen_evidence_source: None,
            }
        }

        fn recording(
            result: Result<String>,
            seen_evidence_source: Arc<Mutex<Option<String>>>,
        ) -> Self {
            Self {
                result: Mutex::new(Some(result)),
                seen_evidence_source: Some(seen_evidence_source),
            }
        }
    }

    #[async_trait]
    impl crate::core::Verifier for FakeVerifier {
        async fn verify(
            &self,
            _raw_evidence: &[u8],
            context: &VerificationContext,
        ) -> Result<String> {
            if let Some(seen_evidence_source) = &self.seen_evidence_source {
                *seen_evidence_source.lock().unwrap() = Some(context.evidence_source().to_string());
            }
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(anyhow!("missing verifier result")))
        }
    }

    fn test_config() -> ServiceConfig {
        ServiceConfig {
            challenge_ttl_secs: 60,
            allow_test_nonce: true,
            challenge_signing_key: b"test-key".to_vec(),
            appraisal_policy: AppraisalPolicy::disabled(),
        }
    }

    fn test_challenge() -> ChallengeTokenClaims {
        ChallengeTokenClaims {
            tee: Tee::Csv as i32,
            mode: 1,
            nonce: "bm9uY2U".to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
        }
    }

    #[test]
    fn audit_event_uses_challenge_id_and_evidence_source() {
        let context = VerificationContext::new(test_challenge(), "guest-components-grpc");

        let event = AuditEvent::verification_accepted(Tee::Csv, &context);

        assert_eq!(event.kind, AuditEventKind::VerificationAccepted);
        assert_eq!(event.tee, Tee::Csv);
        assert_eq!(event.mode, 1);
        assert_eq!(event.evidence_source, "guest-components-grpc");
        assert_eq!(event.challenge_id, context.challenge_id());
        assert_eq!(event.reason, None);
    }

    #[test]
    fn audit_rejection_event_records_reason() {
        let context = VerificationContext::new(test_challenge(), "file-backed");

        let event = AuditEvent::verification_rejected(Tee::Csv, &context, "policy failed");

        assert_eq!(event.kind, AuditEventKind::VerificationRejected);
        assert_eq!(event.reason.as_deref(), Some("policy failed"));
    }

    #[tokio::test]
    async fn issue_challenge_rejects_custom_nonce_when_disabled() {
        let service = VerifierApplicationService::new(
            ServiceConfig {
                allow_test_nonce: false,
                ..test_config()
            },
            Arc::new(FakeVerifierFactory::default()),
            Arc::new(FakeChallengeTokens::new(
                Ok((Vec::new(), Vec::new())),
                Ok(test_challenge()),
            )),
        );

        let result = service
            .issue_challenge(IssueChallengeInput {
                tee: Tee::Csv,
                mode: 1,
                requested_nonce: b"fixed".to_vec(),
            })
            .await;

        assert_eq!(
            result.expect_err("custom nonce should be rejected").kind(),
            &ServiceErrorKind::InvalidArgument
        );
    }

    #[tokio::test]
    async fn issue_challenge_returns_token_from_manager() {
        let service = VerifierApplicationService::new(
            test_config(),
            Arc::new(FakeVerifierFactory::default()),
            Arc::new(FakeChallengeTokens::new(
                Ok((b"nonce".to_vec(), b"token".to_vec())),
                Ok(test_challenge()),
            )),
        );

        let result = service
            .issue_challenge(IssueChallengeInput {
                tee: Tee::Csv,
                mode: 1,
                requested_nonce: Vec::new(),
            })
            .await
            .expect("challenge should be issued");

        assert_eq!(result.nonce, b"nonce");
        assert_eq!(result.challenge_token, b"token");
    }

    #[tokio::test]
    async fn verify_returns_attestation_token() {
        let service = VerifierApplicationService::new(
            test_config(),
            Arc::new(FakeVerifierFactory::with_result(Ok(Box::new(
                FakeVerifier::new(Ok("signed-token".to_string())),
            )))),
            Arc::new(FakeChallengeTokens::new(
                Ok((Vec::new(), Vec::new())),
                Ok(test_challenge()),
            )),
        );

        let result = service
            .verify(VerifyEvidenceInput {
                tee: Tee::Csv,
                evidence: b"evidence".to_vec(),
                challenge_token: b"challenge".to_vec(),
                evidence_source: "guest-components-rest".to_string(),
            })
            .await
            .expect("verification should succeed");

        assert_eq!(result.attestation_token, b"signed-token");
    }

    #[tokio::test]
    async fn verify_passes_evidence_source_to_verifier() {
        let seen_evidence_source = Arc::new(Mutex::new(None));
        let service = VerifierApplicationService::new(
            test_config(),
            Arc::new(FakeVerifierFactory::with_result(Ok(Box::new(
                FakeVerifier::recording(
                    Ok("signed-token".to_string()),
                    seen_evidence_source.clone(),
                ),
            )))),
            Arc::new(FakeChallengeTokens::new(
                Ok((Vec::new(), Vec::new())),
                Ok(test_challenge()),
            )),
        );

        let result = service
            .verify(VerifyEvidenceInput {
                tee: Tee::Csv,
                evidence: b"evidence".to_vec(),
                challenge_token: b"challenge".to_vec(),
                evidence_source: "guest-components-rest".to_string(),
            })
            .await
            .expect("verification should succeed");

        assert_eq!(result.attestation_token, b"signed-token");
        assert_eq!(
            seen_evidence_source.lock().unwrap().as_deref(),
            Some("guest-components-rest")
        );
    }

    #[tokio::test]
    async fn verify_maps_invalid_challenge_to_invalid_argument() {
        let service = VerifierApplicationService::new(
            test_config(),
            Arc::new(FakeVerifierFactory::default()),
            Arc::new(FakeChallengeTokens::new(
                Ok((Vec::new(), Vec::new())),
                Err(anyhow!("bad challenge")),
            )),
        );

        let result = service
            .verify(VerifyEvidenceInput {
                tee: Tee::Csv,
                evidence: b"evidence".to_vec(),
                challenge_token: b"challenge".to_vec(),
                evidence_source: "file-backed".to_string(),
            })
            .await;

        assert_eq!(
            result.expect_err("challenge should be rejected").kind(),
            &ServiceErrorKind::InvalidArgument
        );
    }
}
