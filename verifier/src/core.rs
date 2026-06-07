use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use cfg_if::cfg_if;
use ear::{Ear, Nonce, RawValue, RawValueKind, VerifierID};
use protos::Tee;
use protos::challenge::ChallengeTokenClaims;
use serde::Deserialize;
use serde_json::Value;

const EXT_CHALLENGE_BINDING: i32 = -70001;
const EXT_EVIDENCE_SOURCE: i32 = -70002;
const EXT_APPRAISAL_POLICY_ID: i32 = -70003;
const EXT_APPRAISAL_RESULT: i32 = -70004;
const DEFAULT_EVIDENCE_SOURCE: &str = "unspecified";

pub type TeeEvidenceParsedClaim = Value;
pub type TeeClass = String;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ChallengeBindingStatus {
    HardwareVerified,
    Simulated,
}

impl ChallengeBindingStatus {
    pub fn as_token_value(self) -> &'static str {
        match self {
            Self::HardwareVerified => "hardware_verified",
            Self::Simulated => "simulated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsvAppraisalPolicy {
    policy_id: Option<String>,
    csv_allowed_measurements: Vec<String>,
    /// ADR 0002: 默认拒绝 debug=on（即 CSV `nodbg` 位为 0）。
    forbid_debug: bool,
}

impl Default for CsvAppraisalPolicy {
    fn default() -> Self {
        Self {
            policy_id: None,
            csv_allowed_measurements: Vec::new(),
            forbid_debug: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppraisalOutcome {
    pub policy_id: String,
    pub result: String,
}

#[derive(Debug, Deserialize)]
struct AppraisalPolicyFile {
    policy_id: Option<String>,
    #[serde(default)]
    csv_allowed_measurements: Vec<String>,
    #[serde(default = "default_forbid_debug")]
    forbid_debug: bool,
}

fn default_forbid_debug() -> bool {
    true
}

impl CsvAppraisalPolicy {
    pub fn disabled() -> Self {
        Self {
            policy_id: None,
            csv_allowed_measurements: Vec::new(),
            forbid_debug: false,
        }
    }

    pub fn from_runtime_config(config: &crate::config::VerifierConfig) -> Result<Self> {
        let Some(path) = &config.appraisal_policy_path else {
            // 未配置 policy 文件时仍启用 forbid_debug（生产基线安全姿态）。
            return Ok(Self::default());
        };
        let content = crate::config::read_text(path)
            .with_context(|| format!("read appraisal policy file `{path}`"))?;
        Self::from_toml(&content)
    }

    pub fn from_toml(content: &str) -> Result<Self> {
        let policy = toml::from_str::<AppraisalPolicyFile>(content)
            .context("parse appraisal policy file")?;
        Ok(Self {
            policy_id: policy.policy_id,
            csv_allowed_measurements: policy.csv_allowed_measurements,
            forbid_debug: policy.forbid_debug,
        })
    }

    /// 校验 CSV `measure` 与 `nodbg` 位，返回 appraisal 结果。
    ///
    /// `nodbg = 1` 表示 debug 关闭；`forbid_debug = true` 时若 `nodbg = 0` 则拒签。
    /// 同时若配置了 `csv_allowed_measurements`，则 `measure` 必须命中白名单。
    /// 当两类校验都未配置（白名单空 + forbid_debug=false）时返回 `None`，跳过 appraisal。
    pub fn evaluate_csv(
        &self,
        measure: Option<&str>,
        nodbg: bool,
    ) -> Result<Option<AppraisalOutcome>> {
        if self.forbid_debug && !nodbg {
            bail!("appraisal policy rejected CSV evidence: debug mode is enabled (nodbg=0)");
        }

        if self.csv_allowed_measurements.is_empty() {
            return if self.forbid_debug {
                Ok(Some(AppraisalOutcome {
                    policy_id: self.policy_id(),
                    result: "passed".to_string(),
                }))
            } else {
                Ok(None)
            };
        }

        let measure = measure.context("appraisal policy requires CSV measurement")?;
        if self
            .csv_allowed_measurements
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(measure))
        {
            return Ok(Some(AppraisalOutcome {
                policy_id: self.policy_id(),
                result: "passed".to_string(),
            }));
        }

        bail!("appraisal policy rejected CSV measurement `{measure}`")
    }

    fn policy_id(&self) -> String {
        self.policy_id
            .clone()
            .unwrap_or_else(|| "default-local-policy".to_string())
    }
}

#[derive(Clone, Debug)]
pub struct VerificationContext {
    pub challenge: ChallengeTokenClaims,
    evidence_source: String,
    csv_appraisal_policy: CsvAppraisalPolicy,
}

impl VerificationContext {
    pub fn new(challenge: ChallengeTokenClaims, evidence_source: impl Into<String>) -> Self {
        let evidence_source = evidence_source.into();
        let evidence_source = match evidence_source.trim() {
            "" => DEFAULT_EVIDENCE_SOURCE.to_string(),
            source => source.to_string(),
        };
        Self {
            challenge,
            evidence_source,
            csv_appraisal_policy: CsvAppraisalPolicy::disabled(),
        }
    }

    pub fn evidence_source(&self) -> &str {
        &self.evidence_source
    }

    pub fn challenge_id(&self) -> String {
        self.challenge.challenge_id()
    }

    pub fn with_csv_appraisal_policy(mut self, policy: CsvAppraisalPolicy) -> Self {
        self.csv_appraisal_policy = policy;
        self
    }

    pub fn csv_appraisal_policy(&self) -> &CsvAppraisalPolicy {
        &self.csv_appraisal_policy
    }
}

#[async_trait]
pub trait Verifier {
    async fn verify(&self, raw_evidence: &[u8], context: &VerificationContext) -> Result<String>;
}

pub trait VerifierFactory: Send + Sync {
    fn resolve(&self, tee: Tee) -> Result<Box<dyn Verifier + Send + Sync>>;
}

#[derive(Default)]
pub struct DefaultVerifierFactory;

impl VerifierFactory for DefaultVerifierFactory {
    fn resolve(&self, tee: Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
        match tee {
            Tee::Cca => {
                cfg_if! {
                    if #[cfg(feature = "cca-verifier")] {
                        Ok(Box::<crate::tee::cca::CCA>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `cca-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            Tee::Tdx => {
                cfg_if! {
                    if #[cfg(feature = "tdx-verifier")] {
                        Ok(Box::<crate::tee::tdx::TDX>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `tdx-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            Tee::Csv => {
                cfg_if! {
                    if #[cfg(feature = "csv-verifier")] {
                        Ok(Box::<crate::tee::csv::Csv>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `csv-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            Tee::Kunpeng => {
                cfg_if! {
                    if #[cfg(feature = "kunpeng-verifier")] {
                        Ok(Box::<crate::tee::kunpeng::Kunpeng>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `kunpeng-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            _ => bail!("unsupported TEE type"),
        }
    }
}

pub fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    DefaultVerifierFactory.resolve(*tee)
}

pub fn init_ear(profile_name: &str) -> Result<Ear> {
    let config = crate::config::get();
    let mut token = Ear::new_with_profile(profile_name)?;
    token.iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs() as i64;

    token.vid = VerifierID {
        build: config.verifier_build.clone(),
        developer: config.verifier_developer.clone(),
    };
    Ok(token)
}

pub fn verify_challenge_binding(
    extracted_report_data: &[u8],
    challenge: &ChallengeTokenClaims,
) -> Result<ChallengeBindingStatus> {
    let expected = challenge.nonce_bytes()?;
    if extracted_report_data == expected.as_slice()
        || is_zero_padded_report_data(extracted_report_data, &expected)
    {
        return Ok(ChallengeBindingStatus::HardwareVerified);
    }

    bail!(
        "challenge/report data mismatch: expected {} bytes, got {} bytes",
        expected.len(),
        extracted_report_data.len()
    );
}

fn is_zero_padded_report_data(extracted_report_data: &[u8], expected: &[u8]) -> bool {
    expected.len() < extracted_report_data.len()
        && extracted_report_data.starts_with(expected)
        && extracted_report_data[expected.len()..]
            .iter()
            .all(|byte| *byte == 0)
}

pub fn apply_challenge(
    token: &mut Ear,
    challenge: &ChallengeTokenClaims,
    challenge_binding: &str,
    evidence_source: &str,
) -> Result<()> {
    token.nonce = Some(Nonce::try_from(challenge.nonce.as_str())?);
    token.extensions.register(
        "rats.challenge_binding",
        EXT_CHALLENGE_BINDING,
        RawValueKind::String,
    )?;
    token.extensions.register(
        "rats.evidence_source",
        EXT_EVIDENCE_SOURCE,
        RawValueKind::String,
    )?;
    token.extensions.set_by_name(
        "rats.challenge_binding",
        RawValue::String(challenge_binding.to_string()),
    )?;
    token.extensions.set_by_name(
        "rats.evidence_source",
        RawValue::String(evidence_source.to_string()),
    )?;
    Ok(())
}

pub fn apply_appraisal(token: &mut Ear, outcome: Option<AppraisalOutcome>) -> Result<()> {
    let Some(outcome) = outcome else {
        return Ok(());
    };
    token.extensions.register(
        "rats.appraisal_policy_id",
        EXT_APPRAISAL_POLICY_ID,
        RawValueKind::String,
    )?;
    token.extensions.register(
        "rats.appraisal_result",
        EXT_APPRAISAL_RESULT,
        RawValueKind::String,
    )?;
    token.extensions.set_by_name(
        "rats.appraisal_policy_id",
        RawValue::String(outcome.policy_id),
    )?;
    token
        .extensions
        .set_by_name("rats.appraisal_result", RawValue::String(outcome.result))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protos::{Mode, Tee, challenge};

    fn challenge_from_nonce(nonce: &[u8]) -> Result<ChallengeTokenClaims> {
        let (_nonce, token) = challenge::issue(
            Tee::Tdx as i32,
            Mode::Passport as i32,
            Some(nonce),
            60,
            b"test-key",
        )?;
        challenge::decode(&token)
    }

    #[test]
    fn challenge_binding_accepts_exact_nonce() -> Result<()> {
        let challenge = challenge_from_nonce(b"expected-nonce")?;

        let status = verify_challenge_binding(b"expected-nonce", &challenge)?;

        assert_eq!(status, ChallengeBindingStatus::HardwareVerified);
        Ok(())
    }

    #[test]
    fn challenge_binding_accepts_zero_padded_nonce() -> Result<()> {
        let challenge = challenge_from_nonce(b"expected-nonce")?;
        let mut report_data = b"expected-nonce".to_vec();
        report_data.resize(64, 0);

        let status = verify_challenge_binding(&report_data, &challenge)?;

        assert_eq!(status, ChallengeBindingStatus::HardwareVerified);
        Ok(())
    }

    #[test]
    fn challenge_binding_rejects_nonzero_suffix() -> Result<()> {
        let challenge = challenge_from_nonce(b"expected-nonce")?;
        let mut report_data = b"expected-nonce".to_vec();
        report_data.resize(64, 0);
        report_data[63] = 1;

        let result = verify_challenge_binding(&report_data, &challenge);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn appraisal_policy_accepts_allowed_csv_measurement() -> Result<()> {
        let policy = CsvAppraisalPolicy::from_toml(
            r#"
policy_id = "csv-demo-policy"
csv_allowed_measurements = ["abc123"]
"#,
        )?;

        let outcome = policy
            .evaluate_csv(Some("ABC123"), true)?
            .expect("policy should be evaluated");

        assert_eq!(outcome.policy_id, "csv-demo-policy");
        assert_eq!(outcome.result, "passed");
        Ok(())
    }

    #[test]
    fn appraisal_policy_rejects_unexpected_csv_measurement() -> Result<()> {
        let policy = CsvAppraisalPolicy::from_toml(
            r#"
policy_id = "csv-demo-policy"
csv_allowed_measurements = ["expected"]
"#,
        )?;

        let err = policy
            .evaluate_csv(Some("unexpected"), true)
            .expect_err("unexpected measurement should fail");

        assert!(err.to_string().contains("rejected CSV measurement"));
        Ok(())
    }

    #[test]
    fn appraisal_policy_rejects_debug_on() -> Result<()> {
        let policy = CsvAppraisalPolicy::default();

        let err = policy
            .evaluate_csv(None, false)
            .expect_err("debug=on (nodbg=0) should be rejected by default");

        assert!(err.to_string().contains("debug mode is enabled"));
        Ok(())
    }

    #[test]
    fn appraisal_policy_disabled_skips_evaluation() -> Result<()> {
        let policy = CsvAppraisalPolicy::disabled();

        // disabled policy 不强制 forbid_debug 也不强制白名单，返回 None。
        let outcome = policy.evaluate_csv(None, false)?;

        assert!(outcome.is_none());
        Ok(())
    }
}
