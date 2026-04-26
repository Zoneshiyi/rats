use anyhow::{Result, bail};
use async_trait::async_trait;
use cfg_if::cfg_if;
use ear::{Ear, Nonce, RawValue, RawValueKind, VerifierID};
use protos::Tee;
use protos::challenge::ChallengeTokenClaims;
use serde_json::Value;

const EXT_CHALLENGE_BINDING: i32 = -70001;
const EXT_EVIDENCE_SOURCE: i32 = -70002;

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

#[async_trait]
pub trait Verifier {
    async fn verify(&self, raw_evidence: &[u8], challenge: &ChallengeTokenClaims)
    -> Result<String>;
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
                        Ok(Box::<crate::cca::CCA>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `cca-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            Tee::Tdx => {
                cfg_if! {
                    if #[cfg(feature = "tdx-verifier")] {
                        Ok(Box::<crate::tdx::TDX>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `tdx-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            Tee::Csv => {
                cfg_if! {
                    if #[cfg(feature = "csv-verifier")] {
                        Ok(Box::<crate::csv::Csv>::default() as Box<dyn Verifier + Send + Sync>)
                    } else {
                        bail!("feature `csv-verifier` is not enabled for `verifier` crate.")
                    }
                }
            }
            Tee::Kunpeng => {
                cfg_if! {
                    if #[cfg(feature = "kunpeng-verifier")] {
                        Ok(Box::<crate::kunpeng::Kunpeng>::default() as Box<dyn Verifier + Send + Sync>)
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
        .unwrap()
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
}
