use anyhow::{bail, Result};
use async_trait::async_trait;
use cfg_if::cfg_if;
use kbs_types::Tee;
use serde_json::Value;

#[cfg(feature = "cca-verifier")]
pub mod cca;

#[cfg(feature = "tdx-verifier")]
pub mod tdx;
pub fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    match tee {
        Tee::Cca => {
            cfg_if! {
                if #[cfg(feature = "cca-verifier")] {
                    Ok(Box::<cca::CCA>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `cca-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Tdx => {
            cfg_if! {
                if #[cfg(feature = "tdx-verifier")] {
                    Ok(Box::<tdx::TDX>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `tdx-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        _ => bail!("unsupported TEE type"),
    }
}

pub type TeeEvidenceParsedClaim = Value;
pub type TeeClass = String;

#[async_trait]
pub trait Verifier {
    async fn verify(&self, raw_evidence: &[u8]) -> Result<String>;
}