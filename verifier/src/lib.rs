pub mod api;
pub mod config;
pub mod core;
pub mod service;
pub mod service_config;

pub use anyhow::Result;
pub use async_trait::async_trait;
pub use ear::Ear;
pub use protos::challenge::ChallengeTokenClaims;

#[cfg(feature = "cca-verifier")]
pub mod cca;

#[cfg(feature = "tdx-verifier")]
pub mod tdx;

#[cfg(feature = "csv-verifier")]
pub mod csv;

#[cfg(feature = "csv-verifier")]
pub(crate) mod csv_support;

#[cfg(feature = "kunpeng-verifier")]
pub mod kunpeng;

pub use core::{
    AppraisalOutcome, AppraisalPolicy, ChallengeBindingStatus, TeeClass, TeeEvidenceParsedClaim,
    VerificationContext, Verifier, apply_appraisal, apply_challenge, init_ear, to_verifier,
    verify_challenge_binding,
};
