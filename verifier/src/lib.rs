pub mod api;
pub mod config;
pub mod core;
pub mod service;
pub mod service_config;
pub mod tee;

pub use anyhow::Result;
pub use async_trait::async_trait;
pub use ear::Ear;
pub use protos::challenge::ChallengeTokenClaims;

pub use core::{
    AppraisalOutcome, AppraisalPolicy, ChallengeBindingStatus, TeeClass, TeeEvidenceParsedClaim,
    VerificationContext, Verifier, apply_appraisal, apply_challenge, init_ear, to_verifier,
    verify_challenge_binding,
};
