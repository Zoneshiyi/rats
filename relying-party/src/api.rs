use anyhow::{Result, bail};
use async_trait::async_trait;
use protos::attestation_response;
use protos::attestation_service_client::AttestationServiceClient;
use protos::{
    AttestationRequest, ChallengeRequest, ErrorCode, Evidence, Mode, VerificationRequest,
};
use tonic::Request;
use tonic::transport::Channel;

use crate::service::{
    AttestationGateway, AttestationOutcome, IssuedChallenge, RelyingPartyEvidence,
};

pub struct GrpcAttestationGateway {
    inner: AttestationServiceClient<Channel>,
}

impl GrpcAttestationGateway {
    pub async fn connect(addr: impl Into<String>) -> Result<Self> {
        let endpoint = format!("http://{}", addr.into());
        let inner = AttestationServiceClient::connect(endpoint).await?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl AttestationGateway for GrpcAttestationGateway {
    async fn get_challenge(&mut self, mode: Mode, nonce: Vec<u8>) -> Result<IssuedChallenge> {
        let request = ChallengeRequest {
            mode: mode as i32,
            nonce,
        };
        let response = self
            .inner
            .get_challenge(Request::new(request))
            .await?
            .into_inner();
        ensure_ok(response.error_code)?;
        Ok(IssuedChallenge {
            nonce: response.nonce,
            challenge_token: response.challenge_token,
        })
    }

    async fn attest(&mut self, mode: Mode, challenge_token: Vec<u8>) -> Result<AttestationOutcome> {
        let request = AttestationRequest {
            mode: mode as i32,
            challenge_token,
        };
        let response = self
            .inner
            .attestation_evaluate(Request::new(request))
            .await?
            .into_inner();
        ensure_ok(response.error_code)?;

        match response.result {
            Some(attestation_response::Result::AttestationToken(token)) => {
                Ok(AttestationOutcome::AttestationToken(token))
            }
            Some(attestation_response::Result::EvidenceList(list)) => {
                Ok(AttestationOutcome::EvidenceList(
                    list.evidence
                        .into_iter()
                        .map(|item| RelyingPartyEvidence {
                            init_data: item.init_data,
                            runtime_data: item.runtime_data,
                        })
                        .collect(),
                ))
            }
            None => bail!("missing attestation result"),
        }
    }

    async fn verify(
        &mut self,
        evidence: Vec<RelyingPartyEvidence>,
        challenge_token: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let request = VerificationRequest {
            evidence: evidence
                .into_iter()
                .map(|item| Evidence {
                    init_data: item.init_data,
                    runtime_data: item.runtime_data,
                })
                .collect(),
            challenge_token,
        };
        let response = self
            .inner
            .verification_evaluate(Request::new(request))
            .await?
            .into_inner();
        ensure_ok(response.error_code)?;
        Ok(response.attestation_token)
    }
}

fn ensure_ok(code: i32) -> Result<()> {
    if code == ErrorCode::Ok as i32 {
        return Ok(());
    }
    bail!("remote call failed with code: {}", code)
}
