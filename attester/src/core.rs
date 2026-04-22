use anyhow::{Result, anyhow};
use async_trait::async_trait;
use protos::challenge::decode as decode_challenge_token;
use protos::{Evidence, Mode, Tee};
use tokio::fs;

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
    use protos::challenge;

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
}
