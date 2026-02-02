use super::*;
use anyhow::Ok;
use dcap_qvl::PHALA_PCCS_URL;
use dcap_qvl::collateral::get_collateral;
use ear::{Profile, RawValueKind, register_profile};

#[derive(Debug, Default)]
pub struct TDX {}

const PROFILE_NAME: &str = "tdx-ear";

fn init_profile() {
    let mut profile = Profile::new(PROFILE_NAME);
    _ = profile.register_appraisal_extension("ext.test", -812345, RawValueKind::Integer);
    _ = register_profile(&profile);
}

#[async_trait]
impl Verifier for TDX {
    async fn verify(&self, raw_evidence: &[u8]) -> Result<String> {
        init_profile();

        let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
        let collateral = get_collateral(&pccs_url, raw_evidence)
            .await
            .expect("failed to get collateral");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let report = dcap_qvl::verify::verify(raw_evidence, &collateral, now).expect("failed to verify quote");
        println!("{:?}", report);

        Ok("<tdx-ear-token>".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = to_verifier(&Tee::Tdx).expect("failed to create TDX verifier");
        let quote = include_bytes!("../../test_data/tdx/tdx_quote_5.dat");

        let _ = verifier.verify(quote).await?;

        Ok(())
    }
}
