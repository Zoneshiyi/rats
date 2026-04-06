use super::*;
// use dcap_qvl::PHALA_PCCS_URL;
// use dcap_qvl::collateral::get_collateral;
use ear::{Algorithm, Appraisal, Bytes, Ear, Profile, RawValue, RawValueKind, register_profile};
use tdx_quote::Quote;

#[derive(Debug, Default)]
pub struct TDX {}

const PROFILE_NAME: &str = "tdx-ear";
const EXT_REPORTDATA: i32 = 1001;
const EXT_MRTD: i32 = 1002;
const EXT_RTMR0: i32 = 1003;
const EXT_RTMR1: i32 = 1004;
const EXT_RTMR2: i32 = 1005;
const EXT_RTMR3: i32 = 1006;
const EXT_PCK_CHAIN_VERIFIED: i32 = 1010;

fn init_profile() -> Result<()> {
    let mut profile = Profile::new(PROFILE_NAME);
    profile.register_appraisal_extension("reportdata", EXT_REPORTDATA, RawValueKind::Bytes)?;
    profile.register_appraisal_extension("mrtd", EXT_MRTD, RawValueKind::Bytes)?;
    profile.register_appraisal_extension("rtmr0", EXT_RTMR0, RawValueKind::Bytes)?;
    profile.register_appraisal_extension("rtmr1", EXT_RTMR1, RawValueKind::Bytes)?;
    profile.register_appraisal_extension("rtmr2", EXT_RTMR2, RawValueKind::Bytes)?;
    profile.register_appraisal_extension("rtmr3", EXT_RTMR3, RawValueKind::Bytes)?;
    profile.register_appraisal_extension(
        "pck_chain_verified",
        EXT_PCK_CHAIN_VERIFIED,
        RawValueKind::Integer,
    )?;
    if let Err(err) = register_profile(&profile)
        && !err.to_string().to_ascii_lowercase().contains("already")
    {
        return Err(err.into());
    }
    Ok(())
}

fn check_quote(raw_evidence: &[u8]) -> Result<Quote> {
    // let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
    // let collateral = get_collateral(&pccs_url, raw_evidence)
    //     .await
    //     .expect("failed to get collateral");

    // let now = std::time::SystemTime::now()
    //     .duration_since(std::time::UNIX_EPOCH)
    //     .unwrap()
    //     .as_secs();
    // let report = dcap_qvl::verify::verify(raw_evidence, &collateral, now)
    //     .expect("failed to verify quote");
    // println!("{:?}", report);

    let quote = Quote::from_bytes(raw_evidence)?;
    let _pck_pub = quote.verify()?;

    Ok(quote)
}

fn gen_ear_token(quote: &Quote) -> Result<Ear> {
    let mut token = init_ear(PROFILE_NAME)?;

    let mut appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
    appraisal.extensions.set_by_key(
        EXT_REPORTDATA,
        RawValue::Bytes(Bytes(quote.report_input_data().to_vec())),
    )?;
    appraisal
        .extensions
        .set_by_key(EXT_MRTD, RawValue::Bytes(Bytes(quote.mrtd().to_vec())))?;
    appraisal
        .extensions
        .set_by_key(EXT_RTMR0, RawValue::Bytes(Bytes(quote.rtmr0().to_vec())))?;
    appraisal
        .extensions
        .set_by_key(EXT_RTMR1, RawValue::Bytes(Bytes(quote.rtmr1().to_vec())))?;
    appraisal
        .extensions
        .set_by_key(EXT_RTMR2, RawValue::Bytes(Bytes(quote.rtmr2().to_vec())))?;
    appraisal
        .extensions
        .set_by_key(EXT_RTMR3, RawValue::Bytes(Bytes(quote.rtmr3().to_vec())))?;
    appraisal
        .extensions
        .set_by_key(EXT_PCK_CHAIN_VERIFIED, RawValue::Integer(1))?;

    appraisal.update_status_from_trust_vector();

    token.submods.insert("tdx".to_string(), appraisal);

    Ok(token)
}

#[async_trait]
impl Verifier for TDX {
    async fn verify(
        &self,
        raw_evidence: &[u8],
        challenge: &ChallengeTokenClaims,
    ) -> Result<String> {
        init_profile()?;

        let quote = check_quote(raw_evidence)?;

        let mut ear_token = gen_ear_token(&quote)?;
        apply_challenge(&mut ear_token, challenge, "simulated", "file-backed")?;

        let config = config::get();
        let pri_key = config::read_binary(&config.signing_key_path)?;
        let signed_token = ear_token.sign_jwt_pem(Algorithm::ES384, &pri_key)?;
        Ok(signed_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protos::Tee;

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = to_verifier(&Tee::Tdx).expect("failed to create TDX verifier");
        let quote = include_bytes!("../../test_data/tdx/tdx_quote_4.dat");
        let challenge = ChallengeTokenClaims {
            tee: 2,
            mode: 1,
            nonce: "ZGVtby10ZHgtbm9uY2U".to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
        };

        let signed_token = verifier.verify(quote, &challenge).await?;

        let pub_key = include_bytes!("../../test_certs/server_pubkey.json");
        let ear = Ear::from_jwt_jwk(&signed_token, Algorithm::ES384, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        println!("verified EAR Token Content (JSON): {}", &token_pretty);

        Ok(())
    }
}
