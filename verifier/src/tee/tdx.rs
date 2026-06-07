use async_trait::async_trait;
// use dcap_qvl::PHALA_PCCS_URL;
// use dcap_qvl::collateral::get_collateral;
use ear::{Algorithm, Appraisal, Bytes, Profile, RawValue, RawValueKind, register_profile};
use tdx_quote::Quote;

use crate::{
    Result, VerificationContext, Verifier, apply_challenge, config, init_ear,
    verify_challenge_binding,
};

// ADR 0007: 当前阶段未接入真实 DCAP / PCCS 链路，binding 标签固定为 "simulated"。
const BINDING_STATUS_SIMULATED: &str = "simulated";

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

fn gen_ear_token(quote: &Quote) -> Result<crate::Ear> {
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
    // ADR 0007: PCK chain 验证未接入，写入 0；接入 DCAP QVL 后改为动态值。
    appraisal
        .extensions
        .set_by_key(EXT_PCK_CHAIN_VERIFIED, RawValue::Integer(0))?;

    appraisal.update_status_from_trust_vector();

    token.submods.insert("tdx".to_string(), appraisal);

    Ok(token)
}

#[async_trait]
impl Verifier for TDX {
    async fn verify(&self, raw_evidence: &[u8], context: &VerificationContext) -> Result<String> {
        init_profile()?;

        let quote = check_quote(raw_evidence)?;

        // ADR 0007: challenge 比对仍执行（quote 自身字段层面，挡住明显的 nonce 不匹配），
        // 但其结果不再决定 binding 状态——当前阶段统一标记为 simulated。
        verify_challenge_binding(&quote.report_input_data(), &context.challenge)?;
        let mut ear_token = gen_ear_token(&quote)?;
        apply_challenge(
            &mut ear_token,
            &context.challenge,
            BINDING_STATUS_SIMULATED,
            context.evidence_source(),
        )?;

        let config = config::get();
        let pri_key = config::read_binary(&config.signing_key_path)?;
        let signed_token = ear_token.sign_jwt_pem(Algorithm::ES384, &pri_key)?;
        Ok(signed_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChallengeTokenClaims;
    use protos::Tee;

    fn challenge_from_report_data(tee: Tee, report_data: &[u8]) -> Result<ChallengeTokenClaims> {
        let (_nonce, token) =
            protos::challenge::issue(tee as i32, 1, Some(report_data), 60, b"test-challenge-key")?;
        protos::challenge::decode(&token)
    }

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = crate::to_verifier(&Tee::Tdx).expect("failed to create TDX verifier");
        let quote = include_bytes!("../../../test_data/tdx/tdx_quote_4.dat");
        let parsed_quote = check_quote(quote)?;
        let challenge = challenge_from_report_data(Tee::Tdx, &parsed_quote.report_input_data())?;
        let context = VerificationContext::new(challenge, "file-backed");

        let signed_token = verifier.verify(quote, &context).await?;

        let pub_key = include_bytes!("../../../test_certs/server_pubkey.json");
        let ear = crate::Ear::from_jwt_jwk(&signed_token, Algorithm::ES384, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        println!("verified EAR Token Content (JSON): {}", &token_pretty);

        Ok(())
    }

    #[tokio::test]
    async fn reject_challenge_mismatch() -> Result<()> {
        let verifier = crate::to_verifier(&Tee::Tdx).expect("failed to create TDX verifier");
        let quote = include_bytes!("../../../test_data/tdx/tdx_quote_4.dat");
        let challenge = challenge_from_report_data(Tee::Tdx, b"mismatched-tdx-nonce")?;
        let context = VerificationContext::new(challenge, "file-backed");

        let result = verifier.verify(quote, &context).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("mismatched challenge should fail")
                .to_string()
                .contains("challenge/report data mismatch")
        );
        Ok(())
    }
}
