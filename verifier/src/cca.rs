use super::*;
use ccatoken::{store, token::Evidence};
use ear::{Algorithm, Appraisal, Bytes, Profile, RawValue, RawValueKind, register_profile};

#[derive(Debug, Default)]
pub struct CCA {}

const PROFILE_NAME: &str = "cca-ear";

fn init_profile() -> Result<()> {
    let mut profile = Profile::new(PROFILE_NAME);
    profile.register_appraisal_extension("nonce", 11, RawValueKind::Bytes)?;
    if let Err(err) = register_profile(&profile)
        && !err.to_string().to_ascii_lowercase().contains("already")
    {
        return Err(err.into());
    }
    Ok(())
}

fn check_evidence(e: &mut Evidence) -> Result<()> {
    let config = config::get();
    let jta = config::read_text(&config.cca_trust_anchors_path)?;
    let mut tas = store::MemoTrustAnchorStore::new();
    tas.load_json(&jta).expect("loading trust anchors");
    e.verify(&tas)?;

    let jrv = config::read_text(&config.cca_reference_values_path)?;
    let mut rvs = store::MemoRefValueStore::new();
    rvs.load_json(&jrv).expect("loading reference values");
    e.appraise(&rvs)?;
    Ok(())
}

fn gen_ear_token(e: &Evidence) -> Result<Ear> {
    let (platform_tvec, realm_tvec) = e.get_trust_vectors();

    let mut token = init_ear(PROFILE_NAME)?;

    let mut platform_appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
    // Convert via JSON as an interchange format.
    platform_appraisal.trust_vector =
        serde_json::from_str(&serde_json::to_string(&platform_tvec)?)?;
    platform_appraisal.extensions.set_by_key(
        11,
        RawValue::Bytes(Bytes(e.platform_claims.challenge.to_vec())),
    )?;
    platform_appraisal.update_status_from_trust_vector();

    let mut realm_appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
    realm_appraisal.trust_vector = serde_json::from_str(&serde_json::to_string(&realm_tvec)?)?;
    realm_appraisal.extensions.set_by_key(
        11,
        RawValue::Bytes(Bytes(e.realm_claims.challenge.to_vec())),
    )?;
    realm_appraisal.update_status_from_trust_vector();

    token
        .submods
        .insert("platform".to_string(), platform_appraisal);
    token.submods.insert("realm".to_string(), realm_appraisal);

    Ok(token)
}

#[async_trait]
impl Verifier for CCA {
    async fn verify(
        &self,
        raw_evidence: &[u8],
        challenge: &ChallengeTokenClaims,
    ) -> Result<String> {
        init_profile()?;

        let mut e = Evidence::decode(&raw_evidence.to_vec()).expect("decoding CCA token");

        check_evidence(&mut e)?;

        let binding_status = verify_challenge_binding(&e.realm_claims.challenge, challenge)?;
        let mut ear_token = gen_ear_token(&e)?;
        apply_challenge(
            &mut ear_token,
            challenge,
            binding_status.as_token_value(),
            "file-backed",
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
    use protos::Tee;

    fn challenge_from_report_data(tee: Tee, report_data: &[u8]) -> Result<ChallengeTokenClaims> {
        let (_nonce, token) =
            protos::challenge::issue(tee as i32, 1, Some(report_data), 60, b"test-challenge-key")?;
        protos::challenge::decode(&token)
    }

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = to_verifier(&Tee::Cca).expect("failed to create CCA verifier");
        let token = include_bytes!("../../test_data/cca/cca-token.cbor");
        let evidence = Evidence::decode(&token.to_vec()).expect("decoding CCA token");
        let challenge = challenge_from_report_data(Tee::Cca, &evidence.realm_claims.challenge)?;
        let signed_token = verifier.verify(token, &challenge).await?;

        let pub_key = include_bytes!("../../test_certs/server_pubkey.json");
        let ear = Ear::from_jwt_jwk(&signed_token, Algorithm::ES384, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        println!("verified EAR Token Content (JSON): {}", &token_pretty);

        Ok(())
    }

    #[tokio::test]
    async fn reject_challenge_mismatch() -> Result<()> {
        let verifier = to_verifier(&Tee::Cca).expect("failed to create CCA verifier");
        let token = include_bytes!("../../test_data/cca/cca-token.cbor");
        let challenge = challenge_from_report_data(Tee::Cca, b"mismatched-cca-nonce")?;

        let result = verifier.verify(token, &challenge).await;
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
