use super::*;
use ccatoken::{store, token};
use ear::{Algorithm, Appraisal, Ear, Profile, RawValue, RawValueKind, VerifierID, register_profile, Bytes};

#[derive(Debug, Default)]
pub struct CCA {}

const PROFILE_NAME: &str = "cca-ear";

fn init_profile() {
    let mut profile = Profile::new(PROFILE_NAME);
    _ = profile.register_appraisal_extension("nonce", 11, RawValueKind::Bytes);
    _ = register_profile(&profile);
}

#[async_trait]
impl Verifier for CCA {
    async fn verify(&self, raw_evidence: &[u8]) -> Result<String> {
        init_profile();

        let mut e = token::Evidence::decode(&raw_evidence.to_vec()).expect("decoding CCA token");

        // TODO: choose real ta.json
        let jta: &str = include_str!("../../test_data/cca/ta.json");
        let mut tas = store::MemoTrustAnchorStore::new();
        tas.load_json(jta).expect("loading trust anchors");
        // verify the integrity
        e.verify(&tas)?;

        // TODO: choose real rv.json
        let jrv: &str = include_str!("../../test_data/cca/rv.json");
        let mut rvs = store::MemoRefValueStore::new();
        rvs.load_json(jrv).expect("loading reference values");
        // compare with reference values
        e.appraise(&rvs).expect("appraising CCA token");

        let (platform_tvec, realm_tvec) = e.get_trust_vectors();

        let mut token = Ear::new_with_profile(PROFILE_NAME)?;
        token.iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        token.vid = VerifierID {
            build: "verifier-1.0.0".to_string(),
            developer: "https://veraison-project.org".to_string(),
        };

        let mut platform_appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
        // Convert via JSON as an interchange format.
        platform_appraisal.trust_vector =
            serde_json::from_str(&serde_json::to_string(&platform_tvec)?)?;
        platform_appraisal
            .extensions
            .set_by_key(11,
                RawValue::Bytes(Bytes(e.platform_claims.challenge))
            )?;
        platform_appraisal.update_status_from_trust_vector();

        let mut realm_appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
        realm_appraisal.trust_vector = serde_json::from_str(&serde_json::to_string(&realm_tvec)?)?;
        realm_appraisal.extensions.set_by_key(11,
            RawValue::Bytes(Bytes(e.realm_claims.challenge.to_vec()))
        )?;
        realm_appraisal.update_status_from_trust_vector();

        token
            .submods
            .insert("platform".to_string(), platform_appraisal);
        token.submods.insert("realm".to_string(), realm_appraisal);

        // println!("EAR Token Content (JSON): {}", serde_json::to_string_pretty(&token)?);

        // TODO: sign the token with real key
        let pri_key = include_bytes!("../../test_certs/server.pkcs8.key");
        let signed_token = token.sign_jwt_pem(Algorithm::ES256, pri_key)?;

        // println!("signed token: {}", signed_token);

        Ok(signed_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = to_verifier(&Tee::Cca).expect("failed to create CCA verifier");
        let token = include_bytes!("../../test_data/cca/cca-token.cbor");
        let signed_token = verifier.verify(token).await?;

        let pub_key = include_bytes!("../../test_certs/server_pubkey.json");
        let ear = Ear::from_jwt_jwk(&signed_token, Algorithm::ES256, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        println!("verified EAR Token Content (JSON): {}", &token_pretty);

        Ok(())
    }
}
