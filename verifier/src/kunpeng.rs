use super::*;
use ear::{Algorithm, Appraisal, Bytes, Ear, Profile, RawValue, RawValueKind, register_profile};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct Kunpeng {}

const PROFILE_NAME: &str = "kunpeng-ear";
const EXT_PLATFORM: i32 = 3001;
const EXT_DEVICE_ID: i32 = 3002;
const EXT_BOOT_MEASUREMENT: i32 = 3003;
const EXT_IMAGE_HASH: i32 = 3004;
const EXT_SECURE_BOOT: i32 = 3005;
const EXT_FIRMWARE_VERSION: i32 = 3006;

#[derive(Debug, Deserialize)]
struct KunpengEvidence {
    platform: String,
    device_id: String,
    boot_measurement: String,
    image_hash: String,
    secure_boot: bool,
    firmware_version: String,
}

fn init_profile() -> Result<()> {
    let mut profile = Profile::new(PROFILE_NAME);
    profile.register_appraisal_extension("platform", EXT_PLATFORM, RawValueKind::String)?;
    profile.register_appraisal_extension("device_id", EXT_DEVICE_ID, RawValueKind::String)?;
    profile.register_appraisal_extension(
        "boot_measurement",
        EXT_BOOT_MEASUREMENT,
        RawValueKind::Bytes,
    )?;
    profile.register_appraisal_extension("image_hash", EXT_IMAGE_HASH, RawValueKind::Bytes)?;
    profile.register_appraisal_extension("secure_boot", EXT_SECURE_BOOT, RawValueKind::Integer)?;
    profile.register_appraisal_extension(
        "firmware_version",
        EXT_FIRMWARE_VERSION,
        RawValueKind::String,
    )?;
    if let Err(err) = register_profile(&profile)
        && !err.to_string().to_ascii_lowercase().contains("already")
    {
        return Err(err.into());
    }
    Ok(())
}

fn parse_evidence(raw_evidence: &[u8]) -> Result<KunpengEvidence> {
    Ok(serde_json::from_slice(raw_evidence)?)
}

fn gen_ear_token(evidence: &KunpengEvidence) -> Result<Ear> {
    let mut token = init_ear(PROFILE_NAME)?;

    let mut appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
    appraisal
        .extensions
        .set_by_key(EXT_PLATFORM, RawValue::String(evidence.platform.clone()))?;
    appraisal
        .extensions
        .set_by_key(EXT_DEVICE_ID, RawValue::String(evidence.device_id.clone()))?;
    appraisal.extensions.set_by_key(
        EXT_BOOT_MEASUREMENT,
        RawValue::Bytes(Bytes(evidence.boot_measurement.as_bytes().to_vec())),
    )?;
    appraisal.extensions.set_by_key(
        EXT_IMAGE_HASH,
        RawValue::Bytes(Bytes(evidence.image_hash.as_bytes().to_vec())),
    )?;
    appraisal.extensions.set_by_key(
        EXT_SECURE_BOOT,
        RawValue::Integer(if evidence.secure_boot { 1 } else { 0 }),
    )?;
    appraisal.extensions.set_by_key(
        EXT_FIRMWARE_VERSION,
        RawValue::String(evidence.firmware_version.clone()),
    )?;
    appraisal.update_status_from_trust_vector();

    token.submods.insert("kunpeng".to_string(), appraisal);
    Ok(token)
}

#[async_trait]
impl Verifier for Kunpeng {
    async fn verify(
        &self,
        raw_evidence: &[u8],
        challenge: &ChallengeTokenClaims,
    ) -> Result<String> {
        init_profile()?;

        let evidence = parse_evidence(raw_evidence)?;
        let mut ear_token = gen_ear_token(&evidence)?;
        apply_challenge(&mut ear_token, challenge, "simulated", "file-backed")?;

        let config = config::get();
        let pri_key = config::read_binary(&config.signing_key_path)?;
        Ok(ear_token.sign_jwt_pem(Algorithm::ES384, &pri_key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protos::Tee;

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = to_verifier(&Tee::Kunpeng).expect("failed to create Kunpeng verifier");
        let evidence = include_bytes!("../../test_data/kunpeng/kunpeng_evidence.json");
        let challenge = ChallengeTokenClaims {
            tee: Tee::Kunpeng as i32,
            mode: 1,
            nonce: "ZGVtby1rdW5wZW5nLW5vbmNl".to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
        };

        let signed_token = verifier.verify(evidence, &challenge).await?;
        let pub_key = include_bytes!("../../test_certs/server_pubkey.json");
        let ear = Ear::from_jwt_jwk(&signed_token, Algorithm::ES384, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        println!("verified EAR Token Content (JSON): {}", &token_pretty);

        Ok(())
    }
}
