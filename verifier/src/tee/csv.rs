mod certs;
mod evidence;
mod kds;

use async_trait::async_trait;
use ear::{Algorithm, Appraisal, Profile, RawValue, RawValueKind, register_profile};
use serde_json::Value;

use self::certs::{CertificateChainSource, verify_certificate_chain};
use self::evidence::{
    CsvEvidence, encode_hex, parse_attestation_report, parse_evidence, policy_to_json,
    trim_null_terminated,
};
use self::kds::resolve_certificate_chain;
use crate::{
    Result, VerificationContext, Verifier, apply_appraisal, apply_challenge, config, init_ear,
    verify_challenge_binding,
};

#[derive(Debug, Default)]
pub struct Csv {}

const PROFILE_NAME: &str = "csv-ear";
const EXT_VERSION: i32 = 2001;
const EXT_SERIAL_NUMBER: i32 = 2002;
const EXT_REPORT_DATA: i32 = 2003;
const EXT_MEASURE: i32 = 2004;
const EXT_POLICY_JSON: i32 = 2005;
const EXT_USER_PUBKEY_DIGEST: i32 = 2006;
const EXT_CC_EVENTLOG: i32 = 2007;
const EXT_EVIDENCE_SHAPE: i32 = 2008;
const EXT_ATTESTATION_REPORT_LEN: i32 = 2009;
const EXT_CERT_CHAIN_EMBEDDED: i32 = 2010;
const EXT_CERT_CHAIN_VALIDATION: i32 = 2011;
const EXT_CERT_CHAIN_SOURCE: i32 = 2012;

#[derive(Debug)]
struct CsvClaims {
    version: String,
    serial_number: String,
    report_data: String,
    measure: String,
    policy_json: String,
    nodbg: bool,
    user_pubkey_digest: String,
    cc_eventlog: Option<String>,
    evidence_shape: &'static str,
    attestation_report_len: Option<i64>,
    cert_chain_embedded: bool,
    cert_chain_validation: &'static str,
    cert_chain_source: &'static str,
    challenge_binding_data: Vec<u8>,
}

fn init_profile() -> Result<()> {
    let mut profile = Profile::new(PROFILE_NAME);
    profile.register_appraisal_extension("version", EXT_VERSION, RawValueKind::String)?;
    profile.register_appraisal_extension(
        "serial_number",
        EXT_SERIAL_NUMBER,
        RawValueKind::String,
    )?;
    profile.register_appraisal_extension("report_data", EXT_REPORT_DATA, RawValueKind::String)?;
    profile.register_appraisal_extension("measure", EXT_MEASURE, RawValueKind::String)?;
    profile.register_appraisal_extension("policy", EXT_POLICY_JSON, RawValueKind::String)?;
    profile.register_appraisal_extension(
        "user_pubkey_digest",
        EXT_USER_PUBKEY_DIGEST,
        RawValueKind::String,
    )?;
    profile.register_appraisal_extension("cc_eventlog", EXT_CC_EVENTLOG, RawValueKind::String)?;
    profile.register_appraisal_extension(
        "evidence_shape",
        EXT_EVIDENCE_SHAPE,
        RawValueKind::String,
    )?;
    profile.register_appraisal_extension(
        "attestation_report_len",
        EXT_ATTESTATION_REPORT_LEN,
        RawValueKind::Integer,
    )?;
    profile.register_appraisal_extension(
        "cert_chain_embedded",
        EXT_CERT_CHAIN_EMBEDDED,
        RawValueKind::Integer,
    )?;
    profile.register_appraisal_extension(
        "certificate_chain_validation",
        EXT_CERT_CHAIN_VALIDATION,
        RawValueKind::String,
    )?;
    profile.register_appraisal_extension(
        "certificate_chain_source",
        EXT_CERT_CHAIN_SOURCE,
        RawValueKind::String,
    )?;
    if let Err(err) = register_profile(&profile)
        && !err.to_string().to_ascii_lowercase().contains("already")
    {
        return Err(err.into());
    }
    Ok(())
}

async fn normalize_claims(evidence: CsvEvidence) -> Result<CsvClaims> {
    let CsvEvidence { evidence, raw } = evidence;
    let serial_number = trim_null_terminated(&evidence.serial_number)?;
    let report = parse_attestation_report(&evidence.attestation_report)?;
    let resolved_chain = resolve_certificate_chain(&serial_number, evidence.cert_chain).await?;
    verify_certificate_chain(&report, &resolved_chain)?;
    let report_data = report.tee_info().report_data();
    let policy = report.tee_info().policy();
    let nodbg = policy.nodbg() == 1;

    Ok(CsvClaims {
        version: report.version().to_string(),
        serial_number,
        report_data: encode_hex(&report_data),
        measure: encode_hex(&report.tee_info().measure()),
        policy_json: policy_to_json(policy)?,
        nodbg,
        user_pubkey_digest: encode_hex(&report.tee_info().user_pubkey_digest()),
        cc_eventlog: evidence.cc_eventlog,
        evidence_shape: "trustee-reference-json",
        attestation_report_len: raw
            .pointer("/attestation_report/data")
            .and_then(Value::as_array)
            .map(|report_bytes| report_bytes.len() as i64),
        cert_chain_embedded: raw.pointer("/cert_chain/hsk_cek").is_some(),
        cert_chain_validation: "verified",
        cert_chain_source: match resolved_chain.source {
            CertificateChainSource::Embedded => "embedded",
            CertificateChainSource::LocalFile => "local-file",
            CertificateChainSource::Kds => "kds",
        },
        challenge_binding_data: report_data,
    })
}

fn gen_ear_token(claims: &CsvClaims) -> Result<crate::Ear> {
    let mut token = init_ear(PROFILE_NAME)?;

    let mut appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
    appraisal
        .extensions
        .set_by_key(EXT_VERSION, RawValue::String(claims.version.clone()))?;
    appraisal.extensions.set_by_key(
        EXT_SERIAL_NUMBER,
        RawValue::String(claims.serial_number.clone()),
    )?;
    appraisal.extensions.set_by_key(
        EXT_REPORT_DATA,
        RawValue::String(claims.report_data.clone()),
    )?;
    appraisal
        .extensions
        .set_by_key(EXT_MEASURE, RawValue::String(claims.measure.clone()))?;
    appraisal.extensions.set_by_key(
        EXT_POLICY_JSON,
        RawValue::String(claims.policy_json.clone()),
    )?;
    appraisal.extensions.set_by_key(
        EXT_USER_PUBKEY_DIGEST,
        RawValue::String(claims.user_pubkey_digest.clone()),
    )?;
    if let Some(cc_eventlog) = &claims.cc_eventlog {
        appraisal
            .extensions
            .set_by_key(EXT_CC_EVENTLOG, RawValue::String(cc_eventlog.clone()))?;
    }
    appraisal.extensions.set_by_key(
        EXT_EVIDENCE_SHAPE,
        RawValue::String(claims.evidence_shape.to_string()),
    )?;
    if let Some(attestation_report_len) = claims.attestation_report_len {
        appraisal.extensions.set_by_key(
            EXT_ATTESTATION_REPORT_LEN,
            RawValue::Integer(attestation_report_len),
        )?;
    }
    appraisal.extensions.set_by_key(
        EXT_CERT_CHAIN_EMBEDDED,
        RawValue::Integer(i64::from(claims.cert_chain_embedded)),
    )?;
    appraisal.extensions.set_by_key(
        EXT_CERT_CHAIN_VALIDATION,
        RawValue::String(claims.cert_chain_validation.to_string()),
    )?;
    appraisal.extensions.set_by_key(
        EXT_CERT_CHAIN_SOURCE,
        RawValue::String(claims.cert_chain_source.to_string()),
    )?;
    appraisal.update_status_from_trust_vector();

    token.submods.insert("csv".to_string(), appraisal);
    Ok(token)
}

#[async_trait]
impl Verifier for Csv {
    async fn verify(&self, raw_evidence: &[u8], context: &VerificationContext) -> Result<String> {
        init_profile()?;

        let evidence = parse_evidence(raw_evidence)?;
        let claims = normalize_claims(evidence).await?;
        let mut ear_token = gen_ear_token(&claims)?;
        let appraisal = context
            .csv_appraisal_policy()
            .evaluate_csv(Some(&claims.measure), claims.nodbg)?;
        let binding_status =
            verify_challenge_binding(&claims.challenge_binding_data, &context.challenge)?;
        apply_appraisal(&mut ear_token, appraisal)?;
        apply_challenge(
            &mut ear_token,
            &context.challenge,
            binding_status.as_token_value(),
            context.evidence_source(),
        )?;

        let config = config::get();
        let pri_key = config::read_binary(&config.signing_key_path)?;
        Ok(ear_token.sign_jwt_pem(Algorithm::ES384, &pri_key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChallengeTokenClaims;
    use protos::Tee;

    async fn challenge_from_csv_evidence(
        tee: Tee,
        raw_evidence: &[u8],
    ) -> Result<ChallengeTokenClaims> {
        let evidence = parse_evidence(raw_evidence)?;
        let claims = normalize_claims(evidence).await?;
        let (_nonce, token) = protos::challenge::issue(
            tee as i32,
            1,
            Some(&claims.challenge_binding_data),
            60,
            b"test-challenge-key",
        )?;
        protos::challenge::decode(&token)
    }

    async fn csv_fixture_context(raw_evidence: &[u8]) -> Result<Option<VerificationContext>> {
        match challenge_from_csv_evidence(Tee::Csv, raw_evidence).await {
            Ok(challenge) => Ok(Some(VerificationContext::new(challenge, "file-backed"))),
            Err(err) if is_missing_csv_bundle(&err) => {
                eprintln!("skipping CSV fixture test: {err}");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn is_missing_csv_bundle(err: &anyhow::Error) -> bool {
        err.to_string().contains("missing HSK/CEK")
            || err
                .chain()
                .any(|cause| cause.to_string().contains("missing HSK/CEK"))
    }

    #[tokio::test]
    async fn verify() -> Result<()> {
        let verifier = crate::to_verifier(&Tee::Csv).expect("failed to create CSV verifier");
        let evidence = include_bytes!("../../../test_data/csv/csv_evidence.json");
        let Some(context) = csv_fixture_context(evidence).await? else {
            return Ok(());
        };

        let signed_token = verifier.verify(evidence, &context).await?;
        let pub_key = include_bytes!("../../../test_certs/server_pubkey.json");
        let ear = crate::Ear::from_jwt_jwk(&signed_token, Algorithm::ES384, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        assert!(token_pretty.contains("KPA64911240507"));
        assert!(token_pretty.contains("trustee-reference-json"));
        assert!(token_pretty.contains("verified"));
        assert!(token_pretty.contains("local-file"));
        Ok(())
    }

    #[tokio::test]
    async fn reject_tampered_pek_signature() -> Result<()> {
        let verifier = crate::to_verifier(&Tee::Csv).expect("failed to create CSV verifier");
        let mut evidence: Value =
            serde_json::from_slice(include_bytes!("../../../test_data/csv/csv_evidence.json"))
                .expect("failed to parse csv evidence");
        let r0 = evidence
            .pointer("/cert_chain/pek/sigs/0/signature/r/0")
            .and_then(Value::as_u64)
            .expect("missing PEK signature byte");
        *evidence
            .pointer_mut("/cert_chain/pek/sigs/0/signature/r/0")
            .expect("missing mutable PEK signature byte") = serde_json::json!((r0 + 1) % 255);

        let Some(context) =
            csv_fixture_context(include_bytes!("../../../test_data/csv/csv_evidence.json")).await?
        else {
            return Ok(());
        };

        let result = verifier
            .verify(
                &serde_json::to_vec(&evidence).expect("failed to serialize tampered evidence"),
                &context,
            )
            .await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reject_challenge_mismatch() -> Result<()> {
        let verifier = crate::to_verifier(&Tee::Csv).expect("failed to create CSV verifier");
        let evidence = include_bytes!("../../../test_data/csv/csv_evidence.json");
        if csv_fixture_context(evidence).await?.is_none() {
            return Ok(());
        }
        let (_nonce, token) = protos::challenge::issue(
            Tee::Csv as i32,
            1,
            Some(b"mismatched-csv-nonce"),
            60,
            b"test-challenge-key",
        )?;
        let challenge = protos::challenge::decode(&token)?;
        let context = VerificationContext::new(challenge, "file-backed");

        let result = verifier.verify(evidence, &context).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("mismatched challenge should fail")
                .to_string()
                .contains("challenge/report data mismatch")
        );
        Ok(())
    }

    #[tokio::test]
    async fn reject_evidence_without_attestation_report() -> Result<()> {
        let verifier = crate::to_verifier(&Tee::Csv).expect("failed to create CSV verifier");
        let evidence = b"{\"serial_number\":\"mock\"}";
        let challenge = ChallengeTokenClaims {
            tee: Tee::Csv as i32,
            mode: 1,
            nonce: "ZXhwZWN0ZWQtbm9uY2U".to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
        };
        let context = VerificationContext::new(challenge, "file-backed");

        let err = verifier
            .verify(evidence, &context)
            .await
            .expect_err("CSV evidence without attestation_report must be rejected");
        assert!(err.to_string().contains("attestation_report"));
        Ok(())
    }
}
