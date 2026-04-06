use super::*;
use anyhow::Context;
use ear::{Algorithm, Appraisal, Ear, Profile, RawValue, RawValueKind, register_profile};
use serde::Deserialize;
use serde_json::Value;

use crate::csv_support::{
    CertificateChainSource, CsvEvidenceEnvelope, parse_attestation_report, parse_evidence,
    policy_to_json, resolve_certificate_chain, trim_null_terminated, verify_certificate_chain,
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

#[derive(Debug, Deserialize)]
struct SimplifiedCsvEvidence {
    version: String,
    serial_number: String,
    report_data: String,
    #[serde(alias = "measurement")]
    measure: String,
    #[serde(default)]
    policy: Value,
    #[serde(default)]
    user_pubkey_digest: String,
    #[serde(default)]
    cc_eventlog: Option<String>,
}

#[derive(Debug)]
struct CsvClaims {
    version: Option<String>,
    serial_number: String,
    report_data: Option<String>,
    measure: Option<String>,
    policy_json: Option<String>,
    user_pubkey_digest: Option<String>,
    cc_eventlog: Option<String>,
    evidence_shape: String,
    attestation_report_len: Option<i64>,
    cert_chain_embedded: Option<i64>,
    cert_chain_validation: Option<String>,
    cert_chain_source: Option<String>,
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

async fn normalize_claims(evidence: CsvEvidenceEnvelope) -> Result<CsvClaims> {
    match evidence {
        CsvEvidenceEnvelope::Simplified(evidence) => {
            let evidence: SimplifiedCsvEvidence = serde_json::from_value(evidence)
                .context("failed to parse simplified CSV evidence")?;
            Ok(CsvClaims {
                version: Some(evidence.version),
                serial_number: evidence.serial_number,
                report_data: Some(evidence.report_data),
                measure: Some(evidence.measure),
                policy_json: Some(serde_json::to_string(&evidence.policy)?),
                user_pubkey_digest: (!evidence.user_pubkey_digest.is_empty())
                    .then_some(evidence.user_pubkey_digest),
                cc_eventlog: evidence.cc_eventlog,
                evidence_shape: "normalized-mock".to_string(),
                attestation_report_len: None,
                cert_chain_embedded: None,
                cert_chain_validation: Some("not_applicable".to_string()),
                cert_chain_source: Some("mock".to_string()),
            })
        }
        CsvEvidenceEnvelope::Trustee { evidence, raw } => {
            let serial_number = trim_null_terminated(&evidence.serial_number)?;
            let report = parse_attestation_report(&evidence.attestation_report)?;
            let resolved_chain =
                resolve_certificate_chain(&serial_number, evidence.cert_chain).await?;
            verify_certificate_chain(&report, &resolved_chain)?;

            Ok(CsvClaims {
                version: Some(report.version().to_string()),
                serial_number,
                report_data: Some(crate::csv_support::encode_hex(
                    &report.tee_info().report_data(),
                )),
                measure: Some(crate::csv_support::encode_hex(&report.tee_info().measure())),
                policy_json: Some(policy_to_json(report.tee_info().policy())?),
                user_pubkey_digest: Some(crate::csv_support::encode_hex(
                    &report.tee_info().user_pubkey_digest(),
                )),
                cc_eventlog: evidence.cc_eventlog,
                evidence_shape: "trustee-reference-json".to_string(),
                attestation_report_len: raw
                    .pointer("/attestation_report/data")
                    .and_then(Value::as_array)
                    .map(|report_bytes| report_bytes.len() as i64),
                cert_chain_embedded: Some(i64::from(raw.pointer("/cert_chain/hsk_cek").is_some())),
                cert_chain_validation: Some("verified".to_string()),
                cert_chain_source: Some(match resolved_chain.source {
                    CertificateChainSource::Embedded => "embedded".to_string(),
                    CertificateChainSource::LocalFile => "local-file".to_string(),
                    CertificateChainSource::Kds => "kds".to_string(),
                }),
            })
        }
    }
}

fn gen_ear_token(claims: &CsvClaims) -> Result<Ear> {
    let mut token = init_ear(PROFILE_NAME)?;

    let mut appraisal = Appraisal::new_with_profile(PROFILE_NAME)?;
    if let Some(version) = &claims.version {
        appraisal
            .extensions
            .set_by_key(EXT_VERSION, RawValue::String(version.clone()))?;
    }
    appraisal.extensions.set_by_key(
        EXT_SERIAL_NUMBER,
        RawValue::String(claims.serial_number.clone()),
    )?;
    if let Some(report_data) = &claims.report_data {
        appraisal
            .extensions
            .set_by_key(EXT_REPORT_DATA, RawValue::String(report_data.clone()))?;
    }
    if let Some(measure) = &claims.measure {
        appraisal
            .extensions
            .set_by_key(EXT_MEASURE, RawValue::String(measure.clone()))?;
    }
    if let Some(policy_json) = &claims.policy_json {
        appraisal
            .extensions
            .set_by_key(EXT_POLICY_JSON, RawValue::String(policy_json.clone()))?;
    }
    if let Some(user_pubkey_digest) = &claims.user_pubkey_digest {
        appraisal.extensions.set_by_key(
            EXT_USER_PUBKEY_DIGEST,
            RawValue::String(user_pubkey_digest.clone()),
        )?;
    }
    if let Some(cc_eventlog) = &claims.cc_eventlog {
        appraisal
            .extensions
            .set_by_key(EXT_CC_EVENTLOG, RawValue::String(cc_eventlog.clone()))?;
    }
    appraisal.extensions.set_by_key(
        EXT_EVIDENCE_SHAPE,
        RawValue::String(claims.evidence_shape.clone()),
    )?;
    if let Some(attestation_report_len) = claims.attestation_report_len {
        appraisal.extensions.set_by_key(
            EXT_ATTESTATION_REPORT_LEN,
            RawValue::Integer(attestation_report_len),
        )?;
    }
    if let Some(cert_chain_embedded) = claims.cert_chain_embedded {
        appraisal.extensions.set_by_key(
            EXT_CERT_CHAIN_EMBEDDED,
            RawValue::Integer(cert_chain_embedded),
        )?;
    }
    if let Some(cert_chain_validation) = &claims.cert_chain_validation {
        appraisal.extensions.set_by_key(
            EXT_CERT_CHAIN_VALIDATION,
            RawValue::String(cert_chain_validation.clone()),
        )?;
    }
    if let Some(cert_chain_source) = &claims.cert_chain_source {
        appraisal.extensions.set_by_key(
            EXT_CERT_CHAIN_SOURCE,
            RawValue::String(cert_chain_source.clone()),
        )?;
    }
    appraisal.update_status_from_trust_vector();

    token.submods.insert("csv".to_string(), appraisal);
    Ok(token)
}

#[async_trait]
impl Verifier for Csv {
    async fn verify(
        &self,
        raw_evidence: &[u8],
        challenge: &ChallengeTokenClaims,
    ) -> Result<String> {
        init_profile()?;

        let evidence = parse_evidence(raw_evidence)?;
        let claims = normalize_claims(evidence).await?;
        let mut ear_token = gen_ear_token(&claims)?;
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
        let verifier = to_verifier(&Tee::Csv).expect("failed to create CSV verifier");
        let evidence = include_bytes!("../../test_data/csv/csv_evidence.json");
        let challenge = ChallengeTokenClaims {
            tee: Tee::Csv as i32,
            mode: 1,
            nonce: "ZGVtby1jc3Ytbm9uY2U".to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
        };

        let signed_token = verifier.verify(evidence, &challenge).await?;
        let pub_key = include_bytes!("../../test_certs/server_pubkey.json");
        let ear = Ear::from_jwt_jwk(&signed_token, Algorithm::ES384, pub_key)?;
        let token_pretty = serde_json::to_string_pretty(&ear)?;
        assert!(token_pretty.contains("KPA64911240507"));
        assert!(token_pretty.contains("trustee-reference-json"));
        assert!(token_pretty.contains("verified"));
        assert!(token_pretty.contains("local-file"));
        Ok(())
    }

    #[tokio::test]
    async fn reject_tampered_pek_signature() {
        let verifier = to_verifier(&Tee::Csv).expect("failed to create CSV verifier");
        let mut evidence: Value =
            serde_json::from_slice(include_bytes!("../../test_data/csv/csv_evidence.json"))
                .expect("failed to parse csv evidence");
        let r0 = evidence
            .pointer("/cert_chain/pek/sigs/0/signature/r/0")
            .and_then(Value::as_u64)
            .expect("missing PEK signature byte");
        *evidence
            .pointer_mut("/cert_chain/pek/sigs/0/signature/r/0")
            .expect("missing mutable PEK signature byte") = serde_json::json!((r0 + 1) % 255);

        let challenge = ChallengeTokenClaims {
            tee: Tee::Csv as i32,
            mode: 1,
            nonce: "dGFtcGVyZWQtY3N2LW5vbmNl".to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
        };

        let result = verifier
            .verify(
                &serde_json::to_vec(&evidence).expect("failed to serialize tampered evidence"),
                &challenge,
            )
            .await;
        assert!(result.is_err());
    }
}
