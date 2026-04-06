use anyhow::{Context, Result, bail};
use bincode;
use bitfield::bitfield;
use libc::{c_int, c_uchar, c_void};
use openssl::{bn, ecdsa};
use openssl_sys::*;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use serde_json::{Value, json};
use std::io::Cursor;
use std::ptr;

use crate::config;

const HSK_CEK_FILENAME: &str = "hsk_cek.cert";
const ATTESTATION_EXT_MAGIC: [u8; 16] = *b"ATTESTATION_EXT\0";
const CSV_RTMR_REG_SIZE: usize = 32;
const HRK: &[u8] = include_bytes!("hrk.cert");

unsafe extern "C" {
    fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, sctx: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_CTX_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, len: c_int) -> c_int;
}

#[allow(non_snake_case)]
unsafe fn evp_pkey_ctx_set1_id(
    ctx: *mut EVP_PKEY_CTX,
    id: *const c_void,
    id_len: c_int,
) -> c_int {
    unsafe { EVP_PKEY_CTX_set1_id(ctx, id, id_len) }
}

pub(crate) enum CsvEvidenceEnvelope {
    Trustee {
        evidence: TrusteeCsvEvidence,
        raw: Value,
    },
    Simplified(Value),
}

#[derive(Deserialize)]
pub(crate) struct TrusteeCsvEvidence {
    pub attestation_report: AttestationReportWrapper,
    pub cert_chain: CertificateChain,
    pub serial_number: Vec<u8>,
    #[serde(default)]
    pub cc_eventlog: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CertificateChain {
    #[serde(default)]
    pub hsk_cek: Option<HskCek>,
    pub pek: CsvCertificate,
}

#[derive(Deserialize)]
pub(crate) struct HskCek {
    pub hsk: CaCertificate,
    pub cek: CsvCertificate,
}

#[derive(Copy, Clone)]
pub(crate) enum CertificateChainSource {
    Embedded,
    LocalFile,
    Kds,
}

pub(crate) struct ResolvedCertificateChain {
    pub hsk: CaCertificate,
    pub cek: CsvCertificate,
    pub pek: CsvCertificate,
    pub source: CertificateChainSource,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Usage(u32);

impl Usage {
    const HRK: Self = Self(0x0000u32.to_le());
    const HSK: Self = Self(0x0013u32.to_le());
    const PEK: Self = Self(0x1002u32.to_le());
    const CEK: Self = Self(0x1004u32.to_le());
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CsvAlgorithm(u32);

impl CsvAlgorithm {
    const SM2_SA: Self = Self(0x0004u32.to_le());
    const SM2_DH: Self = Self(0x0005u32.to_le());
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Group(u32);

impl Group {
    const SM2_256: Self = Self(3u32.to_le());

    fn size(self) -> Result<usize> {
        match self {
            Self::SM2_256 => Ok(32),
            _ => bail!("unsupported CSV curve group"),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct PubKey {
    g: Group,
    #[serde(with = "BigArray")]
    x: [u8; 72],
    #[serde(with = "BigArray")]
    y: [u8; 72],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
struct CsvVersion {
    major: u8,
    minor: u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct RawEcdsaSignature {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
}

impl Default for RawEcdsaSignature {
    fn default() -> Self {
        Self {
            r: [0u8; 72],
            s: [0u8; 72],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize)]
struct CaData {
    kid: [u8; 16],
    sid: [u8; 16],
    usage: Usage,
    reserved: [u8; 24],
}

#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize)]
struct CaPreamble {
    ver: u32,
    data: CaData,
}

#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize)]
struct CaBody {
    preamble: CaPreamble,
    pubkey: PubKey,
    uid_size: u16,
    #[serde(with = "BigArray")]
    user_id: [u8; 254],
    #[serde(with = "BigArray")]
    reserved: [u8; 108],
}

#[repr(C)]
#[derive(Copy, Clone, Deserialize, Serialize)]
pub(crate) struct CaCertificate {
    body: CaBody,
    signature: RawEcdsaSignature,
    #[serde(with = "BigArray")]
    _reserved: [u8; 112],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
struct CsvCertPubKey {
    usage: Usage,
    algo: CsvAlgorithm,
    key: PubKey,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
struct CsvCertData {
    firmware: CsvVersion,
    reserved1: u16,
    pubkey: CsvCertPubKey,
    uid_size: u16,
    #[serde(with = "BigArray")]
    user_id: [u8; 254],
    sid: [u8; 16],
    #[serde(with = "BigArray")]
    reserved2: [u8; 608],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
struct CsvCertBody {
    ver: u32,
    data: CsvCertData,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
struct CsvCertSignatureSlot {
    usage: Usage,
    algo: CsvAlgorithm,
    signature: RawEcdsaSignature,
    #[serde(with = "BigArray")]
    _reserved: [u8; 368],
}

impl CsvCertSignatureSlot {
    fn is_empty(&self) -> bool {
        match self.usage {
            Usage::CEK | Usage::HRK | Usage::HSK | Usage::PEK => {
                !matches!(self.algo, CsvAlgorithm::SM2_SA | CsvAlgorithm::SM2_DH)
            }
            _ => true,
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub(crate) struct CsvCertificate {
    body: CsvCertBody,
    sigs: [CsvCertSignatureSlot; 2],
}

bitfield! {
    #[repr(C)]
    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
    pub struct GuestPolicy(u32);
    impl Debug;
    pub nodbg, _: 0, 0;
    pub noks, _: 1, 1;
    pub es, _: 2, 2;
    pub nosend, _: 3, 3;
    pub domain, _: 4, 4;
    pub csv, _: 5, 5;
    pub csv3, _: 6, 6;
    pub asid_reuse, _: 7, 7;
    pub hsk_version, _: 11, 8;
    pub cek_version, _: 15, 12;
    pub api_major, _: 23, 16;
    pub api_minor, _: 31, 24;
}

impl GuestPolicy {
    fn xor(&self, anonce: u32) -> Self {
        Self(self.0 ^ anonce)
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TeeInfoV1 {
    user_pubkey_digest: [u8; 32],
    vm_id: [u8; 16],
    vm_version: [u8; 16],
    #[serde(with = "BigArray")]
    report_data: [u8; 64],
    mnonce: [u8; 16],
    measure: [u8; 32],
    policy: GuestPolicy,
    sig_usage: u32,
    sig_algo: u32,
    anonce: u32,
    sig: RawEcdsaSignature,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TeeInfoV2 {
    user_pubkey_digest: [u8; 32],
    vm_id: [u8; 16],
    vm_version: [u8; 16],
    #[serde(with = "BigArray")]
    report_data: [u8; 64],
    mnonce: [u8; 16],
    measure: [u8; 32],
    policy: GuestPolicy,
    sig_usage: u32,
    sig_algo: u32,
    build: u32,
    rtmr_version: u16,
    reserved0: [u8; 14],
    rtmr0: [u8; CSV_RTMR_REG_SIZE],
    rtmr1: [u8; CSV_RTMR_REG_SIZE],
    rtmr2: [u8; CSV_RTMR_REG_SIZE],
    rtmr3: [u8; CSV_RTMR_REG_SIZE],
    rtmr4: [u8; CSV_RTMR_REG_SIZE],
    #[serde(with = "BigArray")]
    reserved1: [u8; 656],
    sig: RawEcdsaSignature,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TeeInfoSigner {
    #[serde(with = "BigArray")]
    pek_cert: [u8; 2084],
    #[serde(with = "BigArray")]
    sn: [u8; 64],
    reserved: [u8; 32],
    mac: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttestationReportV1 {
    tee_info: TeeInfoV1,
    signer: TeeInfoSigner,
    #[serde(with = "BigArray")]
    reserved: [u8; 1548],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttestationReportV2 {
    tee_info: TeeInfoV2,
    signer: TeeInfoSigner,
    #[serde(with = "BigArray")]
    reserved: [u8; 716],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttestationReportWrapper {
    #[serde(default)]
    magic: [u8; 16],
    flags: u32,
    #[serde(with = "BigArray")]
    data: [u8; 4096],
}

pub(crate) enum AttestationReport {
    V1(AttestationReportV1),
    V2(AttestationReportV2),
}

pub(crate) enum TeeInfoRef<'a> {
    V1(&'a TeeInfoV1),
    V2(&'a TeeInfoV2),
}

impl AttestationReport {
    pub(crate) fn version(&self) -> &'static str {
        match self {
            Self::V1(_) => "1",
            Self::V2(_) => "2",
        }
    }

    pub(crate) fn tee_info(&self) -> TeeInfoRef<'_> {
        match self {
            Self::V1(report) => TeeInfoRef::V1(&report.tee_info),
            Self::V2(report) => TeeInfoRef::V2(&report.tee_info),
        }
    }
}

impl TeeInfoRef<'_> {
    pub(crate) fn report_data(&self) -> Vec<u8> {
        match self {
            Self::V1(tee_info) => xor_with_anonce(&tee_info.report_data, tee_info.anonce),
            Self::V2(tee_info) => tee_info.report_data.to_vec(),
        }
    }

    pub(crate) fn measure(&self) -> Vec<u8> {
        match self {
            Self::V1(tee_info) => xor_with_anonce(&tee_info.measure, tee_info.anonce),
            Self::V2(tee_info) => tee_info.measure.to_vec(),
        }
    }

    pub(crate) fn user_pubkey_digest(&self) -> Vec<u8> {
        match self {
            Self::V1(tee_info) => xor_with_anonce(&tee_info.user_pubkey_digest, tee_info.anonce),
            Self::V2(tee_info) => tee_info.user_pubkey_digest.to_vec(),
        }
    }

    pub(crate) fn policy(&self) -> GuestPolicy {
        match self {
            Self::V1(tee_info) => tee_info.policy.xor(tee_info.anonce),
            Self::V2(tee_info) => tee_info.policy,
        }
    }

    fn signature(&self) -> &RawEcdsaSignature {
        match self {
            Self::V1(tee_info) => &tee_info.sig,
            Self::V2(tee_info) => &tee_info.sig,
        }
    }

    fn signed_bytes(&self) -> Vec<u8> {
        match self {
            Self::V1(tee_info) => {
                let mut bytes = Vec::with_capacity(168);
                bytes.extend_from_slice(&tee_info.user_pubkey_digest);
                bytes.extend_from_slice(&tee_info.vm_id);
                bytes.extend_from_slice(&tee_info.vm_version);
                bytes.extend_from_slice(&tee_info.report_data);
                bytes.extend_from_slice(&tee_info.mnonce);
                bytes.extend_from_slice(&tee_info.measure);
                bytes.extend_from_slice(&tee_info.policy.0.to_le_bytes());
                bytes
            }
            Self::V2(tee_info) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&tee_info.user_pubkey_digest);
                bytes.extend_from_slice(&tee_info.vm_id);
                bytes.extend_from_slice(&tee_info.vm_version);
                bytes.extend_from_slice(&tee_info.report_data);
                bytes.extend_from_slice(&tee_info.mnonce);
                bytes.extend_from_slice(&tee_info.measure);
                bytes.extend_from_slice(&tee_info.policy.0.to_le_bytes());
                bytes.extend_from_slice(&tee_info.sig_usage.to_le_bytes());
                bytes.extend_from_slice(&tee_info.sig_algo.to_le_bytes());
                bytes.extend_from_slice(&tee_info.build.to_le_bytes());
                bytes.extend_from_slice(&tee_info.rtmr_version.to_le_bytes());
                bytes.extend_from_slice(&tee_info.reserved0);
                bytes.extend_from_slice(&tee_info.rtmr0);
                bytes.extend_from_slice(&tee_info.rtmr1);
                bytes.extend_from_slice(&tee_info.rtmr2);
                bytes.extend_from_slice(&tee_info.rtmr3);
                bytes.extend_from_slice(&tee_info.rtmr4);
                bytes.extend_from_slice(&tee_info.reserved1);
                bytes
            }
        }
    }
}

pub(crate) fn parse_evidence(raw_evidence: &[u8]) -> Result<CsvEvidenceEnvelope> {
    let value: Value = serde_json::from_slice(raw_evidence)?;
    if value.get("attestation_report").is_some() {
        Ok(CsvEvidenceEnvelope::Trustee {
            evidence: serde_json::from_value(value.clone())
                .context("failed to parse trustee-style CSV evidence")?,
            raw: value,
        })
    } else {
        Ok(CsvEvidenceEnvelope::Simplified(value))
    }
}

pub(crate) fn parse_attestation_report(
    wrapper: &AttestationReportWrapper,
) -> Result<AttestationReport> {
    match (wrapper.magic, wrapper.flags) {
        (magic, _) if magic == [0u8; 16] => Ok(AttestationReport::V1(
            bincode::deserialize::<AttestationReportV1>(&wrapper.data)
                .context("failed to decode CSV attestation report V1")?,
        )),
        (ATTESTATION_EXT_MAGIC, 0) => Ok(AttestationReport::V1(
            bincode::deserialize::<AttestationReportV1>(&wrapper.data)
                .context("failed to decode CSV attestation report V1")?,
        )),
        (ATTESTATION_EXT_MAGIC, 1) => Ok(AttestationReport::V2(
            bincode::deserialize::<AttestationReportV2>(&wrapper.data)
                .context("failed to decode CSV attestation report V2")?,
        )),
        _ => bail!("invalid CSV attestation report wrapper"),
    }
}

pub(crate) async fn resolve_certificate_chain(
    chip_id: &str,
    cert_chain: CertificateChain,
) -> Result<ResolvedCertificateChain> {
    if let Some(hsk_cek) = cert_chain.hsk_cek {
        return Ok(ResolvedCertificateChain {
            hsk: hsk_cek.hsk,
            cek: hsk_cek.cek,
            pek: cert_chain.pek,
            source: CertificateChainSource::Embedded,
        });
    }

    if let Some(cert_bytes) = try_load_hsk_cek_offline(chip_id)? {
        let (hsk, cek) = decode_hsk_cek_bundle(&cert_bytes)?;
        return Ok(ResolvedCertificateChain {
            hsk,
            cek,
            pek: cert_chain.pek,
            source: CertificateChainSource::LocalFile,
        });
    }

    let config = config::get();
    if config.csv_allow_kds_fetch {
        let cert_bytes = download_hsk_cek_from_kds(&config.csv_kds_base_url, chip_id).await?;
        let (hsk, cek) = decode_hsk_cek_bundle(&cert_bytes)?;
        return Ok(ResolvedCertificateChain {
            hsk,
            cek,
            pek: cert_chain.pek,
            source: CertificateChainSource::Kds,
        });
    }

    bail!("CSV evidence is missing HSK/CEK and no offline bundle was found for chip `{chip_id}`")
}

fn try_load_hsk_cek_offline(chip_id: &str) -> Result<Option<Vec<u8>>> {
    let config = config::get();
    let base_dir = config::resolve_existing_path(&config.csv_hsk_cek_dir);
    let candidates = [
        base_dir.join(chip_id).join(HSK_CEK_FILENAME),
        base_dir.join(format!("{chip_id}.cert")),
        base_dir.join(HSK_CEK_FILENAME),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Ok(Some(std::fs::read(&candidate).with_context(|| {
                format!(
                    "failed to read CSV HSK/CEK bundle from {}",
                    candidate.display()
                )
            })?));
        }
    }

    Ok(None)
}

async fn download_hsk_cek_from_kds(kds_base_url: &str, chip_id: &str) -> Result<Vec<u8>> {
    let url = format!(
        "{}/hsk_cek?snumber={chip_id}",
        kds_base_url.trim_end_matches('/')
    );
    let response = reqwest::get(&url)
        .await
        .with_context(|| format!("failed to request CSV HSK/CEK from {url}"))?;

    match response.status() {
        StatusCode::OK => Ok(response
            .bytes()
            .await
            .with_context(|| format!("failed to read CSV HSK/CEK response from {url}"))?
            .to_vec()),
        status => bail!("failed to fetch CSV HSK/CEK from {url}: {status}"),
    }
}

fn decode_hsk_cek_bundle(cert_bytes: &[u8]) -> Result<(CaCertificate, CsvCertificate)> {
    let mut cursor = Cursor::new(cert_bytes);
    let hsk: CaCertificate =
        bincode::deserialize_from(&mut cursor).context("failed to decode CSV HSK certificate")?;
    let cek: CsvCertificate =
        bincode::deserialize_from(&mut cursor).context("failed to decode CSV CEK certificate")?;
    Ok((hsk, cek))
}

pub(crate) fn verify_certificate_chain(
    report: &AttestationReport,
    resolved_chain: &ResolvedCertificateChain,
) -> Result<()> {
    let hrk: CaCertificate =
        bincode::deserialize(HRK).context("failed to decode embedded CSV HRK certificate")?;
    verify_ca_certificate(&hrk, &hrk).context("CSV HRK self-signature validation failed")?;
    verify_ca_certificate(&hrk, &resolved_chain.hsk)
        .context("CSV HSK signature validation failed")?;
    verify_csv_certificate_with_ca(&resolved_chain.hsk, &resolved_chain.cek)
        .context("CSV CEK signature validation failed")?;
    verify_csv_certificate_with_csv(&resolved_chain.cek, &resolved_chain.pek)
        .context("CSV PEK signature validation failed")?;
    verify_report_signature(&resolved_chain.pek, report)
        .context("CSV attestation report signature validation failed")?;
    Ok(())
}

fn verify_ca_certificate(signer: &CaCertificate, signed: &CaCertificate) -> Result<()> {
    let message =
        bincode::serialize(&signed.body).context("failed to encode CA certificate body")?;
    verify_sm2_signature(
        &signer.body.pubkey,
        &signer.body.user_id[..signer.body.uid_size as usize],
        &message,
        &signed.signature,
    )
}

fn verify_csv_certificate_with_ca(signer: &CaCertificate, signed: &CsvCertificate) -> Result<()> {
    let message =
        bincode::serialize(&signed.body).context("failed to encode CSV certificate body")?;
    for slot in signed.sigs.iter() {
        if slot.is_empty() {
            continue;
        }
        if verify_sm2_signature(
            &signer.body.pubkey,
            &signer.body.user_id[..signer.body.uid_size as usize],
            &message,
            &slot.signature,
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    bail!("no valid CSV certificate signature matched the HSK public key")
}

fn verify_csv_certificate_with_csv(signer: &CsvCertificate, signed: &CsvCertificate) -> Result<()> {
    let message =
        bincode::serialize(&signed.body).context("failed to encode CSV certificate body")?;
    for slot in signed.sigs.iter() {
        if slot.is_empty() {
            continue;
        }
        if verify_sm2_signature(
            &signer.body.data.pubkey.key,
            &signer.body.data.user_id[..signer.body.data.uid_size as usize],
            &message,
            &slot.signature,
        )
        .is_ok()
        {
            return Ok(());
        }
    }

    bail!("no valid CSV certificate signature matched the CEK public key")
}

fn verify_report_signature(pek: &CsvCertificate, report: &AttestationReport) -> Result<()> {
    let tee_info = report.tee_info();
    verify_sm2_signature(
        &pek.body.data.pubkey.key,
        &pek.body.data.user_id[..pek.body.data.uid_size as usize],
        &tee_info.signed_bytes(),
        tee_info.signature(),
    )
}

fn verify_sm2_signature(
    pubkey: &PubKey,
    uid: &[u8],
    message: &[u8],
    signature: &RawEcdsaSignature,
) -> Result<()> {
    let signature_der = raw_signature_to_der(signature)?;
    sm2_verify(pubkey, &signature_der, uid, message).context("SM2 signature verification failed")
}

fn sm2_verify(pubkey: &PubKey, signature_der: &[u8], uid: &[u8], message: &[u8]) -> Result<()> {
    let key_size = pubkey.g.size()?;
    let x = pubkey.x[..key_size]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    let y = pubkey.y[..key_size]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();

    unsafe {
        let ec_key = EC_KEY_new_by_curve_name(NID_sm2);
        if ec_key.is_null() {
            bail!("failed to allocate SM2 key");
        }
        let x_bn = BN_bin2bn(
            x.as_ptr() as *const c_uchar,
            key_size as c_int,
            ptr::null_mut(),
        );
        let y_bn = BN_bin2bn(
            y.as_ptr() as *const c_uchar,
            key_size as c_int,
            ptr::null_mut(),
        );
        if x_bn.is_null() || y_bn.is_null() {
            EC_KEY_free(ec_key);
            bail!("failed to decode SM2 public key coordinates");
        }
        if EC_KEY_set_public_key_affine_coordinates(ec_key, x_bn, y_bn) != 1 {
            EC_KEY_free(ec_key);
            bail!("failed to set SM2 public key coordinates");
        }

        let pkey = EVP_PKEY_new();
        if pkey.is_null() {
            EC_KEY_free(ec_key);
            bail!("failed to allocate EVP_PKEY");
        }
        if EVP_PKEY_assign(pkey, EVP_PKEY_SM2, ec_key as *mut c_void) <= 0 {
            EVP_PKEY_free(pkey);
            bail!("failed to assign SM2 key to EVP_PKEY");
        }

        let md_ctx = EVP_MD_CTX_new();
        let pkey_ctx = EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if md_ctx.is_null() || pkey_ctx.is_null() {
            if !pkey_ctx.is_null() {
                EVP_PKEY_CTX_free(pkey_ctx);
            }
            if !md_ctx.is_null() {
                EVP_MD_CTX_free(md_ctx);
            }
            EVP_PKEY_free(pkey);
            bail!("failed to allocate SM2 verification context");
        }

        if evp_pkey_ctx_set1_id(pkey_ctx, uid.as_ptr() as *const c_void, uid.len() as c_int)
            <= 0
        {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            bail!("failed to set SM2 signer identity");
        }
        EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);
        if EVP_DigestVerifyInit(md_ctx, ptr::null_mut(), EVP_sm3(), ptr::null_mut(), pkey) <= 0 {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            bail!("failed to initialize SM2 verification");
        }
        if EVP_DigestVerifyUpdate(md_ctx, message.as_ptr() as *const c_void, message.len()) <= 0 {
            EVP_PKEY_CTX_free(pkey_ctx);
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            bail!("failed to update SM2 verification");
        }
        let verify_ok = EVP_DigestVerifyFinal(md_ctx, signature_der.as_ptr(), signature_der.len());
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);

        if verify_ok != 1 {
            bail!("SM2 signature verification returned failure");
        }
    }

    Ok(())
}

fn raw_signature_to_der(signature: &RawEcdsaSignature) -> Result<Vec<u8>> {
    let r = bignum_from_le(&signature.r).context("failed to decode signature R component")?;
    let s = bignum_from_le(&signature.s).context("failed to decode signature S component")?;
    Ok(ecdsa::EcdsaSig::from_private_components(r, s)?.to_der()?)
}

fn bignum_from_le(bytes: &[u8]) -> Result<bn::BigNum> {
    let mut be = bytes.to_vec();
    be.reverse();
    Ok(bn::BigNum::from_slice(&be)?)
}

fn xor_with_anonce(data: &[u8], anonce: u32) -> Vec<u8> {
    let tweak = anonce.to_le_bytes();
    data.iter()
        .enumerate()
        .map(|(index, byte)| byte ^ tweak[index % tweak.len()])
        .collect()
}

pub(crate) fn trim_null_terminated(bytes: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes)?
        .trim_end_matches('\0')
        .to_string())
}

pub(crate) fn policy_to_json(policy: GuestPolicy) -> Result<String> {
    Ok(serde_json::to_string(&json!({
        "nodbg": policy.nodbg(),
        "noks": policy.noks(),
        "es": policy.es(),
        "nosend": policy.nosend(),
        "domain": policy.domain(),
        "csv": policy.csv(),
        "csv3": policy.csv3(),
        "asid_reuse": policy.asid_reuse(),
        "hsk_version": policy.hsk_version(),
        "cek_version": policy.cek_version(),
        "api_major": policy.api_major(),
        "api_minor": policy.api_minor(),
    }))?)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!("hex nibble out of range"),
    }
}
