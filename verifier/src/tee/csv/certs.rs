use anyhow::{Context, Result, bail};
use libc::{c_int, c_uchar, c_void};
use openssl::{bn, ecdsa};
use openssl_sys::*;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::Cursor;
use std::ptr;

use super::evidence::AttestationReport;

const HRK: &[u8] = include_bytes!("../../../../test_certs/hrk.cert");

unsafe extern "C" {
    fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, sctx: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_CTX_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, len: c_int) -> c_int;
}

#[allow(non_snake_case)]
unsafe fn evp_pkey_ctx_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, id_len: c_int) -> c_int {
    unsafe { EVP_PKEY_CTX_set1_id(ctx, id, id_len) }
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
pub(crate) struct RawEcdsaSignature {
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

pub(crate) fn decode_hsk_cek_bundle(cert_bytes: &[u8]) -> Result<(CaCertificate, CsvCertificate)> {
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

        if evp_pkey_ctx_set1_id(pkey_ctx, uid.as_ptr() as *const c_void, uid.len() as c_int) <= 0 {
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
