use anyhow::{Context, Result, bail};
use bitfield::bitfield;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use serde_json::{Value, json};

use super::certs::{CertificateChain, RawEcdsaSignature};

const ATTESTATION_EXT_MAGIC: [u8; 16] = *b"ATTESTATION_EXT\0";
const CSV_RTMR_REG_SIZE: usize = 32;

pub(crate) struct CsvEvidence {
    pub evidence: Box<TrusteeCsvEvidence>,
    pub raw: Value,
}

#[derive(Deserialize)]
pub(crate) struct TrusteeCsvEvidence {
    pub attestation_report: AttestationReportWrapper,
    pub cert_chain: CertificateChain,
    pub serial_number: Vec<u8>,
    #[serde(default)]
    pub cc_eventlog: Option<String>,
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

    pub(crate) fn signature(&self) -> &RawEcdsaSignature {
        match self {
            Self::V1(tee_info) => &tee_info.sig,
            Self::V2(tee_info) => &tee_info.sig,
        }
    }

    pub(crate) fn signed_bytes(&self) -> Vec<u8> {
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

pub(crate) fn parse_evidence(raw_evidence: &[u8]) -> Result<CsvEvidence> {
    let value: Value = serde_json::from_slice(raw_evidence)?;
    if value.get("attestation_report").is_none() {
        bail!("CSV evidence must contain attestation_report (trustee-style)");
    }
    Ok(CsvEvidence {
        evidence: Box::new(
            serde_json::from_value(value.clone())
                .context("failed to parse trustee-style CSV evidence")?,
        ),
        raw: value,
    })
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
