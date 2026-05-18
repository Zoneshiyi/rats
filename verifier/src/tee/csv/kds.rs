use anyhow::{Context, Result, bail};
use reqwest::StatusCode;

use crate::config;

use super::certs::{
    CertificateChain, CertificateChainSource, ResolvedCertificateChain, decode_hsk_cek_bundle,
};

const HSK_CEK_FILENAME: &str = "hsk_cek.cert";

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
