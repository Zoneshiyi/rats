use anyhow::{Result, bail};
use attestation_service::RelyingPartyClient;
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use protobuf::Enum;
use protos::attestation_response;
use protos::{ErrorCode, Mode, VerificationResponse};

#[tokio::main]
async fn main() -> Result<()> {
    let args = CliArgs::parse()?;
    let client = RelyingPartyClient::new(args.addr);
    let mode = args.mode;
    let nonce = args.nonce.into_bytes();

    let attestation_response = client.attest(mode, nonce).await?;
    ensure_ok(attestation_response.error_code.enum_value_or_default())?;

    let final_token = match attestation_response.result {
        Some(attestation_response::Result::AttestationToken(token)) => token,
        Some(attestation_response::Result::EvidenceList(list)) => {
            let verification_response = client.verify(list.evidence).await?;
            extract_verification_token(verification_response)?
        }
        None => bail!("missing attestation result"),
        Some(_) => bail!("unsupported attestation result"),
    };

    print_result(mode, &final_token)?;
    Ok(())
}

#[derive(Clone)]
struct CliArgs {
    addr: String,
    mode: Mode,
    nonce: String,
}

impl CliArgs {
    fn parse() -> Result<Self> {
        let mut addr = "127.0.0.1:50051".to_string();
        let mut mode = Mode::MODE_PASSPORT;
        let mut nonce = "demo-nonce".to_string();

        let mut iter = std::env::args().skip(1).peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--addr" => {
                    let value = iter.next().ok_or_else(|| anyhow::anyhow!("missing --addr"))?;
                    addr = value;
                }
                "--mode" => {
                    let value = iter.next().ok_or_else(|| anyhow::anyhow!("missing --mode"))?;
                    mode = parse_mode(&value)?;
                }
                "--nonce" => {
                    let value = iter.next().ok_or_else(|| anyhow::anyhow!("missing --nonce"))?;
                    nonce = value;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => bail!("unknown argument: {arg}"),
            }
        }

        Ok(Self { addr, mode, nonce })
    }
}

fn parse_mode(raw: &str) -> Result<Mode> {
    match raw.to_ascii_lowercase().as_str() {
        "passport" => Ok(Mode::MODE_PASSPORT),
        "background" | "background-check" | "background_check" => Ok(Mode::MODE_BACKGROUND_CHECK),
        "mix" => Ok(Mode::MODE_MIX),
        _ => bail!("unsupported mode: {raw}"),
    }
}

fn extract_verification_token(resp: VerificationResponse) -> Result<Vec<u8>> {
    ensure_ok(resp.error_code.enum_value_or_default())?;
    if resp.attestation_token.is_empty() {
        bail!("verification returned empty token");
    }
    Ok(resp.attestation_token)
}

fn ensure_ok(code: ErrorCode) -> Result<()> {
    if code == ErrorCode::ErrorCode_OK {
        return Ok(());
    }
    bail!("remote call failed with code: {:?}", code.value())
}

fn print_result(mode: Mode, token: &[u8]) -> Result<()> {
    let token_text = String::from_utf8(token.to_vec())?;
    println!("mode: {:?}", mode.value());
    println!("final_attestation_token:\n{}\n", token_text);

    if let Some(payload) = decode_jwt_payload(&token_text) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload) {
            println!(
                "decoded_attestation_result:\n{}",
                serde_json::to_string_pretty(&json)?
            );
        } else {
            println!("decoded_attestation_result:\n{}", payload);
        }
    }
    Ok(())
}

fn decode_jwt_payload(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;

    URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn print_usage() {
    println!("Usage:");
    println!("  relying-party [--addr HOST:PORT] [--mode passport|background-check|mix] [--nonce TEXT]");
    println!("Defaults:");
    println!("  --addr 127.0.0.1:50051");
    println!("  --mode passport");
    println!("  --nonce demo-nonce");
}
