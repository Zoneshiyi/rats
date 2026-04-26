use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use protos::Mode;

use crate::config::RelyingPartyConfig;
use crate::service::WorkflowResult;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliArgs {
    pub addr: String,
    pub mode: Mode,
    pub nonce: String,
    pub nonce_b64: Option<String>,
}

impl CliArgs {
    pub fn parse(file_config: RelyingPartyConfig) -> Result<Self> {
        Self::parse_from(file_config, std::env::args().skip(1))
    }

    pub fn parse_from<I, S>(file_config: RelyingPartyConfig, args: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut addr = file_config.addr;
        let mut mode = parse_mode(&file_config.mode)?;
        let mut nonce = file_config.nonce;
        let mut nonce_b64 = None;

        let mut iter = args.into_iter().map(Into::into).peekable();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--addr" => {
                    addr = iter.next().ok_or_else(|| anyhow!("missing --addr"))?;
                }
                "--mode" => {
                    let value = iter.next().ok_or_else(|| anyhow!("missing --mode"))?;
                    mode = parse_mode(&value)?;
                }
                "--nonce" => {
                    nonce = iter.next().ok_or_else(|| anyhow!("missing --nonce"))?;
                }
                "--nonce-b64" => {
                    nonce_b64 = Some(iter.next().ok_or_else(|| anyhow!("missing --nonce-b64"))?);
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                _ => bail!("unknown argument: {arg}"),
            }
        }

        if !nonce.is_empty() && nonce_b64.is_some() {
            bail!("--nonce and --nonce-b64 cannot be used together");
        }

        Ok(Self {
            addr,
            mode,
            nonce,
            nonce_b64,
        })
    }

    pub fn requested_nonce(&self) -> Result<Vec<u8>> {
        if let Some(encoded) = &self.nonce_b64 {
            return URL_SAFE_NO_PAD
                .decode(encoded)
                .or_else(|_| URL_SAFE.decode(encoded))
                .map_err(|err| anyhow!("invalid --nonce-b64: {err}"));
        }
        Ok(if self.nonce.is_empty() {
            Vec::new()
        } else {
            self.nonce.as_bytes().to_vec()
        })
    }
}

pub fn parse_mode(raw: &str) -> Result<Mode> {
    match raw.to_ascii_lowercase().as_str() {
        "passport" => Ok(Mode::Passport),
        "background" | "background-check" | "background_check" => Ok(Mode::BackgroundCheck),
        "mix" => Ok(Mode::Mix),
        _ => bail!("unsupported mode: {raw}"),
    }
}

pub fn decode_jwt_payload(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;

    URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

pub fn format_result(result: &WorkflowResult) -> Result<String> {
    let token_text = String::from_utf8(result.final_token.clone())?;
    let mut rendered = format!(
        "mode: {:?}\nfinal_attestation_token:\n{}\n",
        result.mode as i32, token_text
    );

    if let Some(payload) = decode_jwt_payload(&token_text) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload) {
            rendered.push_str(&format!(
                "\ndecoded_attestation_result:\n{}",
                serde_json::to_string_pretty(&json)?
            ));
        } else {
            rendered.push_str(&format!("\ndecoded_attestation_result:\n{}", payload));
        }
    }

    Ok(rendered)
}

pub fn print_usage() {
    println!("Usage:");
    println!(
        "  relying-party [--addr HOST:PORT] [--mode passport|background-check|mix] [--nonce TEXT|--nonce-b64 BASE64URL]"
    );
    println!("Defaults:");
    println!("  --addr 127.0.0.1:50051");
    println!("  --mode passport");
    println!("  --nonce <empty, verifier generates challenge nonce>");
    println!("  --nonce-b64 <base64url raw nonce/report data for fixture testing>");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RelyingPartyConfig {
        RelyingPartyConfig {
            addr: "127.0.0.1:50051".to_string(),
            mode: "passport".to_string(),
            nonce: String::new(),
        }
    }

    #[test]
    fn parse_mode_accepts_background_alias() -> Result<()> {
        assert_eq!(parse_mode("background-check")?, Mode::BackgroundCheck);
        assert_eq!(parse_mode("background_check")?, Mode::BackgroundCheck);
        Ok(())
    }

    #[test]
    fn cli_args_parse_from_overrides_file_config() -> Result<()> {
        let args = CliArgs::parse_from(
            config(),
            vec![
                "--addr",
                "10.0.0.1:1234",
                "--mode",
                "mix",
                "--nonce",
                "expected",
            ],
        )?;

        assert_eq!(args.addr, "10.0.0.1:1234");
        assert_eq!(args.mode, Mode::Mix);
        assert_eq!(args.nonce, "expected");
        assert_eq!(args.nonce_b64, None);
        Ok(())
    }

    #[test]
    fn cli_args_decodes_base64_nonce() -> Result<()> {
        let args = CliArgs::parse_from(config(), vec!["--nonce-b64", "ZXhwZWN0ZWQ"])?;
        assert_eq!(args.requested_nonce()?, b"expected");
        Ok(())
    }

    #[test]
    fn cli_args_rejects_text_and_base64_nonce_together() {
        let err = CliArgs::parse_from(config(), vec!["--nonce", "a", "--nonce-b64", "Yg"])
            .expect_err("conflicting nonce options should fail");
        assert!(err.to_string().contains("cannot be used together"));
    }

    #[test]
    fn decode_jwt_payload_extracts_middle_segment() {
        let token = "eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJkZW1vIn0.signature";
        assert_eq!(
            decode_jwt_payload(token).as_deref(),
            Some("{\"sub\":\"demo\"}")
        );
    }
}
