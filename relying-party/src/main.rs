use anyhow::Result;
use relying_party::config::RelyingPartyConfig;
use relying_party::{
    CliArgs, GrpcAttestationGateway, RelyingPartyApplicationService, format_result,
};

#[tokio::main]
async fn main() -> Result<()> {
    let file_config = RelyingPartyConfig::load()?;
    let args = CliArgs::parse(file_config)?;
    let gateway = GrpcAttestationGateway::connect(args.addr.clone()).await?;
    let mut service = RelyingPartyApplicationService::new(gateway);
    let result = service.run(args).await?;
    println!("{}", format_result(&result)?);
    Ok(())
}
