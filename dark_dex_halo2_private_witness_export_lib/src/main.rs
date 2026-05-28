//! dex_data_exporter — thin CLI wrapper around the
//! `dark_dex_halo2_private_witness_export_lib::make_private_witness_and_public_data`
//! library entry point.

use clap::Parser;
use dark_dex_halo2_private_witness_export_lib::make_private_witness_and_public_data;
use dark_dex_halo2_private_witness_export_lib::ExportParams;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "dex_data_exporter")]
#[command(about = "Export Merkle proof data for DEX circuit testing")]
struct Cli {
    /// Network endpoint (e.g. "localhost" or "http://127.0.0.1:80")
    #[arg(long, default_value = "localhost")]
    network: String,

    /// Block height containing the event (use this OR --block-id)
    #[arg(long)]
    block_height: Option<u64>,

    /// Block ID (hash) containing the event (use this OR --block-height)
    #[arg(long)]
    block_id: Option<String>,

    /// Event BOC in base64 encoding
    #[arg(long)]
    event_boc: String,

    /// Secret key sk_u in hex
    #[arg(long)]
    sk_u: String,

    /// Ephemeral public key in hex (32 bytes, the pubkey committed to the voucher)
    #[arg(long)]
    ephemeral_pubkey: String,

    /// Output JSON file path
    #[arg(long)]
    output: String,

    /// Maximum number of chain layers to collect. When set, this is treated as
    /// a STRICT requirement: the exporter errors out if that layer's data is
    /// not yet available on the chain.
    #[arg(long)]
    max_layers: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("dex_data_exporter=info")),
        )
        .init();

    let cli = Cli::parse();

    let params = ExportParams {
        network: cli.network,
        block_height: cli.block_height,
        block_id: cli.block_id,
        event_boc: cli.event_boc,
        sk_u: cli.sk_u,
        ephemeral_pubkey: cli.ephemeral_pubkey,
        output: cli.output,
        max_layers: cli.max_layers,
    };

    let json_str = make_private_witness_and_public_data(&params).await?;
    println!("{}", json_str);

    Ok(())
}
