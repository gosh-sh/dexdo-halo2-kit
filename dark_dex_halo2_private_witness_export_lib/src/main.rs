//! dex_data_exporter — thin CLI wrapper around the
//! `dark_dex_halo2_private_witness_export_lib::make_private_witness_with_anchor`
//! library entry point.

use std::time::Duration;

use clap::Parser;
use dark_dex_halo2_private_witness_export_lib::anchor::AnchorLayerMode;
use dark_dex_halo2_private_witness_export_lib::anchor::AnchorOptions;
use dark_dex_halo2_private_witness_export_lib::anchor::WaitOptions;
use dark_dex_halo2_private_witness_export_lib::make_private_witness_with_anchor;
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

    /// History layer the proof is anchored to: 1 (the block tree, default),
    /// 2, ... up to 12, or `auto` for the highest layer the chain has already
    /// produced. RootPN's `layerNumber` must be the same number. The node
    /// accepts an L1 root for ~43 s to ~91 min after it is published, an L2
    /// root for ~91 min to ~8 days.
    #[arg(long, value_name = "LAYER")]
    anchor_layer: Option<AnchorLayerMode>,

    /// Legacy alias: `--max-layers N` is `--anchor-layer N+1` (N chain steps
    /// above L1). Giving both with different layers is an error.
    #[arg(long)]
    max_layers: Option<u32>,

    /// Poll until the anchor block is produced instead of failing.
    #[arg(long)]
    wait_for_anchor: bool,

    /// With --wait-for-anchor: give up after this many seconds.
    #[arg(long, value_name = "SECONDS", default_value_t = 7200)]
    wait_timeout: u64,

    /// With --wait-for-anchor: seconds between polls.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    wait_poll_interval: u64,

    /// Write the fixture even if the node has already evicted the anchor root.
    /// Only for offline fixtures: the chain rejects such a proof.
    #[arg(long)]
    allow_expired: bool,
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

    let layer = match (cli.anchor_layer, cli.max_layers) {
        (Some(layer), _) => layer,
        (None, Some(steps)) => AnchorLayerMode::from_max_layers(Some(steps)),
        (None, None) => AnchorLayerMode::default(),
    };
    let anchor = AnchorOptions {
        layer,
        wait: cli.wait_for_anchor.then(|| WaitOptions {
            timeout: Duration::from_secs(cli.wait_timeout),
            poll_interval: Duration::from_secs(cli.wait_poll_interval),
        }),
        allow_expired: cli.allow_expired,
    };

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

    let json_str = make_private_witness_with_anchor(&params, &anchor).await?;
    println!("{}", json_str);

    Ok(())
}
