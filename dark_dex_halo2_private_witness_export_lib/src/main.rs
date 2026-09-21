//! dex_data_exporter — CLI wrapper around
//! `dark_dex_halo2_private_witness_export_lib`.
//!
//! Two subcommands:
//! - `dex-final` (default) — original behaviour: fetches one event block,
//!   emits a `DexFixtureJson` for the `DarkDexCircuit` DexFinalProof.
//! - `bundle` — emits BOTH the DexFinal fixture AND a companion
//!   `BundleWitnessJson` for the MultiHopProof snarks. `--path` is the
//!   ordered chain `[X, ..., Y]`; use `--path <bid>` (single entry) for
//!   the t=0 uniformity case.

use clap::{Args, Parser, Subcommand};
use dark_dex_halo2_private_witness_export_lib::{
    make_dex_final_and_bundle_witnesses, make_private_witness_and_public_data, BundleParams,
    ExportParams,
};
use tracing_subscriber::EnvFilter;

/// Arguments shared by every subcommand — they always identify the DEX
/// event and where to write the DexFinal fixture.
#[derive(Args)]
struct DexFinalArgs {
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

    /// Output JSON file path for the DexFinal fixture
    #[arg(long)]
    output: String,

    /// Maximum number of chain layers to collect. When set, this is treated
    /// as a STRICT requirement: the exporter errors out if that layer's data
    /// is not yet available on the chain.
    #[arg(long)]
    max_layers: Option<u32>,
}

impl From<DexFinalArgs> for ExportParams {
    fn from(a: DexFinalArgs) -> Self {
        ExportParams {
            network: a.network,
            block_height: a.block_height,
            block_id: a.block_id,
            event_boc: a.event_boc,
            sk_u: a.sk_u,
            ephemeral_pubkey: a.ephemeral_pubkey,
            output: a.output,
            max_layers: a.max_layers,
        }
    }
}

#[derive(Parser)]
#[command(name = "dex_data_exporter")]
#[command(about = "Export Merkle proof data for DEX circuit testing")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Export the DexFinal fixture only (single-block, no bundle witness).
    DexFinal(DexFinalArgs),

    /// Export the DexFinal fixture AND a companion bundle witness.
    Bundle {
        #[command(flatten)]
        dex_final: DexFinalArgs,

        /// Output JSON file path for the bundle witness.
        #[arg(long)]
        bundle_output: String,

        /// Ordered chain path `[X, ..., Y]` as a comma-separated list of
        /// 32-byte block IDs in hex. For t=0 pass a single entry equal to
        /// the event block (the walker emits 20 inactive padding slots so
        /// the bundle shape matches the multi-thread case).
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        path: Vec<String>,

        /// Optional human-readable description embedded in the bundle
        /// witness JSON.
        #[arg(long)]
        description: Option<String>,
    },
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

    match cli.command {
        Command::DexFinal(args) => run_dex_final(args.into()).await,
        Command::Bundle {
            dex_final,
            bundle_output,
            path,
            description,
        } => {
            let params: ExportParams = dex_final.into();
            let bundle_params = BundleParams {
                bundle_output,
                path_hex: path,
                description,
            };
            let (dex_final_json, _) =
                make_dex_final_and_bundle_witnesses(&params, &bundle_params).await?;
            println!("{}", dex_final_json);
            Ok(())
        }
    }
}

async fn run_dex_final(params: ExportParams) -> anyhow::Result<()> {
    let json_str = make_private_witness_and_public_data(&params).await?;
    println!("{}", json_str);
    Ok(())
}
