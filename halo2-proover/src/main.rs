//! DarkDex W=128 ZK proof generator (Hermez-anchored KZG SRS).
//!
//! Loads the Hermez Perpetual Powers of Tau K=20 ceremony (downloading on
//! first run), downsizes to K=19, then generates a proof against a fixture
//! JSON provided on the command line. Output is a JSON object with `proof` +
//! `pub_inputs_hex` fields ready to feed the TVM `ZKHALO2VERIFY` instruction,
//! plus `final_layer_number` (RootPN's `layerNumber`) and the anchor block
//! heights recorded in the fixture.

use clap::Parser;
use halo2_proover::{fixture_anchor_from_json, Prover, MAX_ANCHOR_LAYER};
use std::fs;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

/// `--anchor-layer` value: a layer number or `auto`.
#[derive(Clone, Copy, Debug)]
enum AnchorLayerArg {
    Layer(u32),
    Auto,
}

impl FromStr for AnchorLayerArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        match s.parse::<u32>() {
            Ok(layer) if (1..=MAX_ANCHOR_LAYER).contains(&layer) => Ok(Self::Layer(layer)),
            _ => Err(format!(
                "expected 1..={MAX_ANCHOR_LAYER} or `auto`, got `{s}`"
            )),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "DarkDex W=128 ZK proof generator — Hermez-anchored KZG SRS"
)]
struct Args {
    /// Path to fixture JSON (`DexFixtureJson` schema — see
    /// `dex_fixture_synth_L{0,1,2,11}.json` in this crate for W=128 examples).
    fixture: PathBuf,

    /// Directory for PK / break_points cache (reuses previous keygen work).
    #[arg(long, default_value = ".")]
    cache_dir: PathBuf,

    /// History layer the fixture must be anchored to, i.e. RootPN's
    /// `layerNumber`: 1 (default), 2, ... up to 12, or `auto` to take the
    /// fixture's own. A fixture anchored to another layer, or whose declared
    /// root differs from the one the proof would expose, is refused before
    /// proving.
    #[arg(long, value_name = "LAYER", default_value = "1")]
    anchor_layer: AnchorLayerArg,
}

fn main() {
    let args = Args::parse();

    let fixture_json = fs::read_to_string(&args.fixture).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", args.fixture.display());
        process::exit(1);
    });

    let expected_layer = match args.anchor_layer {
        AnchorLayerArg::Layer(layer) => Some(layer),
        AnchorLayerArg::Auto => None,
    };
    // Refuse a mismatched fixture before the SRS download and keygen.
    if let Err(e) = fixture_anchor_from_json(&fixture_json, expected_layer) {
        eprintln!("Error: {e}");
        process::exit(1);
    }

    // let mut prover = Prover::new_with_hermez(Some(&args.cache_dir)).unwrap_or_else(|e| {
    //     eprintln!("Prover init (Hermez) failed: {e}");
    //     process::exit(1);
    // });

    let mut prover = Prover::new_with_srs_from_url(None, Some(&args.cache_dir))
        .unwrap_or_else(|e| {
            eprintln!("Prover init (SRS from URL) failed: {e}");
            process::exit(1);
        });

    match prover.generate_proof_anchored(&fixture_json, expected_layer) {
        Ok(output) => println!("{}", serde_json::to_string(&output).unwrap()),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
