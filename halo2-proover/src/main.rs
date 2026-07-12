//! DarkDex W=128 ZK proof generator (Hermez-anchored KZG SRS).
//!
//! Loads the Hermez Perpetual Powers of Tau K=20 ceremony (downloading on
//! first run), downsizes to K=19, then generates a proof against a fixture
//! JSON provided on the command line. Output is a JSON object with `proof` +
//! `pub_inputs_hex` fields ready to feed the TVM `ZKHALO2VERIFY` instruction.

use clap::Parser;
use halo2_proover::Prover;
use std::fs;
use std::path::PathBuf;
use std::process;

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
}

fn main() {
    let args = Args::parse();

    let fixture_json = fs::read_to_string(&args.fixture).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", args.fixture.display());
        process::exit(1);
    });

    let mut prover = Prover::new_with_hermez(Some(&args.cache_dir)).unwrap_or_else(|e| {
        eprintln!("Prover init (Hermez) failed: {e}");
        process::exit(1);
    });

    match prover.generate_proof(&fixture_json) {
        Ok(output) => println!("{}", serde_json::to_string(&output).unwrap()),
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}
