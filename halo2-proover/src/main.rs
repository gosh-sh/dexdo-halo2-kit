//! halo2-proover — clap CLI wrapper around the `halo2_proover` library.
//!
//! Three subcommands:
//! - `dex-final <fixture>` — produce a single `DarkDexCircuit` DexFinalProof
//!   from a `DexFixtureJson`. Emits `ProofOutput` JSON on stdout. This is
//!   the legacy behaviour of the pre-clap CLI.
//! - `bundle <bundle_witness>` — produce one DexFinal + `N_BUNDLE` MultiHop
//!   snarks from a `BundleWitnessJson`. Emits `BundleProofsOutput` JSON on
//!   stdout.
//! - `verify-bundle <bundle_output>` — read a previously emitted
//!   `BundleProofsOutput`, run `bundle_verifier::verify_bundle` against the
//!   embedded public instances, and print `OK` (or the rejection reason).

use clap::{Args, Parser, Subcommand};
use halo2_proover::bundle::{verify_bundle_publics, BundleProofsOutput, BundleProver};
use halo2_proover::Prover;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Args)]
struct DexFinalArgs {
    /// Path to the `DexFixtureJson` on disk.
    fixture: PathBuf,

    /// Optional directory for PK/VK/break-points caching. Reused across
    /// invocations to avoid a ~60 s keygen every run.
    #[arg(long, default_value = ".")]
    cache_dir: PathBuf,
}

#[derive(Args)]
struct BundleArgs {
    /// Path to the `BundleWitnessJson` on disk. Its
    /// `dex_final_fixture_path` field is resolved relative to CWD.
    bundle_witness: PathBuf,

    /// Optional cache dir for the DexFinal (K=19) `DarkDexCircuit` keys.
    #[arg(long, default_value = ".")]
    dex_final_cache_dir: PathBuf,

    /// Optional cache dir for the MultiHopProof (K=17) keys. Kept separate
    /// so both PK files can coexist without name collisions.
    #[arg(long, default_value = ".")]
    multi_hop_cache_dir: PathBuf,
}

#[derive(Args)]
struct VerifyBundleArgs {
    /// Path to a previously emitted `BundleProofsOutput` on disk.
    bundle_output: PathBuf,
}

#[derive(Parser)]
#[command(name = "halo2-proover")]
#[command(about = "Halo2 KZG prover for the DarkDex + MultiHopProof bundle")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Produce a single DexFinalProof (legacy behaviour).
    DexFinal(DexFinalArgs),

    /// Produce a full bundle: 1 DexFinal + N_BUNDLE MultiHop snarks.
    Bundle(BundleArgs),

    /// Run `bundle_verifier::verify_bundle` on a previously emitted
    /// `BundleProofsOutput` JSON.
    VerifyBundle(VerifyBundleArgs),
}

fn main() {
    let cli = Cli::parse();

    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::DexFinal(args) => run_dex_final(args),
        Command::Bundle(args) => run_bundle(args),
        Command::VerifyBundle(args) => run_verify_bundle(args),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run_dex_final(args: DexFinalArgs) -> Result<(), Box<dyn std::error::Error>> {
    let fixture_json = fs::read_to_string(&args.fixture)?;
    let mut prover = Prover::new(Some(Path::new(&args.cache_dir)))?;
    let output = prover.generate_proof(&fixture_json)?;
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn run_bundle(args: BundleArgs) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_json = fs::read_to_string(&args.bundle_witness)?;
    let mut prover = BundleProver::new(
        Some(&args.dex_final_cache_dir),
        Some(&args.multi_hop_cache_dir),
    )?;
    let output = prover.generate(&bundle_json)?;

    // Immediate self-verify — catches instance-layout regressions before the
    // caller has a chance to notice on-chain. Same rules `RootPN.sol` runs.
    verify_bundle_publics(&output)?;
    eprintln!("[bundle] self-verify (verify_bundle) OK");

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn run_verify_bundle(args: VerifyBundleArgs) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_json = fs::read_to_string(&args.bundle_output)?;
    let output: BundleProofsOutput = serde_json::from_str(&bundle_json)?;
    verify_bundle_publics(&output)?;
    println!("OK");
    Ok(())
}
