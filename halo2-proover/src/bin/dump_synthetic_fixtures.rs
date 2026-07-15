//! Regenerate the four `dex_fixture_synth_L{0,1,2,11}.json` files in the
//! parent halo2-proover crate directory.
//!
//! Reads `../dex-halo2-circuit/vouchers.txt` for the voucher BOC. Deterministic
//! given `DEFAULT_SYNTH_SEED`. No SRS / keygen work — just fixture synthesis
//! + JSON serialization; runs in a second or two.
//!
//! Re-run after any change to `W128Fixture::synth` / `build_dense_chain` /
//! `HISTORY_PROOF_WINDOW_SIZE` / `BLOCK_TREE_LEAVES`.

use halo2_proover::{dump_synthetic_fixture_json, DEFAULT_SYNTH_SEED};
use std::fs;
use std::path::PathBuf;

const CHAIN_LENS: [usize; 4] = [0, 1, 2, 11];

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // `W128Fixture::synth` reads `vouchers.txt` from CWD; live in
    // ../dex-halo2-circuit/, chdir there before synth.
    let vouchers_dir = manifest_dir
        .parent()
        .expect("CARGO_MANIFEST_DIR has no parent")
        .join("dex-halo2-circuit");
    std::env::set_current_dir(&vouchers_dir).unwrap_or_else(|e| {
        panic!("chdir to {} failed: {e}", vouchers_dir.display())
    });

    for chain_len in CHAIN_LENS {
        let json = dump_synthetic_fixture_json(chain_len, DEFAULT_SYNTH_SEED)
            .unwrap_or_else(|e| panic!("dump_synthetic_fixture_json(L{chain_len}): {e}"));
        let path = manifest_dir.join(format!("dex_fixture_synth_L{chain_len}.json"));
        fs::write(&path, &json).unwrap();
        eprintln!("Wrote {} ({} bytes)", path.display(), json.len());
    }
}
