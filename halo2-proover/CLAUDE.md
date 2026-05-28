# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZK proof generator for the new DarkDex circuit from [gosh-sh](https://github.com/gosh-sh/gosh-dark-dex-halo2-new-circuit/tree/finalization_option_1). Uses Halo2 proof system with SHA-256 BOC verification, Poseidon commitments, and dense Merkle tree chain verification on the BN256 curve. Output is designed for use with the `ZKHALO2VERIFY` TVM instruction.

## Build & Run

```bash
cargo build                # debug build (opt-level=3 in dev profile)
cargo build --release      # optimized build

# Generate proof from a fixture JSON file:
cargo run -- <fixture_json_path>
# Example:
cargo run -- ../gosh-dark-dex-halo2-new-circuit/tests/fixtures/dex_fixture_L1_H197_S0.json
```

## Architecture

Single-file project (`src/main.rs`) that wraps the `gosh-dark-dex-halo2-new-circuit` library.

### Pipeline

1. Read + parse fixture JSON (same format as `tests/fixtures/dex_fixture*.json` in the circuit repo)
2. Parse event BOC from base64, flatten via `serialize_cells_tree_root_first`
3. Pad dense chain to `MAX_CHAIN_LEN` with inactive links
4. Compute 5 public instances natively:
   - Instance 0: `deposit_identifier_hash` (Poseidon commitment)
   - Instance 1: `final_layer_historical_hash_root`
   - Instance 2: `voucher_nominal` (Fr)
   - Instance 3: `token_type` (Fr)
   - Instance 4: `ephemeral_pubkey` (Fr)
5. Keygen or load cached PK from `pk_cache.bin` + `break_points_cache.bin`
6. Build `DarkDexCircuitNew::new_for_proving(...)` and generate proof
7. Output JSON to stdout

### Key parameters

- Circuit size `K = 19`
- 4 advice columns, 1 lookup advice column, 1 fixed column, 1 instance column
- lookup_bits = 18
- Field: BN256 `Fr`

### Output JSON format

```json
{
  "proof": "<hex proof bytes>",
  "pub_inputs_hex": "<hex 160 bytes: 5 × 32B LE Fr concatenated>",
  "deposit_identifier_hash": "<hex 32B LE Fr>",
  "final_layer_historical_hash_root": "<hex 32B LE Fr>",
  "voucher_nominal": "<hex 32B LE Fr>",
  "token_type": "<hex 32B LE Fr>",
  "ephemeral_pubkey": "<hex 32B LE Fr>"
}
```

### PK Caching

On first run, keygen is performed and the proving key + break points are cached to `pk_cache.bin` and `break_points_cache.bin`. Subsequent runs load from cache (~30s saved). Delete these files to force re-keygen.

## Key Dependencies

- `gosh-dark-dex-halo2-new-circuit` — local workspace dependency (path = `../dex-halo2-circuit`, package = `dex-halo2-circuit`); provides circuit definition, BOC helper, Poseidon hash
- `gosh-dense-balanced-tree` — dense balanced Merkle tree operations
- `halo2-base` — Halo2 proof system base (axiom version from gosh-sh fork)
- `tvm_types`, `tvm_block` — TVM cell/message deserialization
- `pse-poseidon` — Poseidon hash function

## Rust Edition

Uses Rust edition `2021` with nightly toolchain.
