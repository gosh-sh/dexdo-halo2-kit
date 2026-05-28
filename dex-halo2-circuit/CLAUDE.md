# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Halo2 zero-knowledge circuit for the GOSH Dark DEX. It proves correctness of TVM (TON VM) event BOC (Bag-of-Cells) tree verification and extracts event fields (sk_u_commit, voucher_nominal, token_type) without revealing the full event, producing a Poseidon hash commitment as the public output.

## Build & Test Commands

```bash
# Build (requires nightly Rust — specified in rust-toolchain)
cargo build
cargo build --release

# Run all tests
cargo test -- --nocapture

# Run specific test
cargo test test_dark_dex_circuit_positive -- --nocapture
cargo test test_dark_dex_circuit_real_proof -- --nocapture

# Decode a BOC file with tvm-cli
./tvm-cli decode msg --abi RootPN.abi.json event.boc
```

## Architecture

### Circuit Pipeline (all inside base circuit eDSL)

1. **SHA-256 Verification** — Assigns preimage bytes as witnesses, hashes them via `gosh-sha256-chip::Sha256Chip::digest_bytes()` (pure eDSL, no custom gates), then constrains root's embedded child hash bytes == child's SHA-256 output.

2. **Field Extraction** — Slices child preimage bytes directly (already assigned and range-checked by SHA-256 chip) to extract three event fields:
   - `sk_u_commit`: bytes 6–37 (32 bytes, LE Fr)
   - `voucher_nominal`: bytes 38–69 (32 bytes, BE)
   - `token_type`: bytes 70–73 (4 bytes, BE)

3. **Poseidon Commitment** — Computes public output = `Poseidon(voucher_nominal, token_type, sk_u, sk_u_commit)` via halo2-base's `PoseidonHasher`.

4. **Dense Tree Verification** — Root SHA-256 hash bytes packed to leaf_fr, verified through a chain of dense balanced Merkle tree proofs.

### Key Modules

| Module | Purpose |
|--------|---------|
| `dark_dex_circuit_new` | Main circuit (`DarkDexCircuitNew`) — orchestrates all phases, implements `Circuit<Fr>` |
| `boc_helper` | TVM cell serialization; `BocFlattenData` struct; `serialize_cells_tree_root_first()` BFS traversal |
| `chips/byte_decomposition` | `decompose_fr_to_bytes`, `pack_bytes_to_fr`, `assert_bytes_zero_from` |
| `chips/dense_tree` | Dense balanced tree proof verification and chain verification |
| `circuit_helper` | `fill_byte_range_table()` (0–255 lookup), `sha256_pad()` |
| `poseidon` | Thin wrapper over pse-poseidon; constants T=3, RATE=2, R_F=8, R_P=57 |

### Keygen vs Prove Paths

- **Keygen:** `DarkDexCircuitNew::new()` → `keygen_vk()` / `keygen_pk()` → extract `break_points`
- **Prove:** `DarkDexCircuitNew::new_for_proving(break_points)` → `gen_proof_with_instances()`

The `synthesize` method resets the base circuit builder on each call to avoid accumulating gates across keygen_vk and keygen_pk invocations.

## Circuit Parameters

- K = 14 (2^14 = 16384 rows)
- 110 advice columns, 8 lookup advice columns, 2 fixed columns, 1 instance column
- lookup_bits = 13
- Field: BN256 Fr (254-bit prime)

## Key Dependencies

- **gosh-sha256-chip** (path dependency `../gosh-halo2-crypto-lib/sha256-chip`) — eDSL SHA-256
- **halo2-base, halo2-ecc** from `gosh-sh/halo2-lib-zkevm-sha256-and-bls12-381` fork, branch `main`
- **tvm_types, tvm_block** from `tvmlabs/tvm-sdk`
- A `[patch.crates-io]` section redirects halo2-base to avoid duplicate versions.

## BOC cell_repr_data Layout

```
d1 (1B): level_mask(3b) | exotic(1b) | refs_count(3b)
d2 (1B): (bit_len/8)<<1 | (bit_len%8!=0)
data (N bytes): cell payload
depths (refs_count * 2B): child depths, big-endian u16
hashes (refs_count * 32B): child repr-hashes (SHA-256)
```
