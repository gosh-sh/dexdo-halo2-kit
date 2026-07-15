# halo2-proover

ZK proof generator for the DarkDex circuit (**W=128**, `HISTORY_PROOF_WINDOW_SIZE = 128`).

Two SRS paths — **use Hermez.**

## Hermez (secure, default)

The Perpetual Powers of Tau K=20 ceremony (`powersOfTau28_hez_final_20.ptau`,
raw-SRS SHA-256 `80394564e2598883dbb5d7d61630287f34e29cdd806d7ef74f68acc6bffeb608`).
Same SRS anchor as production tvm-sdk / on-chain `USDCBridge.sol` — proofs
produced here verify against `DARK_DEX_W128_VK_BYTES` in
`tvm_vm/src/executor/zk_halo2_utils.rs`.

On first run the ptau is downloaded to `~/.cache/halo2-kzg-srs/` and its SHA-256
anchor is checked before use.

`Prover::new_with_hermez(cache_dir)` loads the SRS;
`Prover::generate_proof(fixture_json)` produces a proof against the supplied
fixture JSON (see `DexFixtureJson` schema).

Exemplary call (from `halo2-proover/`):

```
cargo run --release --bin halo2-proover -- dex_fixture_synth_L1.json
```

(`--bin halo2-proover` selects this crate's main prover binary — the crate
also ships a `dump_synthetic_fixtures` bin, see below.)

Reads the synthetic W=128 fixture, runs Hermez keygen (first call only — PK +
break_points cached to `--cache-dir`, default `.`), then proves. Output:

```json
{
  "proof": "<~1.7 kB hex — feed to ZKHALO2VERIFY>",
  "pub_inputs_hex": "<320 hex chars = 5 × 32-byte LE Fr>",
  "deposit_identifier_hash": "<32-byte LE Fr>",
  "final_layer_historical_hash_root": "<32-byte LE Fr>",
  "voucher_nominal": "<32-byte LE Fr>",
  "token_type": "<32-byte LE Fr>",
  "ephemeral_pubkey": "<32-byte LE Fr>"
}
```

Given the same fixture, output is bit-reproducible. Feed `proof` +
`pub_inputs_hex` into the TVM `ZKHALO2VERIFY` instruction.

### Included fixtures

`dex_fixture_synth_L{0,1,2,11}.json` — synthetic W=128 fixtures at chain
lengths 0, 1, 2, and 11 (`MAX_CHAIN_LEN`). All derived from
`../dex-halo2-circuit/vouchers.txt[0]` + `seed = 99` via `W128Fixture::synth`.
Sibling counts match production tree geometry: events depth 7, block-tree
depth 8, per-chain-link depth 8. To regenerate (e.g. after a circuit-shape
change):

```
cargo run --release --bin dump_synthetic_fixtures
```

## Legacy `gen_srs` (insecure, historical only)

`Prover::new()` loads a self-generated `gen_srs(19)` SRS whose trapdoor `s` is
knowable. Proofs produced this way **do NOT verify against production tvm-sdk
or USDCBridge**. Kept only for backward-compat reproduction of pre-Hermez
behavior — do not use for anything real.
