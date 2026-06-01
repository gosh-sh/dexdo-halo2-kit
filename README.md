# dexdo-halo2-kit

Zero-knowledge toolkit for **DEX.DO** — the privacy-preserving exchange that runs
as a plugin to the [Acki Nacki](https://github.com/gosh-sh/acki-nacki) Block
Manager. This workspace contains the halo2 circuit that DEX.DO proofs are
generated against, the prover binary, and the on-chain witness exporter that
collects the data needed to build a proof.

The kit lets a user prove — to a TVM smart contract — that a `voucherGenerated`
event for some `sk_u_commit / voucher_nominal / token_type` was emitted by a
specific account, in a specific block, that is linked all the way to a layer
historical hash root the chain already trusts. The proof reveals only the
voucher nominal, token type, and an ephemeral public key; everything else (the
secret key, the account, the block, the chain of historical-hash roots) stays
private.

## Workspace layout

| Crate | Role |
| --- | --- |
| [`dex-halo2-circuit/`](dex-halo2-circuit) | The halo2 circuit (`DarkDexCircuitNew`) that constrains BOC decoding, Poseidon sk-commit, external-message Merkle proof, block Merkle proof, and the dense chain of historical-hash roots. |
| [`halo2-proover/`](halo2-proover) | Standalone prover. Takes a fixture JSON, runs KZG setup / keygen (with on-disk caches), and emits the proof bytes + public-input bytes ready for the `ZKHALO2VERIFY` TVM instruction. |
| [`dark_dex_halo2_private_witness_export_lib/`](dark_dex_halo2_private_witness_export_lib) | Library + `dex_data_exporter` CLI. Talks to a running Acki Nacki node, walks the layer-0 cycle and layer-N history proofs, and produces the fixture JSON consumed by `halo2-proover`. |

## End-to-end flow

```
   on-chain                  off-chain                        on-chain
┌──────────────┐   query    ┌────────────────────────┐  fixture  ┌────────────┐  proof+inputs  ┌────────────┐
│  Acki Nacki  │ ─────────▶ │ dex_data_exporter      │ ────────▶ │ halo2-     │ ─────────────▶ │   TVM      │
│  node        │            │ (export lib)           │   JSON    │ proover    │                │ contract   │
└──────────────┘            └────────────────────────┘           └────────────┘                │ ZKHALO2-   │
                                                                                                │ VERIFY     │
                                                                                                └────────────┘
```

1. **Export witness.** `dex_data_exporter` pulls the event BOC, the events-tree
   Merkle proof, the block Merkle proof, and the dense chain of layer-N
   historical-hash proofs from a node, and writes a `dex_fixture_*.json` file.
2. **Generate proof.** `halo2-proover <fixture.json>` builds the circuit
   witness, computes / caches the proving and verification keys, and prints the
   proof bytes together with the public-input bytes as JSON.
3. **Verify on chain.** The `proof` and `pub_inputs_hex` fields are passed
   directly to the `ZKHALO2VERIFY` TVM instruction inside the DEX.DO contract.

## Public inputs

The circuit exposes five public field elements (concatenated into
`pub_inputs_hex`):

| # | Name | Meaning |
| - | --- | --- |
| 0 | `deposit_identifier_hash` | Poseidon commitment binding the deposit (private `sk_u`) to the public voucher parameters. |
| 1 | `final_layer_historical_hash_root` | Root that the on-chain `gosh.check_layer_hash` is expected to recognise. |
| 2 | `voucher_nominal` | Voucher amount, revealed. |
| 3 | `token_type` | Token type, revealed. |
| 4 | `ephemeral_pubkey` | Ephemeral pubkey committed to the voucher, revealed. |

## Building

Requires the pinned Rust nightly (see [`rust-toolchain`](rust-toolchain)). The
workspace `Cargo.toml` patches `halo2-base` to the `gosh-sh` fork that ships
sha256 / bls12-381 chips, and `.cargo/config.toml` sets the `tokio_unstable`
cfg flag — both are needed for a clean build.

```bash
# Build everything
cargo build --release

# Run the circuit's MockProver tests
cargo test --release -p dex-halo2-circuit -- --nocapture
```

## Quick start: generating a proof

A handful of pre-collected fixtures live in `halo2-proover/` so the prover can
be exercised without standing up a node:

```bash
cd halo2-proover
cargo run --release -- dex_fixture_live_L1_H277_S0.json
```

The first run performs KZG SRS generation and writes `pk_cache.bin`,
`break_points_cache.bin`, and `vk_cache.bin` into the working directory; later
runs reuse them. Output is a single JSON object with `proof`, `pub_inputs_hex`,
and the individual public-input components — see
[`halo2-proover/README.md`](halo2-proover/README.md) for a full example.

## Quick start: exporting a witness

Run against a reachable Acki Nacki node:

```bash
cargo run --release -p dark_dex_halo2_private_witness_export_lib --bin dex_data_exporter -- \
  --network         http://127.0.0.1:80 \
  --block-height    277 \
  --event-boc       <base64 BOC of the voucherGenerated event> \
  --sk-u            <hex sk_u> \
  --ephemeral-pubkey <hex 32-byte pubkey> \
  --output          dex_fixture.json
```

Pass either `--block-height` or `--block-id`. `--max-layers` makes the layer
collection strict (the exporter errors instead of returning a partial chain).

## Runtime context

`dexdo-halo2-kit` is consumed by [**DEX.DO**](https://github.com/gosh-sh/dexdo),
which itself runs as a plugin to the **Acki Nacki Block Manager**. The Block
Manager is distributed separately under its own license (the Acki Nacki Node
License — BUSL with a two-year change date to AGPL-3.0); see that repository
for current terms.

## License

`dexdo-halo2-kit` is released under the **GNU Affero General Public License v3**
([LICENSE.md](LICENSE.md)). The choice of AGPL is deliberate — every user who
runs a prover built from this code must be able to inspect it, so a closed
fork that serves proofs over the network cannot hide extra witness extraction
or key leakage. See [NOTICE.md](NOTICE.md) for the full rationale.
