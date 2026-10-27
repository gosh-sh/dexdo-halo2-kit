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
| [`sk-commit-tool/`](sk-commit-tool) | Tiny CLI that takes a 32-byte `sk_u` hex and prints its Poseidon commitment `poseidon(sk_u, 0)` — the same `sk_u_commit` the circuit binds in `deposit_identifier_hash`. |

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
   proof bytes together with the public-input bytes as JSON. It takes the
   anchor layer from the fixture and prints it as `final_layer_number`, the
   `layerNumber` RootPN expects.
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

The layer of root 1 is not a public input. RootPN takes it as the
`layerNumber` argument, which the prover prints as `final_layer_number`.

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

A handful of synthetic fixtures live in `halo2-proover/` so the prover can be
exercised without standing up a node:

```bash
cd halo2-proover
cargo run --release -- dex_fixture_synth_L0.json
```

The `_L<n>` suffix counts chain steps, so `dex_fixture_synth_L1.json` is
anchored to layer 2 and the prover reports `"final_layer_number": 2` for it.

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

Pass either `--block-height` or `--block-id`. The exporter selects the tracked
message matching the representation hash of `--event-boc`; an invalid BOC or a
message absent from the block is an error.

### Choosing the anchor layer

The anchor layer is chosen here, in the exporter, and nowhere else. Without a
flag the proof is anchored to the layer-1 (block tree) root:

| Exporter flag | Anchored to | Chain steps | RootPN `layerNumber` |
| --- | --- | --- | --- |
| none, or `--anchor-layer 1` | L1 root (block tree) | 0 | 1 |
| `--anchor-layer 2` | L2 root | 1 | 2 |
| `--anchor-layer N`, up to 12 | L(N) root | N − 1 | N |
| `--anchor-layer auto` | highest layer the chain has already produced | varies | the fixture's `final_layer_number` |

`--max-layers N` is the older spelling of `--anchor-layer N+1`. The fixture
records the layer as `final_layer_number`. The prover reads it from there and
needs no flag; its own `--anchor-layer N` only adds a check that the fixture is
anchored to layer N.

The node accepts each layer root only for a limited time. At ~3 blocks/s an L1
root is accepted for ~43 s to ~91 min after it is published, and an L2 root for
~91 min to ~8 days, so a voucher claimed later needs L2. The L(N) root that
covers the event is published by the block at the next multiple of 128^N above
the event's height, so an L2 root appears up to ~91 min after the event. Before
it writes the fixture, the exporter checks against the node:

- **The anchor block is not produced yet.** It fails right away, or with
  `--wait-for-anchor` polls until the block appears (`--wait-timeout`, default
  7200 s; `--wait-poll-interval`, default 10 s).
- **The node has already evicted the root.** It fails and suggests the next
  layer. `--allow-expired` writes the fixture anyway, for offline tests only:
  the chain rejects such a proof.
- **The rebuilt root differs from the node's.** It fails, and no fixture is
  written.

The fixture also records `event_block_height`, `anchor_block_height` and
`anchor_expires_at_height`, the first height at which the node no longer
accepts the root.

### Full L2 run

With the binaries built by `cargo build --release` (in `target/release/`):

1. Export, anchored to L2. `--wait-for-anchor` waits for the L2 root if it is
   not published yet:

   ```bash
   dex_data_exporter --network http://127.0.0.1:80 --block-id <block id> \
     --event-boc <base64 BOC> --sk-u <hex sk_u> --ephemeral-pubkey <hex pubkey> \
     --output dex_fixture.json --anchor-layer 2 --wait-for-anchor
   ```

2. Prove. No flag is needed, because the layer comes from the fixture:

   ```bash
   halo2-proover dex_fixture.json > proof.json
   ```

3. Call RootPN `deployPrivateNote` with the values from `proof.json`, passing
   its `final_layer_number` (here `2`) as `layerNumber`. RootPN checks the root
   with `gosh.check_layer_hash(finalLayerHistoricalHashRoot, layerNumber)`.

For L1, drop `--anchor-layer 2`; everything else stays the same.

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
