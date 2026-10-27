# Changelog

All notable changes to `dark_dex_halo2_private_witness_export_lib` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
uses [Semantic Versioning](https://semver.org/). Release tags are named
`dark_dex_halo2_private_witness_export_lib-v<version>`.

## [0.3.0] - 2026-10-27

### Changed

- `dex_data_exporter` without a layer flag now anchors the proof to layer 1, the
  block-tree root. It used to climb to the highest layer the chain had produced; that is
  now `--anchor-layer auto`. `--max-layers N` stays as an alias for `--anchor-layer N+1`.
- Before it writes a fixture, the exporter checks the anchor against the node. A missing
  anchor block is an error, and so is a root the node has already evicted; the error
  suggests the next layer. The rebuilt root must equal the node's `history_proofs[n]` in
  the anchor block, otherwise no fixture is written.
- `make_private_witness_and_public_data` keeps its signature and its `max_layers` meaning
  (`None` is the highest layer produced), and runs the same checks.

### Added

- `--anchor-layer 1..12|auto` chooses the history layer the proof is anchored to. RootPN's
  `layerNumber` must be the same number, which the fixture records as
  `final_layer_number`. Layer 1 roots are accepted by the node for ~43 s to ~91 min after
  they are published, layer 2 roots for ~91 min to ~8 days.
- `--wait-for-anchor` (with `--wait-timeout` and `--wait-poll-interval`) waits for the
  anchor block instead of failing.
- `--allow-expired` writes a fixture even if the anchor root is already evicted, for
  offline tests only: the chain rejects such a proof.
- Fixture fields `event_block_height`, `anchor_block_height` and
  `anchor_expires_at_height`.
- Library: the `anchor` module (`AnchorLayerMode`, `AnchorOptions`, `WaitOptions`, anchor
  and eviction heights), `make_private_witness_with_anchor`,
  `blockchain::try_query_block_by_height` and `proof::generate_layer_n_proof_at`.
- Integration tests against a simulated chain in `tests/anchor_layers.rs`.

### Fixed

- An event in a block whose height is a multiple of 128^n is anchored to the next
  boundary block. It used to be anchored to its own block, one window too early.

## [0.2.0] - 2026-10-20

### Fixed

- `make_private_witness_and_public_data` selects the tracked external message whose
  representation hash matches `event_boc`. Previously it always took the first tracked
  message in the block, so a block with several tracked messages could produce a fixture
  that mixed routing and Merkle path from a different event (#8, #9).

### Changed

- An `event_boc` that is not valid base64, is not a valid BOC, or whose message is not among
  the block's tracked `ext_out_messages` now returns an error, and no fixture is written.

### Added

- Dependency on `tvm_types` (from `tvmlabs/tvm-sdk`) to decode `event_boc`.
- Integration tests for event selection in `tests/event_selection.rs`.

## [0.1.0]

- Initial release.

[0.3.0]: https://github.com/gosh-sh/dexdo-halo2-kit/releases/tag/dark_dex_halo2_private_witness_export_lib-v0.3.0
[0.2.0]: https://github.com/gosh-sh/dexdo-halo2-kit/releases/tag/dark_dex_halo2_private_witness_export_lib-v0.2.0
