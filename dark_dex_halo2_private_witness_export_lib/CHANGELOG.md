# Changelog

All notable changes to `dark_dex_halo2_private_witness_export_lib` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
uses [Semantic Versioning](https://semver.org/). Release tags are named
`dark_dex_halo2_private_witness_export_lib-v<version>`.

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

[0.2.0]: https://github.com/gosh-sh/dexdo-halo2-kit/releases/tag/dark_dex_halo2_private_witness_export_lib-v0.2.0
