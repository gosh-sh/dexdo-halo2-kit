//! Local re-export of the Poseidon BN254 parameter set and native hash.
//!
//! The single source of truth lives in
//! [`gosh_dense_balanced_tree`](https://github.com/gosh-sh/gosh-halo2-crypto-lib).
//! This module just preserves the legacy `dex_halo2_circuit::poseidon::*` path
//! that existing call-sites (the in-circuit gadgets in
//! [`crate::dark_dex_circuit_new`] / [`crate::multi_hop_proof`], the
//! `sk-commit-tool` binary, and the integration tests) already import.
//!
//! If the Poseidon parameter set ever changes, update it in
//! `gosh-halo2-crypto-lib::dense-balanced-tree` and the change will flow here
//! automatically.

pub use gosh_dense_balanced_tree::{poseidon_hash_native as poseidon_hash, R_F, R_P, RATE, T};
