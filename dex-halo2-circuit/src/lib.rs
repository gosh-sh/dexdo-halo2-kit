pub mod block_id_tree;
pub mod boc_helper;
pub mod bundle_verifier;
pub mod dark_dex_circuit;
pub mod voucher_event_helper;
pub mod hop_proof;
pub mod multi_hop_proof;
pub mod multi_hop_witness;
pub mod poseidon_dex_helper;
pub mod salt;

// `test_helpers` is exposed unconditionally so integration tests (under
// `tests/`) can reach `synth_chain` / `split_into_bundle_snarks`. Items
// that depend on the dev-only `dense_balanced_tree` crate are themselves
// `#[cfg(test)]`-gated inside the module.
pub mod test_helpers;