pub mod block_id_tree;
pub mod boc_helper;
pub mod bundle_verifier;
pub mod dark_dex_circuit;
pub mod dense_merkle_bound;
pub mod voucher_event_helper;
pub mod kzg_source;
pub mod multi_hop_proof;
pub mod multi_hop_witness;
pub mod poseidon_dex_helper;
pub mod salt;

// `test_helpers` is exposed unconditionally so integration tests (under
// `tests/`) and the `gen_hermez_kzg_and_dark_dex_keys` /
// `gen_hermez_kzg_and_multi_hop_keys` bins can reach `synth_chain` /
// `split_into_bundle_snarks` / `build_dex_final_witness` etc. Since
// `dense_balanced_tree` was promoted from dev-dep to main dep, everything
// in this module is now buildable outside of `#[cfg(test)]` — only the
// inline `synth_chain_tests` submodule remains test-gated.
pub mod test_helpers;
