//! JSON witness shapes for the multi-hop bundle prover (halo2-proover).
//!
//! One [`BundleWitnessJson`] = 1 DexFinal proof witness ([`DexFixtureJson`]
//! from `lib.rs`, referenced by path) + `N_BUNDLE` [`MultiHopSnarkWitnessJson`]
//! entries. Each snark carries `H_HOPS_PER_PROOF` [`HopWitnessJson`] hops.
//!
//! Field names and per-hop shape mirror
//! `dex_halo2_circuit::multi_hop_proof::MultiHopWitness` 1:1 so the prover
//! can `From::from` a JSON hop into the circuit witness type with no
//! translation layer beyond hex decoding.
//!
//! ## Endpoint hex convention
//!
//! `salted_{start,end}_block_id_hex` are LE hex encodings of the Fr scalar
//! (`Fr::to_repr()`), matching how the DexFinal `pub_inputs_hex` field
//! serializes public instances. `salt_commitment_hex` follows the same
//! convention.
//!
//! ## Byte hex convention
//!
//! All other `*_hex` fields (block ids, merkle siblings, ref paths, L7 root)
//! are the 32-byte hex encodings of raw byte arrays as served by GQL.

use dex_halo2_circuit::multi_hop_witness::{
    BLOCK_MERKLE_DEPTH, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH, N_BUNDLE,
};
use serde::{Deserialize, Serialize};

/// One hop's worth of witness data. Mirrors `MultiHopWitness` in
/// `dex_halo2_circuit::multi_hop_proof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopWitnessJson {
    /// Whether this hop is real or inactive padding (spec §6.4). Inactive
    /// hops collapse to `salted_start_block_id == salted_end_block_id`.
    pub is_active: bool,
    /// The hop's start (predecessor) block id in raw hex (32 B).
    pub ref_block_id_hex: String,
    /// The hop's end block id in raw hex (32 B).
    pub block_id_hex: String,
    /// `block_merkle_tree_leaves[7]` — the Poseidon root of the end
    /// block's `proof_block_refs`. Raw hex (32 B).
    pub l7_hex: String,
    /// Depth-4 SHA-256 opening of `block_merkle_tree_leaves[7]` against
    /// `block_id`. Always 4 siblings, each 32 B raw hex.
    pub block_merkle_leaf_proof_l7_hex: [String; BLOCK_MERKLE_DEPTH],
    /// Position of `ref_block_id` inside `proof_block_refs`. Must be
    /// ≥ 1 (slot 0 is same-thread parent, forbidden per spec §5.1).
    pub ref_index: usize,
    /// Real L7 dense-merkle depth for this hop
    /// (`proof_block_refs.len().next_power_of_two().ilog2()`).
    /// Range `[0, MAX_PROOF_BLOCK_REFS_DEPTH]`.
    pub refs_tree_depth: u8,
    /// L7 dense-merkle sibling path opening `proof_block_refs[ref_index]`,
    /// zero-padded to `MAX_PROOF_BLOCK_REFS_DEPTH` (=8). Only the first
    /// `refs_tree_depth` entries are real; the tail is ignored by the
    /// in-circuit gated fold.
    pub proof_block_ref_inner_path_hex: [String; MAX_PROOF_BLOCK_REFS_DEPTH],
    /// `hash_bytes_flat(fr_to_bytes(salt) ‖ ref_block_id ‖ position)`.
    /// Fr LE hex (`Fr::to_repr()`).
    pub salted_start_block_id_hex: String,
    /// `hash_bytes_flat(fr_to_bytes(salt) ‖ block_id ‖ position+1)`.
    /// Fr LE hex.
    pub salted_end_block_id_hex: String,
}

/// One MultiHopProof snark's witness data — `H_HOPS_PER_PROOF` (=5) hops
/// chained `hops[i].salted_end == hops[i+1].salted_start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiHopSnarkWitnessJson {
    /// Snark position within the bundle (`0..N_BUNDLE`). Drives the
    /// bundle-global position tag mixed into each hop's salted-endpoint
    /// Poseidon (BC-005 anonymity fix). Kept as a private witness in the
    /// circuit; carried here so the prover can pass it to
    /// `MultiHopProofCircuit::new_for_proving`.
    pub bundle_index: u32,
    /// The five hops, chained by salted-endpoint equality.
    pub hops: [HopWitnessJson; H_HOPS_PER_PROOF],
    /// Bundle-wide salt commitment (public instance [2]). Must equal
    /// `Poseidon([Poseidon([DOMAIN_TAG_HOP_SALT_FR, sk_u])])` and must
    /// match every other snark's `salt_commitment_hex` in the same
    /// bundle. Fr LE hex.
    pub salt_commitment_hex: String,
}

/// Full bundle witness — one DexFinal fixture plus `N_BUNDLE` MultiHopProof
/// snark witnesses. The whole file is what `halo2-proover bundle` consumes.
///
/// `sk_u_hex` is the shared voucher secret from which every snark's
/// `salt_commitment_hex` is derived; carried at the top level rather than
/// per-snark to avoid duplication and to enforce (via a load-time check)
/// that every embedded snark agrees on the salt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleWitnessJson {
    /// Human-readable one-line summary (block heights, N_BUNDLE, thread
    /// layout, etc.). Ignored by the prover.
    pub description: String,
    /// Shared voucher secret. All `snarks[*].salt_commitment_hex` must
    /// derive from this via `compute_salt_commitment_native(compute_salt_native(sk_u))`.
    pub sk_u_hex: String,
    /// Path (relative or absolute) to the DexFinal fixture JSON on disk.
    /// Kept as a path rather than inlined so the DexFinal and Bundle
    /// pipelines stay independently regeneratable and share a single
    /// on-disk artifact per event.
    pub dex_final_fixture_path: String,
    /// The N_BUNDLE (=4) MultiHopProof snark witnesses. `snarks[0].hops[0]`'s
    /// salted-start must equal the DexFinal's `salted_x_start`;
    /// `snarks[N_BUNDLE-1].hops[H_HOPS_PER_PROOF-1]`'s salted-end must
    /// equal the DexFinal's `salted_y_end`; adjacent snarks must chain
    /// (`snarks[i][last].salted_end == snarks[i+1][0].salted_start`).
    /// These constraints are enforced by
    /// `dex_halo2_circuit::bundle_verifier::verify_bundle`.
    pub snarks: [MultiHopSnarkWitnessJson; N_BUNDLE],
}
