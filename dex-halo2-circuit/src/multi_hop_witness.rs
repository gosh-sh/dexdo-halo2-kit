//! MultiHopProof witness shapes — mirrors production GQL types byte-for-byte.
//!
//! Field names and sizes match
//! `acki-nacki/helpers/proof_helper/src/gql_proof.rs`, so synthetic test
//! fixtures and live GQL payloads share a single shape.
//!
//! ## Layout
//!
//! A bundle has `N_BUNDLE = 4` MultiHopProof snarks, each covering
//! `H_HOPS_PER_PROOF = 5` hops (≤ 20 hops per bundle). Per hop:
//!
//! - **Outer block-merkle**: `BLOCK_MERKLE_LEAF_COUNT = 8` SHA-256 leaves
//!   L0..L7 (only L7 is constrained at this level — it's the Poseidon root
//!   over the block's ref chain; production calls it `proof_block_refs_root`).
//! - **Inner ref-tree**: up to `MAX_PROOF_BLOCK_REFS` Poseidon leaves
//!   (`compute_referenced_block_leaf_hash(index, block_id)`), opened at
//!   `ref_index` to prove the parent block id of the hop chain.
//! - **`is_active`** padding flag (spec §6.4): inactive hops collapse to
//!   `salted_start_block_id == salted_end_block_id == event_salted_block_id`.
//!
//! ## Two Poseidon hash families
//!
//! - **Shape-mirror** (`ref_*_native`, `proof_block_refs_root_native`, …) —
//!   Fr-vector Poseidon via `gosh_dense_balanced_tree`. Self-consistent
//!   within this kit; **does not** match live-GQL L7 roots.
//! - **Production-parity** (`*_bytes_flat_native`) — byte-flat sponge
//!   identical to `tvm-sdk` `PoseidonSponge::hash_bytes_flat`. Use these
//!   whenever a value must equal a live-GQL L7 root.
//!
//! ## Constants — sourced from production
//!
//! - `BLOCK_MERKLE_LEAF_COUNT = 8`  ← `gql_proof.rs:13`
//! - `MAX_HISTORY_PROOF_LAYERS = 10` ← `gql_proof.rs:15`
//! - `HISTORY_PROOF_WINDOW_SIZE = 128` ← `history-proof/src/lib.rs`
//! - `REFERENCED_PARENT_BLOCK_TAG` / `REFERENCED_REF_BLOCK_TAG`
//!   ← `history-proof`
//! - `MAX_PROOF_BLOCK_REFS = 16` — first-cut testing value;
//!   production needs 256 (spec §10.1).

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants — mirror production
// ---------------------------------------------------------------------------

/// SHA-256 leaves in the per-block outer merkle. **Frozen at 8** by the
/// production GQL layer (`gql_proof.rs:13`). L0 = history-proofs root,
/// L1..L6 = misc block fields, L7 = `proof_block_refs_root` (Poseidon).
pub const BLOCK_MERKLE_LEAF_COUNT: usize = 8;

/// Depth of the per-block SHA-256 merkle (`log2(8) = 3`).
pub const BLOCK_MERKLE_DEPTH: usize = 3;

/// Maximum number of layers in the recursive history-proof chain
/// (`gql_proof.rs:15`).
pub const MAX_HISTORY_PROOF_LAYERS: usize = 10;

/// Window size used by `history-proof` (`HISTORY_PROOF_WINDOW_SIZE`). Each
/// layer covers `WINDOW_SIZE^layer` consecutive blocks.
pub const HISTORY_PROOF_WINDOW_SIZE: usize = 128;

/// Hops per MultiHopProof snark (spec §6.4).
pub const H_HOPS_PER_PROOF: usize = 5;

/// MultiHopProof snarks per bundle (spec §6.4 `N_BUNDLE`).
pub const N_BUNDLE: usize = 4;

/// Max leaves in the L7 inner Poseidon dense merkle tree.
///
/// **First-cut testing value.** Production protocol cap is 256 (spec §10.1);
/// bumping this only enlarges the L7-inner-path padding.
///
/// TODO: bump to 256 for production once cell-budget tuning is done.
pub const MAX_PROOF_BLOCK_REFS: usize = 16;

/// `ceil(log2(MAX_PROOF_BLOCK_REFS))`.
pub const MAX_PROOF_BLOCK_REFS_DEPTH: usize = 4;

/// Domain tag for the parent slot (index 0) in the ref-chain Poseidon tree.
/// Must equal `history-proof::REFERENCED_PARENT_BLOCK_TAG`.
pub const REFERENCED_PARENT_BLOCK_TAG: &[u8] = b"acki-nacki:referenced-block:parent:v1";

/// Domain tag for non-parent slots (index ≥ 1) in the ref-chain Poseidon tree.
/// Must equal `history-proof::REFERENCED_REF_BLOCK_TAG`.
pub const REFERENCED_REF_BLOCK_TAG: &[u8] = b"acki-nacki:referenced-block:ref:v1";

// ---------------------------------------------------------------------------
// Witness structs — field names mirror `gql_proof.rs` 1:1 where applicable
// ---------------------------------------------------------------------------

/// One block's GQL-shaped data — what the production verifier consumes per
/// block. Mirrors the inputs to `verify_gql_block_merkle` +
/// `verify_gql_proof_block_refs_l7`.
#[derive(Clone, Debug)]
pub struct BlockWitness {
    /// SHA-256 of the block: `block_merkle_root(block_merkle_tree_leaves)`.
    pub block_id: [u8; 32],

    /// The 8 SHA-256 leaves L0..L7 (`gql_proof.rs`'s
    /// `block_merkle_tree_leaves`). Leaf L7 (`block_merkle_tree_leaves[7]`)
    /// equals `proof_block_refs_root(proof_block_refs)`.
    pub block_merkle_tree_leaves: [[u8; 32]; BLOCK_MERKLE_LEAF_COUNT],

    /// The referenced-block-id list whose Poseidon dense-merkle root is L7.
    /// `proof_block_refs[0]` is the parent of `block_id` (tagged with
    /// `REFERENCED_PARENT_BLOCK_TAG`); `proof_block_refs[1..]` are
    /// referenced predecessors (tagged with `REFERENCED_REF_BLOCK_TAG`).
    ///
    /// Length is variable (≤ `MAX_PROOF_BLOCK_REFS`); the circuit pads to
    /// `MAX_PROOF_BLOCK_REFS` with an inactive padding leaf.
    pub proof_block_refs: Vec<[u8; 32]>,
}

/// One hop in the multi-hop chain — what the in-circuit `MultiHopProof` opens
/// per hop slot.
#[derive(Clone, Debug)]
pub struct HopWitness {
    /// Whether this hop slot is real or inactive padding (spec §6.4). When
    /// `false`, the circuit constrains `salted_start_block_id == salted_end_block_id ==
    /// event_salted_block_id` and skips all openings below.
    pub is_active: bool,

    /// The block this hop targets — i.e. the block in which the hop's
    /// `referenced-block` link is *witnessed*.
    pub block: BlockWitness,

    /// L0..L6 SHA-256 merkle opening for `block.block_merkle_tree_leaves[7]`
    /// against `block.block_id`. Always 3 siblings (depth = 3).
    pub block_merkle_leaf_proof_l7: [[u8; 32]; BLOCK_MERKLE_DEPTH],

    /// Index of the *referenced parent* block within `block.proof_block_refs`.
    /// In practice this is 0 (the parent slot) for sequential chains, but the
    /// inner-ref Merkle tree is general.
    pub ref_index: usize,

    /// Dense-merkle siblings for opening `proof_block_refs[ref_index]`
    /// against L7. Always `MAX_PROOF_BLOCK_REFS_DEPTH` siblings.
    pub proof_block_ref_inner_path: [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],

    /// The hop's start endpoint as the verifier sees it:
    /// `Poseidon([salt, bytes_to_fr(block_id_of_predecessor)])`.
    pub salted_start_block_id: Fr,

    /// The hop's end endpoint:
    /// `Poseidon([salt, bytes_to_fr(block.block_id)])`.
    pub salted_end_block_id: Fr,
}

/// One MultiHopProof snark's worth of witness data — `H_HOPS_PER_PROOF` hops,
/// chained `hops[i].salted_end_block_id == hops[i+1].salted_start_block_id`.
#[derive(Clone, Debug)]
pub struct MultiHopProofWitness {
    pub hops: [HopWitness; H_HOPS_PER_PROOF],

    /// Bundle-wide salt commitment (instance [2]).
    pub salt_commitment: Fr,
}

// ---------------------------------------------------------------------------
// Native SHA-256 8-leaf merkle helpers — byte-identical to `gql_proof.rs`.
// ---------------------------------------------------------------------------

fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// SHA-256 depth-3 merkle root over 8 leaves. Mirrors
/// `gql_proof.rs::block_merkle_root` exactly.
pub fn block_merkle_root(leaves: &[[u8; 32]; BLOCK_MERKLE_LEAF_COUNT]) -> [u8; 32] {
    let h0 = sha256_pair(&leaves[0], &leaves[1]);
    let h1 = sha256_pair(&leaves[2], &leaves[3]);
    let h2 = sha256_pair(&leaves[4], &leaves[5]);
    let h3 = sha256_pair(&leaves[6], &leaves[7]);
    let h01 = sha256_pair(&h0, &h1);
    let h23 = sha256_pair(&h2, &h3);
    sha256_pair(&h01, &h23)
}

/// 3-sibling path proving `leaves[leaf_index]` against `block_merkle_root`.
/// Mirrors `gql_proof.rs::block_merkle_leaf_proof` exactly.
pub fn block_merkle_leaf_proof(
    leaves: &[[u8; 32]; BLOCK_MERKLE_LEAF_COUNT],
    leaf_index: usize,
) -> [[u8; 32]; BLOCK_MERKLE_DEPTH] {
    assert!(
        leaf_index < BLOCK_MERKLE_LEAF_COUNT,
        "leaf_index {leaf_index} out of range"
    );
    let h0 = sha256_pair(&leaves[0], &leaves[1]);
    let h1 = sha256_pair(&leaves[2], &leaves[3]);
    let h2 = sha256_pair(&leaves[4], &leaves[5]);
    let h3 = sha256_pair(&leaves[6], &leaves[7]);
    let h01 = sha256_pair(&h0, &h1);
    let h23 = sha256_pair(&h2, &h3);
    match leaf_index {
        0 => [leaves[1], h1, h23],
        1 => [leaves[0], h1, h23],
        2 => [leaves[3], h0, h23],
        3 => [leaves[2], h0, h23],
        4 => [leaves[5], h3, h01],
        5 => [leaves[4], h3, h01],
        6 => [leaves[7], h2, h01],
        7 => [leaves[6], h2, h01],
        _ => unreachable!("checked above"),
    }
}

/// Verify a 3-sibling SHA-256 path against `root`. Mirrors
/// `gql_proof.rs::verify_block_merkle_leaf_proof`.
pub fn verify_block_merkle_leaf_proof(
    root: &[u8; 32],
    leaf: &[u8; 32],
    leaf_index: usize,
    proof: &[[u8; 32]; BLOCK_MERKLE_DEPTH],
) -> bool {
    if leaf_index >= BLOCK_MERKLE_LEAF_COUNT {
        return false;
    }
    let mut cur = *leaf;
    let mut idx = leaf_index;
    for sibling in proof {
        cur = if idx % 2 == 0 {
            sha256_pair(&cur, sibling)
        } else {
            sha256_pair(sibling, &cur)
        };
        idx /= 2;
    }
    &cur == root
}

// ---------------------------------------------------------------------------
// L7 inner ref-chain helpers — shape-mirror (Fr-vector Poseidon).
// ---------------------------------------------------------------------------
//
// These are self-consistent within this kit but do NOT match live-GQL L7
// roots — for that, use the `_bytes_flat_*` family below.

use gosh_dense_balanced_tree::{bytes_to_fr, fr_to_bytes, poseidon_hash_native};

/// Pack a byte tag of arbitrary length into a `Vec<Fr>` by splitting into
/// 31-byte LE chunks. Used because the production tags
/// (`acki-nacki:referenced-block:parent:v1`, 37 bytes) exceed the 31-byte
/// single-Fr limit. The Fr-vector Poseidon input is `[chunks..., block_id]`.
fn pack_tag_chunks(tag_bytes: &[u8]) -> Vec<Fr> {
    let mut chunks = Vec::new();
    for chunk in tag_bytes.chunks(31) {
        let mut buf = [0u8; 32];
        buf[..chunk.len()].copy_from_slice(chunk);
        chunks.push(bytes_to_fr(&buf));
    }
    chunks
}

/// Native: per-ref leaf hash, shape-mirror only. For byte-for-byte parity
/// with `history-proof::compute_referenced_block_leaf_hash`, use
/// [`ref_leaf_hash_bytes_flat_native`].
pub fn ref_leaf_hash_native(index: usize, block_id: &[u8; 32]) -> [u8; 32] {
    let tag_bytes = if index == 0 {
        REFERENCED_PARENT_BLOCK_TAG
    } else {
        REFERENCED_REF_BLOCK_TAG
    };
    let mut inputs = pack_tag_chunks(tag_bytes);
    inputs.push(bytes_to_fr(block_id));
    let out_fr = poseidon_hash_native(&inputs);
    fr_to_bytes(out_fr)
}

/// Native: combine two children in the Poseidon dense merkle tree
/// (shape-mirror; for parity use [`ref_inner_combine_bytes_flat_native`]).
pub fn ref_inner_combine_native(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let out = poseidon_hash_native(&[bytes_to_fr(left), bytes_to_fr(right)]);
    fr_to_bytes(out)
}

/// Compute the L7 root over `proof_block_refs` (shape-mirror). Pads to
/// `MAX_PROOF_BLOCK_REFS` with an inactive padding leaf
/// (`fr_to_bytes(Fr::from(0))` — the dense-tree convention).
///
/// For byte-for-byte GQL parity use [`proof_block_refs_root_bytes_flat_native`].
pub fn proof_block_refs_root_native(proof_block_refs: &[[u8; 32]]) -> [u8; 32] {
    assert!(
        proof_block_refs.len() <= MAX_PROOF_BLOCK_REFS,
        "proof_block_refs len {} exceeds MAX_PROOF_BLOCK_REFS {}",
        proof_block_refs.len(),
        MAX_PROOF_BLOCK_REFS
    );

    let mut layer: Vec<[u8; 32]> = (0..MAX_PROOF_BLOCK_REFS)
        .map(|i| {
            if i < proof_block_refs.len() {
                ref_leaf_hash_native(i, &proof_block_refs[i])
            } else {
                // Padding leaf — matches dense-tree convention (zero Fr).
                fr_to_bytes(Fr::from(0u64))
            }
        })
        .collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(ref_inner_combine_native(&pair[0], &pair[1]));
        }
        layer = next;
    }
    layer[0]
}

/// Open `proof_block_refs[ref_index]` against the L7 root. Returns
/// `MAX_PROOF_BLOCK_REFS_DEPTH` siblings.
pub fn proof_block_ref_inner_path_native(
    proof_block_refs: &[[u8; 32]],
    ref_index: usize,
) -> [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH] {
    assert!(
        ref_index < proof_block_refs.len(),
        "ref_index {ref_index} ≥ proof_block_refs.len() {}",
        proof_block_refs.len()
    );
    assert!(
        proof_block_refs.len() <= MAX_PROOF_BLOCK_REFS,
        "proof_block_refs len {} exceeds MAX_PROOF_BLOCK_REFS {}",
        proof_block_refs.len(),
        MAX_PROOF_BLOCK_REFS
    );

    let mut layer: Vec<[u8; 32]> = (0..MAX_PROOF_BLOCK_REFS)
        .map(|i| {
            if i < proof_block_refs.len() {
                ref_leaf_hash_native(i, &proof_block_refs[i])
            } else {
                fr_to_bytes(Fr::from(0u64))
            }
        })
        .collect();

    let mut idx = ref_index;
    let mut siblings = [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH];
    for d in 0..MAX_PROOF_BLOCK_REFS_DEPTH {
        let sib_idx = idx ^ 1;
        siblings[d] = layer[sib_idx];
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(ref_inner_combine_native(&pair[0], &pair[1]));
        }
        layer = next;
        idx /= 2;
    }
    siblings
}

/// Verify a `proof_block_ref_inner_path_native` opening.
pub fn verify_proof_block_ref_inner_path(
    root: &[u8; 32],
    leaf: &[u8; 32],
    ref_index: usize,
    siblings: &[[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
) -> bool {
    let mut cur = *leaf;
    let mut idx = ref_index;
    for sib in siblings {
        cur = if idx % 2 == 0 {
            ref_inner_combine_native(&cur, sib)
        } else {
            ref_inner_combine_native(sib, &cur)
        };
        idx /= 2;
    }
    &cur == root
}

// ---------------------------------------------------------------------------
// Production-parity helpers (byte-flat Poseidon sponge)
// ---------------------------------------------------------------------------
//
// Byte-for-byte mirrors of `tvm-sdk` `PoseidonSponge::hash_bytes_flat` and
// `acki-nacki/node/libs/history-proof::compute_referenced_blocks_root`.
// Use these whenever a hash must equal a live-GQL value.
//
// Sponge params (`T=3, RATE=2, R_F=8, R_P=57`) and the LE-bytes→Fr decoding
// are identical to tvm-sdk; the only difference vs. the shape-mirror family
// is that here the full `tag ‖ block_id` byte stream is chunked(31) and
// absorbed, rather than tag and block_id being packed separately.

/// Native: Poseidon sponge over a raw byte stream, identical to
/// `PoseidonSponge::hash_bytes_flat` in tvm-sdk.
///
/// Chunks `bytes` into 31-byte windows, zero-pads the last to 32, interprets
/// each chunk as a little-endian `Fr`, and absorbs the resulting `Vec<Fr>`
/// through `poseidon_hash_native`.
pub fn poseidon_bytes_flat_native(bytes: &[u8]) -> [u8; 32] {
    const CHUNK: usize = 31;
    let mut inputs: Vec<Fr> = Vec::with_capacity((bytes.len() + CHUNK - 1) / CHUNK);
    for window in bytes.chunks(CHUNK) {
        let mut buf = [0u8; 32];
        buf[..window.len()].copy_from_slice(window);
        inputs.push(bytes_to_fr(&buf));
    }
    if inputs.is_empty() {
        // Match production: empty input still goes through one chunk of zeros.
        inputs.push(bytes_to_fr(&[0u8; 32]));
    }
    fr_to_bytes(poseidon_hash_native(&inputs))
}

/// Native: per-ref leaf hash matching `history-proof::compute_referenced_block_leaf_hash`
/// **byte-for-byte**. Index 0 uses the parent tag, ≥1 uses the ref tag, and
/// the entire `tag ‖ block_id` byte stream is fed through
/// `poseidon_bytes_flat_native`.
pub fn ref_leaf_hash_bytes_flat_native(index: usize, block_id: &[u8; 32]) -> [u8; 32] {
    let tag_bytes: &[u8] = if index == 0 {
        REFERENCED_PARENT_BLOCK_TAG
    } else {
        REFERENCED_REF_BLOCK_TAG
    };
    let mut concat = Vec::with_capacity(tag_bytes.len() + 32);
    concat.extend_from_slice(tag_bytes);
    concat.extend_from_slice(block_id);
    poseidon_bytes_flat_native(&concat)
}

/// Native: pairwise combiner matching production's `dense_combine`
/// (`hash_bytes_flat(left ‖ right)`).
pub fn ref_inner_combine_bytes_flat_native(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut concat = [0u8; 64];
    concat[..32].copy_from_slice(left);
    concat[32..].copy_from_slice(right);
    poseidon_bytes_flat_native(&concat)
}

/// Native: L7 root computation matching production
/// `proof_block_refs_root`/`compute_referenced_blocks_root` byte-for-byte.
/// Pads the input to `MAX_PROOF_BLOCK_REFS` with an inactive padding leaf
/// (`fr_to_bytes(Fr::from(0))`).
pub fn proof_block_refs_root_bytes_flat_native(proof_block_refs: &[[u8; 32]]) -> [u8; 32] {
    assert!(
        proof_block_refs.len() <= MAX_PROOF_BLOCK_REFS,
        "proof_block_refs len {} exceeds MAX_PROOF_BLOCK_REFS {}",
        proof_block_refs.len(),
        MAX_PROOF_BLOCK_REFS
    );

    let mut layer: Vec<[u8; 32]> = (0..MAX_PROOF_BLOCK_REFS)
        .map(|i| {
            if i < proof_block_refs.len() {
                ref_leaf_hash_bytes_flat_native(i, &proof_block_refs[i])
            } else {
                fr_to_bytes(Fr::from(0u64))
            }
        })
        .collect();

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(ref_inner_combine_bytes_flat_native(&pair[0], &pair[1]));
        }
        layer = next;
    }
    layer[0]
}

/// Native: opening of `proof_block_refs[ref_index]` against the
/// byte-flat-Poseidon L7 root.
pub fn proof_block_ref_inner_path_bytes_flat_native(
    proof_block_refs: &[[u8; 32]],
    ref_index: usize,
) -> [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH] {
    assert!(
        ref_index < proof_block_refs.len(),
        "ref_index {ref_index} ≥ proof_block_refs.len() {}",
        proof_block_refs.len()
    );
    assert!(
        proof_block_refs.len() <= MAX_PROOF_BLOCK_REFS,
        "proof_block_refs len {} exceeds MAX_PROOF_BLOCK_REFS {}",
        proof_block_refs.len(),
        MAX_PROOF_BLOCK_REFS
    );

    let mut layer: Vec<[u8; 32]> = (0..MAX_PROOF_BLOCK_REFS)
        .map(|i| {
            if i < proof_block_refs.len() {
                ref_leaf_hash_bytes_flat_native(i, &proof_block_refs[i])
            } else {
                fr_to_bytes(Fr::from(0u64))
            }
        })
        .collect();

    let mut idx = ref_index;
    let mut siblings = [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH];
    for d in 0..MAX_PROOF_BLOCK_REFS_DEPTH {
        let sib_idx = idx ^ 1;
        siblings[d] = layer[sib_idx];
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(ref_inner_combine_bytes_flat_native(&pair[0], &pair[1]));
        }
        layer = next;
        idx /= 2;
    }
    siblings
}

/// Verify a `proof_block_ref_inner_path_bytes_flat_native` opening.
pub fn verify_proof_block_ref_inner_path_bytes_flat(
    root: &[u8; 32],
    leaf: &[u8; 32],
    ref_index: usize,
    siblings: &[[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
) -> bool {
    let mut cur = *leaf;
    let mut idx = ref_index;
    for sib in siblings {
        cur = if idx % 2 == 0 {
            ref_inner_combine_bytes_flat_native(&cur, sib)
        } else {
            ref_inner_combine_bytes_flat_native(sib, &cur)
        };
        idx /= 2;
    }
    &cur == root
}

// ---------------------------------------------------------------------------
// Unit tests (shape-only — no production-wire-format parity)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_gql_proof_layout() {
        assert_eq!(BLOCK_MERKLE_LEAF_COUNT, 8);
        assert_eq!(BLOCK_MERKLE_DEPTH, 3);
        assert_eq!(MAX_HISTORY_PROOF_LAYERS, 10);
        assert_eq!(1 << MAX_PROOF_BLOCK_REFS_DEPTH, MAX_PROOF_BLOCK_REFS);
    }

    #[test]
    fn block_merkle_root_and_proof_roundtrip() {
        let leaves: [[u8; 32]; 8] = std::array::from_fn(|i| [i as u8 + 1; 32]);
        let root = block_merkle_root(&leaves);
        for i in 0..8 {
            let proof = block_merkle_leaf_proof(&leaves, i);
            assert!(
                verify_block_merkle_leaf_proof(&root, &leaves[i], i, &proof),
                "leaf {i} proof should verify"
            );
        }
    }

    #[test]
    fn block_merkle_proof_rejects_tampering() {
        let leaves: [[u8; 32]; 8] = std::array::from_fn(|i| [i as u8 + 10; 32]);
        let root = block_merkle_root(&leaves);
        let mut proof = block_merkle_leaf_proof(&leaves, 3);
        proof[1] = [0xFFu8; 32];
        assert!(!verify_block_merkle_leaf_proof(&root, &leaves[3], 3, &proof));
    }

    #[test]
    fn proof_block_refs_root_and_inner_path_roundtrip() {
        let refs: Vec<[u8; 32]> = (0..5).map(|i| [i as u8 + 100; 32]).collect();
        let root = proof_block_refs_root_native(&refs);
        for (i, r) in refs.iter().enumerate() {
            let leaf = ref_leaf_hash_native(i, r);
            let siblings = proof_block_ref_inner_path_native(&refs, i);
            assert!(
                verify_proof_block_ref_inner_path(&root, &leaf, i, &siblings),
                "ref {i} inner-path should verify"
            );
        }
    }

    #[test]
    fn parent_and_ref_tags_distinct() {
        let block_id = [0xAAu8; 32];
        let parent_leaf = ref_leaf_hash_native(0, &block_id);
        let ref_leaf = ref_leaf_hash_native(1, &block_id);
        assert_ne!(
            parent_leaf, ref_leaf,
            "parent-tag and ref-tag must produce distinct leaf hashes"
        );
    }

    // -----------------------------------------------------------------------
    // Tests for production-parity (bytes-flat) family
    // -----------------------------------------------------------------------

    #[test]
    fn bytes_flat_root_and_inner_path_roundtrip() {
        let refs: Vec<[u8; 32]> = (0..5).map(|i| [i as u8 + 200; 32]).collect();
        let root = proof_block_refs_root_bytes_flat_native(&refs);
        for (i, r) in refs.iter().enumerate() {
            let leaf = ref_leaf_hash_bytes_flat_native(i, r);
            let siblings = proof_block_ref_inner_path_bytes_flat_native(&refs, i);
            assert!(
                verify_proof_block_ref_inner_path_bytes_flat(&root, &leaf, i, &siblings),
                "ref {i} bytes-flat inner-path should verify"
            );
        }
    }

    #[test]
    fn bytes_flat_parent_and_ref_tags_distinct() {
        let block_id = [0xBBu8; 32];
        let parent = ref_leaf_hash_bytes_flat_native(0, &block_id);
        let refl = ref_leaf_hash_bytes_flat_native(1, &block_id);
        assert_ne!(parent, refl);
    }

    /// The two families MUST differ — proves the byte-flat variant is a
    /// genuinely new hashing convention, not an alias.
    #[test]
    fn bytes_flat_differs_from_shape_mirror() {
        let block_id = [0x77u8; 32];
        let shape = ref_leaf_hash_native(0, &block_id);
        let flat = ref_leaf_hash_bytes_flat_native(0, &block_id);
        assert_ne!(
            shape, flat,
            "shape-mirror and byte-flat variants must produce different hashes — \
             they differ at the byte→Fr chunking boundary"
        );
    }

    /// `poseidon_bytes_flat_native` on a 32-byte input that fits in one
    /// 31-byte chunk + 1 leftover byte should produce the same result as
    /// running the same chunking by hand.
    #[test]
    fn poseidon_bytes_flat_chunks_match_manual() {
        let input = [0xCCu8; 32];
        let manual = {
            // chunk 0 (31 bytes from input[0..31], zero-padded to 32)
            let mut c0 = [0u8; 32];
            c0[..31].copy_from_slice(&input[..31]);
            // chunk 1 (1 byte from input[31..32], zero-padded to 32)
            let mut c1 = [0u8; 32];
            c1[0] = input[31];
            fr_to_bytes(poseidon_hash_native(&[bytes_to_fr(&c0), bytes_to_fr(&c1)]))
        };
        let via_fn = poseidon_bytes_flat_native(&input);
        assert_eq!(manual, via_fn);
    }
}
