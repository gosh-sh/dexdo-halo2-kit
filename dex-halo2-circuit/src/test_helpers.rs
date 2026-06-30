use crate::boc_helper::*;
use crate::multi_hop_witness::{
    block_merkle_leaf_proof, block_merkle_root, proof_block_ref_inner_path_native,
    proof_block_refs_root_native, BlockWitness, HopWitness, MultiHopProofWitness,
    BLOCK_MERKLE_DEPTH, BLOCK_MERKLE_LEAF_COUNT, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH,
    N_BUNDLE,
};
use crate::salt::{
    compute_salt_commitment_native, compute_salt_native, compute_salted_block_id_native,
};
// `dense_balanced_tree` is a dev-dependency; only the `build_dense_chain` /
// `build_two_level_tree` helpers (both `#[cfg(test)]`-gated below) consume it.
#[cfg(test)]
use dense_balanced_tree::{
    dense_merkle_proof, dense_merkle_root, PoseidonHasher as DensePoseidonHasher,
};
use gosh_dense_balanced_tree::{bytes_to_fr, poseidon_hash_native};
#[cfg(test)]
use gosh_dense_balanced_tree::{fr_to_bytes, DenseChainLink, MAX_CHAIN_LEN};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use rand::Rng;
use tvm_block::{Deserializable, Message, Serializable};

pub const K: u32 = 19;

pub fn base_circuit_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: K as usize,
        num_advice_per_phase: vec![4],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![1],
        lookup_bits: Some(18),
        num_instance_columns: 1,
    }
}

/// Big-endian byte-to-Fr conversion for BOC field extraction (voucher_nominal, token_type).
pub fn bytes_to_fr_be(data: &[u8]) -> Fr {
    let mut val = Fr::from(0u64);
    for &byte in data.iter() {
        val = val * Fr::from(256u64) + Fr::from(byte as u64);
    }
    val
}

/// Integer ceiling of log2(n) for computing tree depth.
pub fn ceil_log2(n: usize) -> usize {
    assert!(n > 0);
    if n == 1 {
        return 0;
    }
    let mut k = 0usize;
    let mut v = 1usize;
    while v < n {
        v <<= 1;
        k += 1;
    }
    k
}

/// Parse a single event BOC into flattened cell entries and repr_hash.
pub fn parse_voucher_boc(event_boc: &str) -> ([BocFlattenData; 2], [u8; 32]) {
    let msg =
        Message::construct_from_base64(event_boc).expect("failed to parse BOC");
    let msg_cell = msg.serialize().expect("failed to serialize");
    let serialized =
        serialize_cells_tree_root_first(&msg_cell).expect("failed to flatten");
    assert_eq!(serialized.len(), 2, "expected 2 cells");
    let repr_hash = serialized[0].repr_hash;
    ([serialized[0].clone(), serialized[1].clone()], repr_hash)
}

/// Extracted public field values from a voucher, ready for instance comparison.
pub struct VoucherFields {
    pub sk_u: Fr,
    pub entries: [BocFlattenData; 2],
    pub repr_hash: [u8; 32],
    pub voucher_nominal_val: Fr,
    pub token_type_val: Fr,
    pub expected_poseidon_hash: Fr,
}

const EVENT_BOC_DATA_BYTES_OFFSET: usize = 6;
const EVENT_SK_U_COMMIT_FIELD_LEN: usize = 32;
const EVENT_VOUCHER_NOMINAL_FIELD_LEN: usize = 32;
const EVENT_TOKEN_TYPE_FIELD_LEN: usize = 4;

const EVENT_SK_U_COMMIT_START: usize = EVENT_BOC_DATA_BYTES_OFFSET;
const EVENT_SK_U_COMMIT_END: usize = EVENT_SK_U_COMMIT_START + EVENT_SK_U_COMMIT_FIELD_LEN;
const EVENT_VOUCHER_NOMINAL_START: usize = EVENT_SK_U_COMMIT_END;
const EVENT_VOUCHER_NOMINAL_END: usize =
    EVENT_VOUCHER_NOMINAL_START + EVENT_VOUCHER_NOMINAL_FIELD_LEN;
const EVENT_TOKEN_TYPE_START: usize = EVENT_VOUCHER_NOMINAL_END;
const EVENT_TOKEN_TYPE_END: usize = EVENT_TOKEN_TYPE_START + EVENT_TOKEN_TYPE_FIELD_LEN;

/// Extract sk_u, public fields, and the expected Poseidon hash from a parsed voucher.
pub fn extract_voucher_fields(
    sk_u: Fr,
    entries: [BocFlattenData; 2],
    repr_hash: [u8; 32],
) -> VoucherFields {
    let sk_u_commit_bytes: [u8; 32] = entries[1].cell_repr_data
        [EVENT_SK_U_COMMIT_START..EVENT_SK_U_COMMIT_END]
        .try_into()
        .unwrap();
    let sk_u_commit_val = Fr::from_repr(sk_u_commit_bytes).unwrap();
    let voucher_nominal_val = bytes_to_fr_be(
        &entries[1].cell_repr_data[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END],
    );
    let token_type_val = bytes_to_fr_be(
        &entries[1].cell_repr_data[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END],
    );
    let expected_poseidon_hash =
        poseidon_hash_native(&[voucher_nominal_val, token_type_val, sk_u, sk_u_commit_val]);
    VoucherFields {
        sk_u,
        entries,
        repr_hash,
        voucher_nominal_val,
        token_type_val,
        expected_poseidon_hash,
    }
}

/// Load the first voucher from vouchers.txt and extract all fields.
pub fn load_first_voucher() -> VoucherFields {
    use crate::event_data_helper::read_event_data_from_file;
    let events = read_event_data_from_file("vouchers.txt");
    assert!(
        !events.is_empty(),
        "vouchers.txt must contain at least one entry"
    );
    let (entries, repr_hash) = parse_voucher_boc(&events[0].event_boc);
    extract_voucher_fields(events[0].sk_u, entries, repr_hash)
}

/// Build a chain of `chain_len` dense balanced trees (0 <= chain_len <= MAX_CHAIN_LEN).
#[cfg(test)]
pub fn build_dense_chain(
    initial_leaf_bytes: [u8; 32],
    chain_len: usize,
    leaves_per_tree: usize,
) -> (Vec<DenseChainLink>, [u8; 32]) {
    use dense_balanced_tree::dense_merkle_verify;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    assert!(chain_len <= MAX_CHAIN_LEN);
    let dense_hasher = DensePoseidonHasher::new();
    let mut rng = StdRng::seed_from_u64(123);
    let mut chain = Vec::with_capacity(MAX_CHAIN_LEN);
    let mut current_leaf_bytes = initial_leaf_bytes;

    for t in 0..chain_len {
        let mut leaves = vec![[0u8; 32]; leaves_per_tree];
        leaves[0] = current_leaf_bytes;
        for i in 1..leaves_per_tree {
            rng.fill(&mut leaves[i]);
        }

        let root_hash = dense_merkle_root(&dense_hasher, &leaves);
        let siblings = dense_merkle_proof(&dense_hasher, &leaves, 0);

        assert!(
            dense_merkle_verify(&dense_hasher, &root_hash, &leaves[0], 0, &siblings),
            "Chain link {}: native verification failed",
            t
        );

        chain.push(DenseChainLink {
            active: true,
            siblings,
            position: 0,
            leaf_native: current_leaf_bytes,
        });

        let root_fr = bytes_to_fr(&root_hash);
        current_leaf_bytes = fr_to_bytes(root_fr);
    }

    let final_root_bytes = current_leaf_bytes;
    let depth = if chain.is_empty() {
        ceil_log2(leaves_per_tree)
    } else {
        chain[0].siblings.len()
    };

    while chain.len() < MAX_CHAIN_LEN {
        chain.push(DenseChainLink::inactive(final_root_bytes, depth));
    }

    (chain, final_root_bytes)
}

/// Synthetic witnesses for the two-level Poseidon tree structure.
pub struct TwoLevelWitnesses {
    pub account_dapp_id: [u8; 32],
    pub account_id: [u8; 32],
    pub block_id: [u8; 32],
    pub envelope_hash_bytes: [u8; 32],
    pub events_siblings: Vec<[u8; 32]>,
    pub events_pos: usize,
    pub block_siblings: Vec<[u8; 32]>,
    pub block_pos: usize,
    /// The history window root (block tree root), used as initial leaf for the chain.
    pub blocks_root_level_0: [u8; 32],
}

/// Build the two-level tree: ext_msg_leaf → events tree → block_leaf → block tree.
#[cfg(test)]
pub fn build_two_level_tree(
    repr_hash: &[u8; 32],
    rng: &mut impl Rng,
    dense_hasher: &DensePoseidonHasher,
    num_events_leaves: usize,
    num_block_leaves: usize,
) -> TwoLevelWitnesses {
    use crate::dark_dex_circuit_new::poseidon_hash_96_native;

    let mut dapp_id = [0u8; 32];
    let mut account_id_b = [0u8; 32];
    let mut block_id = [0u8; 32];
    let mut envelope_hash = [0u8; 32];
    rng.fill(&mut dapp_id);
    rng.fill(&mut account_id_b);
    rng.fill(&mut block_id);
    rng.fill(&mut envelope_hash);

    // Inner: ext_message_leaf = Poseidon(dapp_id || account_id || repr_hash)
    let ext_msg_leaf = poseidon_hash_96_native(&dapp_id, &account_id_b, repr_hash);

    // Events tree with ext_msg_leaf at position 0.
    let mut events_leaves = vec![[0u8; 32]; num_events_leaves];
    events_leaves[0] = ext_msg_leaf;
    for i in 1..num_events_leaves {
        rng.fill(&mut events_leaves[i]);
    }
    let events_root = dense_merkle_root(dense_hasher, &events_leaves);
    let events_siblings = dense_merkle_proof(dense_hasher, &events_leaves, 0);

    // Outer: block_leaf = Poseidon(block_id || envelope_hash || ext_out_messages_root)
    let block_leaf = poseidon_hash_96_native(&block_id, &envelope_hash, &events_root);

    // Block tree with block_leaf at position 0.
    let mut block_leaves = vec![[0u8; 32]; num_block_leaves];
    block_leaves[0] = block_leaf;
    for i in 1..num_block_leaves {
        rng.fill(&mut block_leaves[i]);
    }
    let blocks_root = dense_merkle_root(dense_hasher, &block_leaves);
    let block_siblings = dense_merkle_proof(dense_hasher, &block_leaves, 0);

    TwoLevelWitnesses {
        account_dapp_id: dapp_id,
        account_id: account_id_b,
        block_id,
        envelope_hash_bytes: envelope_hash,
        events_siblings,
        events_pos: 0,
        block_siblings,
        block_pos: 0,
        blocks_root_level_0: blocks_root,
    }
}

// ---------------------------------------------------------------------------
// Synthetic multi-hop chain generator (Stage 2b)
// ---------------------------------------------------------------------------

/// Output of `synth_chain` — everything a Phase 4 bundle E2E test needs.
pub struct SynthChain {
    /// `sk_u` chosen for the chain (random per call).
    pub sk_u: Fr,
    /// Salt and salt_commitment derived from `sk_u` (canonical Phase 3 math).
    pub salt: Fr,
    pub salt_commitment: Fr,
    /// `k_hops` real hops plus padding to fill `N_BUNDLE * H_HOPS_PER_PROOF`
    /// slots. Each hop carries SHA-256 block-merkle + L7 ref-tree openings.
    pub hops: Vec<HopWitness>,
    /// `bundle_head` = salted_id of the genesis (predecessor of hops[0]).
    /// This is what DexFinal's `event_salted_block_id` instance must equal.
    pub bundle_head_salted: Fr,
    /// All real-block IDs in order: `[genesis, b_1, ..., b_{k_hops}]`.
    /// `hops[i]` proves `b_i.proof_block_refs[0] == b_{i-1}`.
    pub block_ids: Vec<[u8; 32]>,
}

/// Build a deterministic synthetic K-hop chain matching the GQL shape.
///
/// Each real hop's target block has:
/// - L0..L6 filled with distinct sentinel bytes (sentinel = `0x10 + i`)
/// - L7 = `proof_block_refs_root_native(&[parent_block_id])` (single-ref case
///   to keep witness compact; the ref-tree machinery still pads to
///   `MAX_PROOF_BLOCK_REFS`)
/// - `block_id = block_merkle_root(L0..L7)`
/// - `block_merkle_leaf_proof_l7` opens L7 against `block_id`
/// - `ref_index = 0` (parent slot)
/// - `proof_block_ref_inner_path` opens leaf 0 of the ref-tree against L7
///
/// Inactive padding hops (`is_active = false`) carry
/// `salted_start_block_id == salted_end_block_id == hops[k_hops-1].salted_end_block_id` so RootPN's
/// continuity check holds.
///
/// For `k_hops = 0` the chain degenerates: all `N_BUNDLE * H` hops inactive,
/// all endpoints equal `hash_bytes_flat(fr_to_bytes(salt) ‖ block_ids[0])`.
pub fn synth_chain(seed: u64, k_hops: usize) -> SynthChain {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let total_slots = N_BUNDLE * H_HOPS_PER_PROOF;
    assert!(
        k_hops <= total_slots,
        "k_hops {k_hops} exceeds bundle capacity {total_slots}"
    );

    let mut rng = StdRng::seed_from_u64(seed);

    // Pick sk_u from RNG so different seeds give different bundles.
    let mut sk_u_bytes = [0u8; 32];
    rng.fill(&mut sk_u_bytes);
    // Force into Fr-valid range by clearing the top byte (safe, keeps test
    // determinism while avoiding non-canonical Fr.)
    sk_u_bytes[31] = 0;
    let sk_u = bytes_to_fr(&sk_u_bytes);

    let salt = compute_salt_native(sk_u);
    let salt_commitment = compute_salt_commitment_native(salt);

    // Generate `k_hops + 1` block IDs (block_ids[0] = genesis predecessor of
    // hops[0]; block_ids[i] = target of hops[i-1]).
    let num_blocks = k_hops + 1;
    let mut block_ids = Vec::with_capacity(num_blocks.max(1));
    for _ in 0..num_blocks.max(1) {
        let mut id = [0u8; 32];
        rng.fill(&mut id);
        block_ids.push(id);
    }

    // Compute salted endpoints for each real block.
    let salted: Vec<Fr> = block_ids
        .iter()
        .map(|b| compute_salted_block_id_native(salt, b))
        .collect();
    let bundle_head_salted = salted[0];
    // Terminal salted endpoint for inactive padding.
    let terminal_salted = if k_hops == 0 {
        bundle_head_salted
    } else {
        salted[k_hops]
    };

    let mut hops = Vec::with_capacity(total_slots);

    for i in 0..k_hops {
        let parent_id = block_ids[i];
        let target_id_expected = block_ids[i + 1];

        // Build the target block's witness: single-ref ref-tree, L0..L6
        // sentinels, L7 = ref-tree root.
        let proof_block_refs: Vec<[u8; 32]> = vec![parent_id];
        let l7 = proof_block_refs_root_native(&proof_block_refs);

        let mut leaves = [[0u8; 32]; BLOCK_MERKLE_LEAF_COUNT];
        for (j, slot) in leaves.iter_mut().enumerate().take(7) {
            *slot = [0x10 + i as u8; 32];
            slot[0] = j as u8; // keep all 8 leaves distinct
        }
        leaves[7] = l7;

        // The synthetic block_id is whatever SHA-256 produces over the leaves
        // — we *re-derive* block_ids[i+1] from that, replacing the random one.
        let computed_block_id = block_merkle_root(&leaves);
        block_ids[i + 1] = computed_block_id;

        // Recompute salted endpoints since we replaced block_ids[i+1].
        // (block_ids[0..=i] are unchanged; future ones still random until
        // their loop iteration overwrites them.)
        let salted_end_block_id = compute_salted_block_id_native(salt, &computed_block_id);

        let block_merkle_leaf_proof_l7 = block_merkle_leaf_proof(&leaves, 7);
        let proof_block_ref_inner_path = proof_block_ref_inner_path_native(&proof_block_refs, 0);

        let salted_start_block_id = if i == 0 {
            bundle_head_salted
        } else {
            // Previous hop's salted_end_block_id (which is `salted_block_id of
            // block_ids[i]`, the now-finalized block we just constructed in
            // iteration i-1).
            compute_salted_block_id_native(salt, &block_ids[i])
        };

        // Sanity: hop chain continuity is intrinsic to the construction.
        debug_assert_ne!(target_id_expected, [0u8; 32]); // (silences unused)

        hops.push(HopWitness {
            is_active: true,
            block: BlockWitness {
                block_id: computed_block_id,
                block_merkle_tree_leaves: leaves,
                proof_block_refs,
            },
            block_merkle_leaf_proof_l7,
            ref_index: 0,
            proof_block_ref_inner_path,
            salted_start_block_id,
            salted_end_block_id,
        });
    }

    // Recompute true terminal after possible block_id overwrites above.
    let final_terminal_salted = if k_hops == 0 {
        bundle_head_salted
    } else {
        hops[k_hops - 1].salted_end_block_id
    };
    let _ = terminal_salted; // silence

    // Pad with inactive hops carrying terminal_salted at both endpoints.
    while hops.len() < total_slots {
        // Inactive padding: zero everything that the circuit will gate out
        // with `is_active`. Endpoints must equal terminal_salted so RootPN's
        // continuity check passes.
        let zero_leaves = [[0u8; 32]; BLOCK_MERKLE_LEAF_COUNT];
        let zero_l7_proof = [[0u8; 32]; BLOCK_MERKLE_DEPTH];
        let zero_inner_path = [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH];
        hops.push(HopWitness {
            is_active: false,
            block: BlockWitness {
                block_id: [0u8; 32],
                block_merkle_tree_leaves: zero_leaves,
                proof_block_refs: Vec::new(),
            },
            block_merkle_leaf_proof_l7: zero_l7_proof,
            ref_index: 0,
            proof_block_ref_inner_path: zero_inner_path,
            salted_start_block_id: final_terminal_salted,
            salted_end_block_id: final_terminal_salted,
        });
    }

    SynthChain {
        sk_u,
        salt,
        salt_commitment,
        hops,
        bundle_head_salted,
        block_ids,
    }
}

// ---------------------------------------------------------------------------
// Variable-`n_bundle` variants for stress tests beyond `L_MAX = 20`.
//
// Spec §10.2 Open Question #1 explicitly contemplates raising `N_BUNDLE` past
// the locked design target of 4 if real testnet chain-length distributions
// demand longer chains (50, 100, even 300 hops). The circuit and on-chain
// verifier loop over snarks, so per-snark logic is unchanged — only the
// bundle width (and total proving wall-time) grows.
//
// These `_n` variants take `n_bundle` as a runtime argument and return a
// `Vec` instead of a fixed-size array, so they can drive bundles of any
// width without touching the locked `N_BUNDLE = 4` constant.
// ---------------------------------------------------------------------------

/// Like `synth_chain` but parameterized by `n_bundle` (number of MultiHop
/// snarks per bundle). Total hop capacity is `n_bundle * H_HOPS_PER_PROOF`.
pub fn synth_chain_n(seed: u64, k_hops: usize, n_bundle: usize) -> SynthChain {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    assert!(n_bundle >= 1, "n_bundle must be >= 1");
    let total_slots = n_bundle * H_HOPS_PER_PROOF;
    assert!(
        k_hops <= total_slots,
        "k_hops {k_hops} exceeds bundle capacity {total_slots}"
    );

    let mut rng = StdRng::seed_from_u64(seed);

    let mut sk_u_bytes = [0u8; 32];
    rng.fill(&mut sk_u_bytes);
    sk_u_bytes[31] = 0;
    let sk_u = bytes_to_fr(&sk_u_bytes);

    let salt = compute_salt_native(sk_u);
    let salt_commitment = compute_salt_commitment_native(salt);

    let num_blocks = k_hops + 1;
    let mut block_ids = Vec::with_capacity(num_blocks.max(1));
    for _ in 0..num_blocks.max(1) {
        let mut id = [0u8; 32];
        rng.fill(&mut id);
        block_ids.push(id);
    }

    let salted_head: Vec<Fr> = block_ids
        .iter()
        .map(|b| compute_salted_block_id_native(salt, b))
        .collect();
    let bundle_head_salted = salted_head[0];

    let mut hops = Vec::with_capacity(total_slots);

    for i in 0..k_hops {
        let parent_id = block_ids[i];

        let proof_block_refs: Vec<[u8; 32]> = vec![parent_id];
        let l7 = proof_block_refs_root_native(&proof_block_refs);

        let mut leaves = [[0u8; 32]; BLOCK_MERKLE_LEAF_COUNT];
        for (j, slot) in leaves.iter_mut().enumerate().take(7) {
            // Use modulo-256 sentinel so loop never overflows for large
            // `k_hops` (e.g. 300 hops).
            *slot = [(0x10u16.wrapping_add(i as u16) & 0xFF) as u8; 32];
            slot[0] = j as u8;
        }
        leaves[7] = l7;

        let computed_block_id = block_merkle_root(&leaves);
        block_ids[i + 1] = computed_block_id;

        let salted_end_block_id = compute_salted_block_id_native(salt, &computed_block_id);

        let block_merkle_leaf_proof_l7 = block_merkle_leaf_proof(&leaves, 7);
        let proof_block_ref_inner_path = proof_block_ref_inner_path_native(&proof_block_refs, 0);

        let salted_start_block_id = if i == 0 {
            bundle_head_salted
        } else {
            compute_salted_block_id_native(salt, &block_ids[i])
        };

        hops.push(HopWitness {
            is_active: true,
            block: BlockWitness {
                block_id: computed_block_id,
                block_merkle_tree_leaves: leaves,
                proof_block_refs,
            },
            block_merkle_leaf_proof_l7,
            ref_index: 0,
            proof_block_ref_inner_path,
            salted_start_block_id,
            salted_end_block_id,
        });
    }

    let final_terminal_salted = if k_hops == 0 {
        bundle_head_salted
    } else {
        hops[k_hops - 1].salted_end_block_id
    };

    while hops.len() < total_slots {
        let zero_leaves = [[0u8; 32]; BLOCK_MERKLE_LEAF_COUNT];
        let zero_l7_proof = [[0u8; 32]; BLOCK_MERKLE_DEPTH];
        let zero_inner_path = [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH];
        hops.push(HopWitness {
            is_active: false,
            block: BlockWitness {
                block_id: [0u8; 32],
                block_merkle_tree_leaves: zero_leaves,
                proof_block_refs: Vec::new(),
            },
            block_merkle_leaf_proof_l7: zero_l7_proof,
            ref_index: 0,
            proof_block_ref_inner_path: zero_inner_path,
            salted_start_block_id: final_terminal_salted,
            salted_end_block_id: final_terminal_salted,
        });
    }

    SynthChain {
        sk_u,
        salt,
        salt_commitment,
        hops,
        bundle_head_salted,
        block_ids,
    }
}

/// Vec-returning splitter for arbitrary `n_bundle`. The returned `Vec` has
/// length `n_bundle`; each `MultiHopProofWitness` still holds the locked
/// `H_HOPS_PER_PROOF` hops.
pub fn split_into_bundle_snarks_n(
    chain: &SynthChain,
    n_bundle: usize,
) -> Vec<MultiHopProofWitness> {
    assert_eq!(
        chain.hops.len(),
        n_bundle * H_HOPS_PER_PROOF,
        "chain hop count {} does not match n_bundle ({}) * H ({})",
        chain.hops.len(),
        n_bundle,
        H_HOPS_PER_PROOF,
    );
    let mut snarks: Vec<MultiHopProofWitness> = Vec::with_capacity(n_bundle);
    for snark_idx in 0..n_bundle {
        let mut snark_hops: Vec<HopWitness> = Vec::with_capacity(H_HOPS_PER_PROOF);
        for h in 0..H_HOPS_PER_PROOF {
            let global = snark_idx * H_HOPS_PER_PROOF + h;
            snark_hops.push(chain.hops[global].clone());
        }
        let arr: [HopWitness; H_HOPS_PER_PROOF] = snark_hops
            .try_into()
            .unwrap_or_else(|v: Vec<HopWitness>| panic!("hop slot count {}", v.len()));
        snarks.push(MultiHopProofWitness {
            hops: arr,
            salt_commitment: chain.salt_commitment,
        });
    }
    snarks
}

/// Split a `synth_chain` output into `N_BUNDLE` `MultiHopProofWitness` snarks,
/// each carrying `H_HOPS_PER_PROOF` consecutive hops.
pub fn split_into_bundle_snarks(chain: &SynthChain) -> [MultiHopProofWitness; N_BUNDLE] {
    let mut snarks: Vec<MultiHopProofWitness> = Vec::with_capacity(N_BUNDLE);
    for snark_idx in 0..N_BUNDLE {
        let mut snark_hops: Vec<HopWitness> = Vec::with_capacity(H_HOPS_PER_PROOF);
        for h in 0..H_HOPS_PER_PROOF {
            let global = snark_idx * H_HOPS_PER_PROOF + h;
            snark_hops.push(chain.hops[global].clone());
        }
        let arr: [HopWitness; H_HOPS_PER_PROOF] = snark_hops
            .try_into()
            .unwrap_or_else(|v: Vec<HopWitness>| panic!("hop slot count {}", v.len()));
        snarks.push(MultiHopProofWitness {
            hops: arr,
            salt_commitment: chain.salt_commitment,
        });
    }
    snarks
        .try_into()
        .unwrap_or_else(|v: Vec<MultiHopProofWitness>| panic!("snark count {}", v.len()))
}

#[cfg(test)]
mod synth_chain_tests {
    use super::*;
    use crate::multi_hop_witness::{
        verify_block_merkle_leaf_proof, verify_proof_block_ref_inner_path, ref_leaf_hash_native,
    };

    /// k_hops=0: degenerate inactive chain. All endpoints equal head.
    #[test]
    fn synth_chain_k0_all_inactive() {
        let c = synth_chain(0xC0FFEE, 0);
        assert_eq!(c.hops.len(), N_BUNDLE * H_HOPS_PER_PROOF);
        for h in &c.hops {
            assert!(!h.is_active);
            assert_eq!(h.salted_start_block_id, c.bundle_head_salted);
            assert_eq!(h.salted_end_block_id, c.bundle_head_salted);
        }
    }

    /// k_hops=5: one full active snark + 3 inactive snarks. Verify hop
    /// continuity, SHA-256 L7 openings, and Poseidon ref-tree openings.
    #[test]
    fn synth_chain_k5_continuity_and_openings() {
        let c = synth_chain(0xBADBABE, 5);

        // Continuity: hops[0].start == head; hops[i].end == hops[i+1].start.
        assert_eq!(c.hops[0].salted_start_block_id, c.bundle_head_salted);
        for i in 0..N_BUNDLE * H_HOPS_PER_PROOF - 1 {
            assert_eq!(
                c.hops[i].salted_end_block_id,
                c.hops[i + 1].salted_start_block_id,
                "continuity broken between hop {i} and hop {}",
                i + 1
            );
        }

        // For the 5 active hops: verify SHA-256 L7 proof + Poseidon ref opening.
        for i in 0..5 {
            let h = &c.hops[i];
            assert!(h.is_active);

            // L7 SHA-256 opening against block_id.
            assert!(
                verify_block_merkle_leaf_proof(
                    &h.block.block_id,
                    &h.block.block_merkle_tree_leaves[7],
                    7,
                    &h.block_merkle_leaf_proof_l7,
                ),
                "hop {i} L7 proof should verify"
            );

            // Ref-tree opening: leaf is `ref_leaf_hash_native(0, parent_id)`
            // and root is L7.
            let parent = h.block.proof_block_refs[h.ref_index];
            let leaf = ref_leaf_hash_native(h.ref_index, &parent);
            assert!(
                verify_proof_block_ref_inner_path(
                    &h.block.block_merkle_tree_leaves[7],
                    &leaf,
                    h.ref_index,
                    &h.proof_block_ref_inner_path,
                ),
                "hop {i} ref-tree opening should verify"
            );
        }

        // Inactive hops sit at terminal.
        let terminal = c.hops[4].salted_end_block_id;
        for i in 5..N_BUNDLE * H_HOPS_PER_PROOF {
            assert!(!c.hops[i].is_active);
            assert_eq!(c.hops[i].salted_start_block_id, terminal);
            assert_eq!(c.hops[i].salted_end_block_id, terminal);
        }
    }

    /// Splitting a K=5 chain into 4 snarks: snark 0 has all active hops,
    /// snarks 1..3 fully inactive, all share salt_commitment.
    #[test]
    fn split_into_4_snarks_active_distribution() {
        let c = synth_chain(0xDEADBEEF, 5);
        let snarks = split_into_bundle_snarks(&c);

        for snark in &snarks {
            assert_eq!(snark.salt_commitment, c.salt_commitment);
            assert_eq!(snark.hops.len(), H_HOPS_PER_PROOF);
        }

        // Snark 0: all 5 hops active.
        for h in &snarks[0].hops {
            assert!(h.is_active);
        }
        // Snarks 1..3: all inactive.
        for s in &snarks[1..] {
            for h in &s.hops {
                assert!(!h.is_active);
            }
        }
    }

    /// K=20 (max capacity): every hop active, single salt_commitment across
    /// all 4 snarks, chain endpoints chain end-to-end.
    #[test]
    fn synth_chain_k20_max_capacity() {
        let c = synth_chain(0x12345, 20);
        for h in &c.hops {
            assert!(h.is_active);
        }
        // Strict continuity along the full 20-hop chain.
        for i in 0..19 {
            assert_eq!(c.hops[i].salted_end_block_id, c.hops[i + 1].salted_start_block_id);
        }
        let snarks = split_into_bundle_snarks(&c);
        for s in &snarks {
            assert_eq!(s.salt_commitment, c.salt_commitment);
        }
    }
}
