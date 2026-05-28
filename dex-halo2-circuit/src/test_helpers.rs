use crate::boc_helper::*;
use crate::poseidon::*;
use dense_balanced_tree::{
    dense_merkle_proof, dense_merkle_root, PoseidonHasher as DensePoseidonHasher,
};
use gosh_dense_balanced_tree::{
    bytes_to_fr, fr_to_bytes, DenseChainLink, MAX_CHAIN_LEN,
};
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
        poseidon_hash(&[voucher_nominal_val, token_type_val, sk_u, sk_u_commit_val]);
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
