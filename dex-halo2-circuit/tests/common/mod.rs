//! Shared fixture loading, parsing, and native instance computation for
//! `test_mock_prover.rs`, `test_dark_dex.rs`, and `test_export_tvm_sdk.rs`.

// Each integration test compiles `common` independently, so any helper unused
// by a given test file trips `dead_code`. Suppress at the module level.
#![allow(dead_code)]

use dex_halo2_circuit::boc_helper::{serialize_cells_tree_root_first, BocFlattenData};
use dex_halo2_circuit::dark_dex_circuit_new::DarkDexCircuitNew;
use dex_halo2_circuit::poseidon::poseidon_hash;
use gosh_dense_balanced_tree::{
    bytes_to_fr, compute_root_native, fr_to_bytes, preprocess_dense_proof, DenseChainLink,
    MAX_CHAIN_LEN,
};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use serde::Deserialize;
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

// ---------------------------------------------------------------------------
// JSON fixture structures
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChainLinkJson {
    pub active: bool,
    pub siblings_hex: Vec<String>,
    pub position: usize,
    pub leaf_hex: String,
}

#[derive(Deserialize)]
pub struct DexFixtureJson {
    #[allow(dead_code)]
    pub description: String,
    pub sk_u_hex: String,
    #[serde(default)]
    pub ephemeral_pubkey_hex: String,
    pub event_boc_base64: String,
    pub events_proof_siblings_hex: Vec<String>,
    pub events_proof_position: usize,
    pub account_dapp_id_hex: String,
    pub account_id_hex: String,
    pub block_id_hex: String,
    pub envelope_hash_hex: String,
    pub block_proof_siblings_hex: Vec<String>,
    pub block_proof_position: usize,
    pub num_active_chain_steps: usize,
    pub dense_chain: Vec<ChainLinkJson>,
}

// ---------------------------------------------------------------------------
// Fixture discovery & loading
// ---------------------------------------------------------------------------

pub fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

pub fn discover_fixtures() -> Vec<std::path::PathBuf> {
    let dir = fixtures_dir();
    if !dir.exists() {
        return vec![];
    }
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("dex_fixture") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    paths
}

pub fn load_fixture(path: &std::path::Path) -> DexFixtureJson {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// Hex / byte helpers
// ---------------------------------------------------------------------------

pub fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hex string");
    assert_eq!(bytes.len(), 32, "expected 32-byte hex value, got {}", bytes.len());
    bytes.try_into().unwrap()
}

pub fn hex_to_fr(hex_str: &str) -> Fr {
    let bytes = hex_to_32(hex_str);
    Fr::from_repr(bytes).expect("hex value is not a valid Fr element")
}

/// Big-endian byte-to-Fr conversion for BOC field extraction.
pub fn bytes_to_fr_be(data: &[u8]) -> Fr {
    let mut val = Fr::from(0u64);
    for &byte in data.iter() {
        val = val * Fr::from(256u64) + Fr::from(byte as u64);
    }
    val
}

// ---------------------------------------------------------------------------
// Event field byte offsets in the child cell's cell_repr_data.
// ---------------------------------------------------------------------------

pub const EVENT_SK_U_COMMIT_START: usize = 6;
pub const EVENT_SK_U_COMMIT_END: usize = 38;
pub const EVENT_VOUCHER_NOMINAL_START: usize = 38;
pub const EVENT_VOUCHER_NOMINAL_END: usize = 70;
pub const EVENT_TOKEN_TYPE_START: usize = 70;
pub const EVENT_TOKEN_TYPE_END: usize = 74;

// ---------------------------------------------------------------------------
// Parsed fixture
// ---------------------------------------------------------------------------

pub struct ParsedFixture {
    pub sk_u: Fr,
    pub ephemeral_pubkey: Fr,
    pub entries: [BocFlattenData; 2],
    pub events_proof_siblings: Vec<[u8; 32]>,
    pub events_proof_position: usize,
    pub account_dapp_id: [u8; 32],
    pub account_id: [u8; 32],
    pub block_id: [u8; 32],
    pub envelope_hash_bytes: [u8; 32],
    pub block_proof_siblings: Vec<[u8; 32]>,
    pub block_proof_position: usize,
    pub dense_chain: Vec<DenseChainLink>,
    pub num_active_chain_steps: usize,
}

pub fn parse_fixture(json: &DexFixtureJson) -> ParsedFixture {
    let sk_u = hex_to_fr(&json.sk_u_hex);
    let ephemeral_pubkey = if json.ephemeral_pubkey_hex.is_empty() {
        Fr::from(0u64)
    } else {
        bytes_to_fr_be(&hex_to_32(&json.ephemeral_pubkey_hex))
    };

    let msg = Message::construct_from_base64(&json.event_boc_base64)
        .expect("Failed to parse event BOC");
    let msg_cell = msg.serialize().expect("Failed to serialize message");
    let serialized =
        serialize_cells_tree_root_first(&msg_cell).expect("Failed to flatten BOC");
    assert_eq!(serialized.len(), 2, "Expected exactly 2 cells in event BOC");
    let entries: [BocFlattenData; 2] = [serialized[0].clone(), serialized[1].clone()];

    let events_proof_siblings: Vec<[u8; 32]> = json
        .events_proof_siblings_hex
        .iter()
        .map(|s| hex_to_32(s))
        .collect();

    let block_proof_siblings: Vec<[u8; 32]> = json
        .block_proof_siblings_hex
        .iter()
        .map(|s| hex_to_32(s))
        .collect();

    let mut dense_chain: Vec<DenseChainLink> = json
        .dense_chain
        .iter()
        .map(|link| DenseChainLink {
            active: link.active,
            siblings: link.siblings_hex.iter().map(|s| hex_to_32(s)).collect(),
            position: link.position,
            leaf_native: hex_to_32(&link.leaf_hex),
        })
        .collect();

    assert!(
        dense_chain.len() <= MAX_CHAIN_LEN,
        "Dense chain too long: {} > {}",
        dense_chain.len(),
        MAX_CHAIN_LEN
    );

    // Pad to MAX_CHAIN_LEN with inactive links whose leaf equals the current
    // Merkle root; the circuit passes `current` as the leaf for inactive links
    // via gate.select, so the preprocess witnesses must match.
    if dense_chain.len() < MAX_CHAIN_LEN {
        let repr_hash = &entries[0].repr_hash;
        let ext_msg_leaf = poseidon_hash_96_native(
            &hex_to_32(&json.account_dapp_id_hex),
            &hex_to_32(&json.account_id_hex),
            repr_hash,
        );
        let ext_out_root_bytes = if events_proof_siblings.is_empty() {
            ext_msg_leaf
        } else {
            let events_proof = preprocess_dense_proof(
                ext_msg_leaf,
                &events_proof_siblings,
                json.events_proof_position,
            );
            fr_to_bytes(compute_root_native(&events_proof))
        };
        let block_leaf = poseidon_hash_96_native(
            &hex_to_32(&json.block_id_hex),
            &hex_to_32(&json.envelope_hash_hex),
            &ext_out_root_bytes,
        );
        let block_proof = preprocess_dense_proof(
            block_leaf,
            &block_proof_siblings,
            json.block_proof_position,
        );
        let root_1_fr = compute_root_native(&block_proof);

        let mut current = root_1_fr;
        for link in dense_chain.iter().filter(|l| l.active) {
            let proof = preprocess_dense_proof(link.leaf_native, &link.siblings, link.position);
            current = compute_root_native(&proof);
        }

        let padding_leaf = fr_to_bytes(current);
        let depth = if !dense_chain.is_empty() {
            dense_chain[0].siblings.len()
        } else {
            block_proof_siblings.len()
        };

        while dense_chain.len() < MAX_CHAIN_LEN {
            dense_chain.push(DenseChainLink::inactive(padding_leaf, depth));
        }
    }

    ParsedFixture {
        sk_u,
        ephemeral_pubkey,
        entries,
        events_proof_siblings,
        events_proof_position: json.events_proof_position,
        account_dapp_id: hex_to_32(&json.account_dapp_id_hex),
        account_id: hex_to_32(&json.account_id_hex),
        block_id: hex_to_32(&json.block_id_hex),
        envelope_hash_bytes: hex_to_32(&json.envelope_hash_hex),
        block_proof_siblings,
        block_proof_position: json.block_proof_position,
        dense_chain,
        num_active_chain_steps: json.num_active_chain_steps,
    }
}

// ---------------------------------------------------------------------------
// Native instance computation
// ---------------------------------------------------------------------------

/// Native poseidon_hash_96: hash 3 × 32-byte inputs with 31-byte chunking.
/// Must match the circuit's `poseidon_hash_96_native`.
pub fn poseidon_hash_96_native(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(a);
    buf[32..64].copy_from_slice(b);
    buf[64..96].copy_from_slice(c);

    let chunk = |start: usize, len: usize| -> Fr {
        let mut b32 = [0u8; 32];
        b32[..len].copy_from_slice(&buf[start..start + len]);
        bytes_to_fr(&b32)
    };

    let hash = poseidon_hash(&[chunk(0, 31), chunk(31, 31), chunk(62, 31), chunk(93, 3)]);
    fr_to_bytes(hash)
}

/// Compute the five public instances for the circuit:
/// `[poseidon_commitment, final_root, voucher_nominal, token_type, ephemeral_pubkey]`.
pub fn compute_instances(parsed: &ParsedFixture) -> Vec<Fr> {
    let child_data = &parsed.entries[1].cell_repr_data;

    let sk_u_commit_bytes: [u8; 32] = child_data
        [EVENT_SK_U_COMMIT_START..EVENT_SK_U_COMMIT_END]
        .try_into()
        .unwrap();
    let sk_u_commit_val = Fr::from_repr(sk_u_commit_bytes).unwrap();
    let voucher_nominal_val =
        bytes_to_fr_be(&child_data[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END]);
    let token_type_val =
        bytes_to_fr_be(&child_data[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END]);

    let poseidon_commitment = poseidon_hash(&[
        voucher_nominal_val,
        token_type_val,
        parsed.sk_u,
        sk_u_commit_val,
    ]);

    let repr_hash = &parsed.entries[0].repr_hash;
    let ext_msg_leaf = poseidon_hash_96_native(
        &parsed.account_dapp_id,
        &parsed.account_id,
        repr_hash,
    );

    let ext_out_root_bytes = if parsed.events_proof_siblings.is_empty() {
        ext_msg_leaf
    } else {
        let events_proof = preprocess_dense_proof(
            ext_msg_leaf,
            &parsed.events_proof_siblings,
            parsed.events_proof_position,
        );
        fr_to_bytes(compute_root_native(&events_proof))
    };

    let block_leaf_native = poseidon_hash_96_native(
        &parsed.block_id,
        &parsed.envelope_hash_bytes,
        &ext_out_root_bytes,
    );

    let block_proof = preprocess_dense_proof(
        block_leaf_native,
        &parsed.block_proof_siblings,
        parsed.block_proof_position,
    );
    let root_1_fr = compute_root_native(&block_proof);

    let final_root = if parsed.num_active_chain_steps == 0 {
        root_1_fr
    } else {
        let mut current = root_1_fr;
        for link in parsed.dense_chain.iter().take(parsed.num_active_chain_steps) {
            assert!(link.active);
            assert_eq!(fr_to_bytes(current), link.leaf_native, "Chain link leaf mismatch");
            let proof = preprocess_dense_proof(link.leaf_native, &link.siblings, link.position);
            current = compute_root_native(&proof);
        }
        current
    };

    vec![
        poseidon_commitment,
        final_root,
        voucher_nominal_val,
        token_type_val,
        parsed.ephemeral_pubkey,
    ]
}

// ---------------------------------------------------------------------------
// Circuit construction
// ---------------------------------------------------------------------------

pub fn build_circuit(parsed: ParsedFixture, params: BaseCircuitParams) -> DarkDexCircuitNew {
    DarkDexCircuitNew::new(
        parsed.sk_u,
        parsed.ephemeral_pubkey,
        parsed.entries,
        parsed.events_proof_siblings,
        parsed.events_proof_position,
        parsed.account_dapp_id,
        parsed.account_id,
        parsed.block_id,
        parsed.envelope_hash_bytes,
        parsed.block_proof_siblings,
        parsed.block_proof_position,
        parsed.dense_chain,
        parsed.num_active_chain_steps,
        params,
    )
}

pub fn build_circuit_for_proving(
    parsed: ParsedFixture,
    params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
) -> DarkDexCircuitNew {
    DarkDexCircuitNew::new_for_proving(
        parsed.sk_u,
        parsed.ephemeral_pubkey,
        parsed.entries,
        parsed.events_proof_siblings,
        parsed.events_proof_position,
        parsed.account_dapp_id,
        parsed.account_id,
        parsed.block_id,
        parsed.envelope_hash_bytes,
        parsed.block_proof_siblings,
        parsed.block_proof_position,
        parsed.dense_chain,
        parsed.num_active_chain_steps,
        params,
        break_points,
    )
}
