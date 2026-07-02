use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use std::fs;
use std::path::Path;

use crate::boc_helper::{serialize_cells_tree_root_first, BocFlattenData};
use gosh_dense_balanced_tree::poseidon_hash_native;
use tvm_block::{Deserializable, Message, Serializable};

pub const EVENT_BOC_DATA_BYTES_OFFSET: usize = 6;
pub const EVENT_SK_U_COMMIT_FIELD_LEN: usize = 32;
pub const EVENT_VOUCHER_NOMINAL_FIELD_LEN: usize = 32;
pub const EVENT_TOKEN_TYPE_FIELD_LEN: usize = 4;

pub const EVENT_SK_U_COMMIT_START: usize = EVENT_BOC_DATA_BYTES_OFFSET;
pub const EVENT_SK_U_COMMIT_END: usize = EVENT_SK_U_COMMIT_START + EVENT_SK_U_COMMIT_FIELD_LEN;
pub const EVENT_VOUCHER_NOMINAL_START: usize = EVENT_SK_U_COMMIT_END;
pub const EVENT_VOUCHER_NOMINAL_END: usize =
    EVENT_VOUCHER_NOMINAL_START + EVENT_VOUCHER_NOMINAL_FIELD_LEN;
pub const EVENT_TOKEN_TYPE_START: usize = EVENT_VOUCHER_NOMINAL_END;
pub const EVENT_TOKEN_TYPE_END: usize = EVENT_TOKEN_TYPE_START + EVENT_TOKEN_TYPE_FIELD_LEN;

pub struct EventData {
    pub sk_u: Fr,
    pub sk_u_commit: Fr,
    pub event_boc: String,
}

/// Parse a 64-char hex string into an `Fr` field element.
///
/// The hex encodes 32 bytes in little-endian order (as produced by
/// `Fr::to_repr()`). Pass directly to `Fr::from_repr`.
fn hex_to_fr(hex_str: &str) -> Fr {
    let bytes = hex::decode(hex_str).expect("invalid hex string");
    assert_eq!(bytes.len(), 32, "expected 32-byte hex value");
    let le_bytes: [u8; 32] = bytes.try_into().unwrap();
    Fr::from_repr(le_bytes).expect("hex value is not a valid Fr element")
}

/// Read event data from a vouchers file.
///
/// File format: repeating groups of 4 lines:
///   line 1: sk_u as 64-char hex
///   line 2: sk_u_commit as 64-char hex
///   line 3: event BOC as base64
///   line 4: blank
pub fn read_event_data_from_file(path: impl AsRef<Path>) -> Vec<EventData> {
    let content = fs::read_to_string(path).expect("failed to read vouchers file");
    let lines: Vec<&str> = content.lines().collect();

    let mut events = Vec::new();
    let mut i = 0;
    while i + 2 < lines.len() {
        let sk_u_hex = lines[i].trim();
        let sk_u_commit_hex = lines[i + 1].trim();
        let boc_base64 = lines[i + 2].trim();

        if sk_u_hex.is_empty() {
            i += 1;
            continue;
        }

        events.push(EventData {
            sk_u: hex_to_fr(sk_u_hex),
            sk_u_commit: hex_to_fr(sk_u_commit_hex),
            event_boc: boc_base64.to_string(),
        });

        i += 4; // skip blank line
    }

    events
}

/// Big-endian byte-to-Fr conversion for BOC field extraction (voucher_nominal, token_type).
pub fn bytes_to_fr_be(data: &[u8]) -> Fr {
    let mut val = Fr::from(0u64);
    for &byte in data.iter() {
        val = val * Fr::from(256u64) + Fr::from(byte as u64);
    }
    val
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
    let events = read_event_data_from_file("vouchers.txt");
    assert!(
        !events.is_empty(),
        "vouchers.txt must contain at least one entry"
    );
    let (entries, repr_hash) = parse_voucher_boc(&events[0].event_boc);
    extract_voucher_fields(events[0].sk_u, entries, repr_hash)
}
