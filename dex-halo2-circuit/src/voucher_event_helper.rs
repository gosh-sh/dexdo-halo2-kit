use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use std::fs;
use std::path::Path;

use crate::boc_helper::BocFlattenData;

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

/// Extract `voucher_nominal` and `token_type` from the child cell of an event BOC,
/// using big-endian byte-to-Fr conversion (matching the in-circuit extraction).
pub fn extract_event_public_fields(entries: &[BocFlattenData; 2]) -> (Fr, Fr) {
    let child_data = &entries[1].cell_repr_data;
    let voucher_bytes = &child_data[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END];
    let token_bytes = &child_data[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END];

    let mut voucher_nominal = Fr::from(0u64);
    for &b in voucher_bytes {
        voucher_nominal = voucher_nominal * Fr::from(256u64) + Fr::from(b as u64);
    }

    let mut token_type = Fr::from(0u64);
    for &b in token_bytes {
        token_type = token_type * Fr::from(256u64) + Fr::from(b as u64);
    }

    (voucher_nominal, token_type)
}
