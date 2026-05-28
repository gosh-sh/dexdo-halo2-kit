use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use std::fs;
use std::path::Path;

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
