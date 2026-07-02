//! Depth-4 SHA-256 block_id tree constants and helpers used by
//! [`crate::dark_dex_circuit_new::DarkDexCircuitV2`].
//!
//! In V2 the block's `block_id` is defined as the SHA-256 root of a depth-4
//! binary tree over 16 fixed-position 32-byte leaves. Leaf 8 is the
//! `l8_tracked_ext_out_messages_root` (a Poseidon image); leaves 9..15 are
//! reserved / zero for now. Leaves 0..=7 are aggregated into an opaque
//! sibling `H07` that the prover supplies as a witness — the circuit does
//! not need to open its structure to bind `x_l8` into `x_block_id`.
//!
//! The depth-4 opening path from leaf-8 to root is:
//!   H8_9   = SHA(x_l8       || ZERO_LEAF)
//!   H8_11  = SHA(H8_9       || H10_11_CONST)
//!   H8_15  = SHA(H8_11      || H12_15_CONST)
//!   root   = SHA(H07        || H8_15)
//!
//! Only the two constants `H10_11_CONST = SHA(0x00 · 32 || 0x00 · 32)` and
//! `H12_15_CONST = SHA(H10_11_CONST || H10_11_CONST)` need to be shared
//! between prover and verifier — the circuit hard-codes them.

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// All-zero 32-byte leaf used to pad the depth-4 block_id SHA-tree.
pub const ZERO_LEAF: [u8; 32] = [0u8; 32];

fn sha256_of_two(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// SHA-256(ZERO_LEAF || ZERO_LEAF) — leaves 10..=11 aggregate.
pub fn h10_11_const() -> &'static [u8; 32] {
    static ONCE: OnceLock<[u8; 32]> = OnceLock::new();
    ONCE.get_or_init(|| sha256_of_two(&ZERO_LEAF, &ZERO_LEAF))
}

/// SHA-256(H10_11_CONST || H10_11_CONST) — leaves 12..=15 aggregate.
pub fn h12_15_const() -> &'static [u8; 32] {
    static ONCE: OnceLock<[u8; 32]> = OnceLock::new();
    ONCE.get_or_init(|| {
        let mid = *h10_11_const();
        sha256_of_two(&mid, &mid)
    })
}

/// Native helper: derive `block_id` from `x_l8` (leaf-8) and the opaque
/// aggregated left sibling `h07_sibling` (SHA-root of leaves 0..=7).
///
/// This is exactly what the in-circuit `assert_depth4_l8_opening_circuit`
/// gadget enforces bit-for-bit.
pub fn compute_block_id_from_l8_native(x_l8: &[u8; 32], h07_sibling: &[u8; 32]) -> [u8; 32] {
    let h8_9 = sha256_of_two(x_l8, &ZERO_LEAF);
    let h8_11 = sha256_of_two(&h8_9, h10_11_const());
    let h8_15 = sha256_of_two(&h8_11, h12_15_const());
    sha256_of_two(h07_sibling, &h8_15)
}

// ---------------------------------------------------------------------------
// In-circuit gadget
// ---------------------------------------------------------------------------

use gosh_sha256_chip::Sha256Chip;
use halo2_base::{
    gates::RangeInstructions,
    halo2_proofs::halo2curves::bn256::Fr,
    AssignedValue, Context,
};

/// Assert that `x_block_id_bytes = depth-4 SHA opening of (leaf=8, sibling_0..=7 = h07)`.
///
/// The four SHA compressions are performed with `sha_chip`. Byte cells are
/// assumed already range-checked to 8 bits by their creators (this gadget
/// re-range-checks the two sibling inputs it loads as witnesses).
pub fn assert_depth4_l8_opening_circuit<'a>(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    sha_chip: &Sha256Chip<'a, Fr>,
    x_l8_bytes: &[AssignedValue<Fr>; 32],
    h07_sibling_bytes: &[AssignedValue<Fr>; 32],
    x_block_id_bytes: &[AssignedValue<Fr>; 32],
) {
    // Load the two known-constant intermediate nodes as constant byte cells.
    let h10_11 = *h10_11_const();
    let h12_15 = *h12_15_const();
    let h10_11_cells: Vec<AssignedValue<Fr>> =
        h10_11.iter().map(|&b| ctx.load_constant(Fr::from(b as u64))).collect();
    let h12_15_cells: Vec<AssignedValue<Fr>> =
        h12_15.iter().map(|&b| ctx.load_constant(Fr::from(b as u64))).collect();

    // Range-check the sibling witness bytes (defensive; the caller should
    // already have witnessed these but we guarantee 8-bit constraints here).
    for &b in h07_sibling_bytes {
        range.range_check(ctx, b, 8);
    }

    // ZERO_LEAF as 32 constant zero cells.
    let zero_leaf_cells: Vec<AssignedValue<Fr>> =
        (0..32).map(|_| ctx.load_constant(Fr::zero())).collect();

    // H8_9 = SHA(x_l8 || ZERO_LEAF)
    let mut buf: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
    buf.extend_from_slice(x_l8_bytes);
    buf.extend_from_slice(&zero_leaf_cells);
    let h8_9 = sha_chip.digest_bytes(ctx, &buf);
    assert_eq!(h8_9.len(), 32);

    // H8_11 = SHA(H8_9 || H10_11_CONST)
    let mut buf: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
    buf.extend_from_slice(&h8_9);
    buf.extend_from_slice(&h10_11_cells);
    let h8_11 = sha_chip.digest_bytes(ctx, &buf);

    // H8_15 = SHA(H8_11 || H12_15_CONST)
    let mut buf: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
    buf.extend_from_slice(&h8_11);
    buf.extend_from_slice(&h12_15_cells);
    let h8_15 = sha_chip.digest_bytes(ctx, &buf);

    // root = SHA(h07_sibling || H8_15)
    let mut buf: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
    buf.extend_from_slice(h07_sibling_bytes);
    buf.extend_from_slice(&h8_15);
    let root_bytes = sha_chip.digest_bytes(ctx, &buf);

    // Constrain root_bytes == x_block_id_bytes.
    for i in 0..32 {
        ctx.constrain_equal(&root_bytes[i], &x_block_id_bytes[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_block_id_deterministic() {
        let l8 = [7u8; 32];
        let sib = [0xABu8; 32];
        let a = compute_block_id_from_l8_native(&l8, &sib);
        let b = compute_block_id_from_l8_native(&l8, &sib);
        assert_eq!(a, b);
    }

    #[test]
    fn h10_11_matches_direct_sha() {
        let expected = sha256_of_two(&[0u8; 32], &[0u8; 32]);
        assert_eq!(*h10_11_const(), expected);
    }
}
