//! Poseidon-hash-of-96-bytes helpers (3 × 32-byte inputs → 4 Fr chunks).
//!
//! Used across the Dark-DEX circuit for two-level tree leaf hashing:
//!   - `block_leaf   = Poseidon96(block_id, envelope_hash, tracked_ext_out_root)`
//!   - `ext_msg_leaf = Poseidon96(account_dapp_id, account_id, msg_repr_hash)`
//!
//! Both the native (off-circuit) and in-circuit (byte-flat) variants use
//! the same 31-byte-boundary chunking convention so the two agree bit-for-bit.

use gosh_dense_balanced_tree::{bytes_to_fr, fr_to_bytes, poseidon_hash_native, RATE, T};
use halo2_base::halo2_proofs::halo2curves::ff::Field as _;
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    halo2_proofs::halo2curves::bn256::Fr,
    poseidon::hasher::PoseidonHasher,
    AssignedValue, Context, QuantumCell,
};

/// Split 96 bytes at 31-byte boundaries into 4 LE Fr elements.
///
/// Chunk layout (matching `hash_bytes_flat` convention):
///   c0 = Fr(buf[0..31])   — 248 bits
///   c1 = Fr(buf[31..62])  — 248 bits
///   c2 = Fr(buf[62..93])  — 248 bits
///   c3 = Fr(buf[93..96])  — 24 bits
fn chunk_96_bytes_to_fr(buf: &[u8; 96]) -> (Fr, Fr, Fr, Fr) {
    let mut b0 = [0u8; 32];
    b0[..31].copy_from_slice(&buf[0..31]);
    let c0 = bytes_to_fr(&b0);

    let mut b1 = [0u8; 32];
    b1[..31].copy_from_slice(&buf[31..62]);
    let c1 = bytes_to_fr(&b1);

    let mut b2 = [0u8; 32];
    b2[..31].copy_from_slice(&buf[62..93]);
    let c2 = bytes_to_fr(&b2);

    let mut b3 = [0u8; 32];
    b3[..3].copy_from_slice(&buf[93..96]);
    let c3 = bytes_to_fr(&b3);

    (c0, c1, c2, c3)
}

/// Native (off-circuit): Poseidon hash of 3 × 32-byte inputs chunked at 31-byte boundaries.
///
/// Returns `fr_to_bytes(Poseidon(c0, c1, c2, c3))`.
pub(crate) fn poseidon_hash_96_native(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(a);
    buf[32..64].copy_from_slice(b);
    buf[64..96].copy_from_slice(c);
    let (c0, c1, c2, c3) = chunk_96_bytes_to_fr(&buf);
    let hash = poseidon_hash_native(&[c0, c1, c2, c3]);
    fr_to_bytes(hash)
}

/// Byte-flat Poseidon over `a ‖ b ‖ c` (96 bytes total).
///
/// Takes byte cells directly (with per-byte `range_check 8`), so each chunk
/// is uniquely determined by the witness. No `chunks_int ≡ Fr (mod p)`
/// malleability: the integer formed by `a_bytes ‖ b_bytes ‖ c_bytes` is
/// fully pinned by the per-byte range checks, and every chunk is < 2^248 < p
/// so equals its integer value in Fp.
///
/// Chunk layout (matching `hash_bytes_flat` / `chunk_96_bytes_to_fr`):
///   c0 = LE(buf[0..31])   c1 = LE(buf[31..62])
///   c2 = LE(buf[62..93])  c3 = LE(buf[93..96])
pub(crate) fn poseidon_hash_96_circuit_bytes(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    a_bytes: &[AssignedValue<Fr>; 32],
    b_bytes: &[AssignedValue<Fr>; 32],
    c_bytes: &[AssignedValue<Fr>; 32],
) -> AssignedValue<Fr> {
    let gate = range.gate();

    // Per-byte range checks pin each cell to [0, 256).
    for cells in [a_bytes, b_bytes, c_bytes] {
        for &cell in cells {
            range.range_check(ctx, cell, 8);
        }
    }

    // Powers of 256 LE, up to 30 (longest contiguous byte slice in any chunk).
    let powers_le_31: Vec<QuantumCell<Fr>> = (0..31)
        .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
        .collect();

    // c0 = LE(a[0..31])
    let c0 = {
        let cells: Vec<QuantumCell<Fr>> =
            a_bytes[0..31].iter().map(|c| QuantumCell::Existing(*c)).collect();
        gate.inner_product(ctx, cells, powers_le_31[..31].iter().cloned())
    };

    // c1 = a[31] + 256 · LE(b[0..30])
    let c1 = {
        let lo30 = {
            let cells: Vec<QuantumCell<Fr>> =
                b_bytes[0..30].iter().map(|c| QuantumCell::Existing(*c)).collect();
            gate.inner_product(ctx, cells, powers_le_31[..30].iter().cloned())
        };
        gate.mul_add(
            ctx,
            QuantumCell::Existing(lo30),
            QuantumCell::Constant(Fr::from(256u64)),
            QuantumCell::Existing(a_bytes[31]),
        )
    };

    // c2 = LE(b[30..32]) + 2^16 · LE(c[0..29])
    let c2 = {
        let hi_b = {
            let cells: Vec<QuantumCell<Fr>> =
                b_bytes[30..32].iter().map(|c| QuantumCell::Existing(*c)).collect();
            gate.inner_product(ctx, cells, powers_le_31[..2].iter().cloned())
        };
        let lo29 = {
            let cells: Vec<QuantumCell<Fr>> =
                c_bytes[0..29].iter().map(|c| QuantumCell::Existing(*c)).collect();
            gate.inner_product(ctx, cells, powers_le_31[..29].iter().cloned())
        };
        gate.mul_add(
            ctx,
            QuantumCell::Existing(lo29),
            QuantumCell::Constant(Fr::from(1u64 << 16)),
            QuantumCell::Existing(hi_b),
        )
    };

    // c3 = LE(c[29..32])
    let c3: AssignedValue<Fr> = {
        let cells: Vec<QuantumCell<Fr>> =
            c_bytes[29..32].iter().map(|c| QuantumCell::Existing(*c)).collect();
        gate.inner_product(ctx, cells, powers_le_31[..3].iter().cloned())
    };

    hasher.hash_fix_len_array(ctx, gate, &[c0, c1, c2, c3])
}
