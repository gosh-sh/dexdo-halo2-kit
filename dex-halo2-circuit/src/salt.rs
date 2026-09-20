//! Voucher-secret-derived salt and salted-block-id helpers.
//!
//! These native helpers MUST stay byte-for-byte equivalent to the in-circuit
//! gadgets in [`crate::dark_dex_circuit`] and [`crate::multi_hop_proof`]:
//! `RootPN.sol` checks `salt_commitment` equality across all snarks of a
//! bundle (`1 DexFinalProof + N MultiHopProof`), and the per-hop
//! `salted_block_id` continuity is what links adjacent hops. Any divergence
//! between the native derivation here and the in-circuit derivation breaks
//! the on-chain orchestrator.
//!
//! ## Public surface
//!
//! - [`DOMAIN_TAG_HOP_SALT_BYTES`] — the 30-byte ASCII tag prepended before
//!   `sk_u` in the salt derivation
//! - [`domain_tag_hop_salt_fr`] — packs the tag into a single `Fr` constant
//! - [`compute_salt_native`] — `salt = Poseidon([tag_fr, sk_u])`
//! - [`compute_salt_commitment_native`] — `salt_commitment = Poseidon([salt])`
//! - [`compute_salted_block_id_native`] —
//!   `Poseidon([salt_chunk0, salt_hi + 256·block_id_lo30, block_id_hi2, position])`
//!
//! ## Position tag (BC-005 anonymity fix)
//!
//! Each salted-block-id absorbs a **bundle-global position** as a 4th Poseidon
//! input. Positions run `0..=N_BUNDLE * H_HOPS_PER_PROOF` and are unique per
//! endpoint slot in the DexFinal + N × MultiHopProof composition:
//!
//! * DexFinal `salted_x_start` — position `0`
//! * MultiHop bundle `b`, hop `h` — start at `b·H+h`, end at `b·H+h+1`
//! * DexFinal `salted_y_end` — position `N_BUNDLE · H_HOPS_PER_PROOF`
//!
//! Without the position tag, in the same-thread (t=0) case the entire chain
//! collapses to a single value, and observers reading the public instances
//! could distinguish it from the cross-thread case by simple equality checks.
//! Mixing the position in makes every salted-block-id fresh Poseidon output
//! regardless of whether the underlying `block_id` is repeated.

use gosh_dense_balanced_tree::{bytes_to_fr, fr_to_bytes, poseidon_hash_native, RATE, T};
use halo2_base::gates::GateInstructions;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::{AssignedValue, Context, QuantumCell};

/// Domain-tag byte string used to bind the voucher's `sk_u` into the per-bundle
/// salt. Differentiates this salt from any other Poseidon image of `sk_u`
/// produced elsewhere (e.g. spend nullifier, deposit commitment).
///
/// This tag is part of the on-chain ABI: the `salt_commitment` instance value
/// of a DexFinalProof must equal the `salt_commitment` of every MultiHopProof
/// in the same bundle. Changing the tag bytes is a breaking change for any
/// previously-published proofs and for `RootPN.sol`'s salt-equality check.
pub const DOMAIN_TAG_HOP_SALT_BYTES: &[u8] = b"acki-nacki:voucher-hop-salt:v1";

/// Derive `DOMAIN_TAG_HOP_SALT_FR` from the ASCII tag bytes by zero-padding to
/// 32 LE-bytes and interpreting as `Fr`. The tag is shorter than 31 bytes so
/// this is collision-free with respect to other tags of the same encoding
/// family.
pub fn domain_tag_hop_salt_fr() -> Fr {
    assert!(
        DOMAIN_TAG_HOP_SALT_BYTES.len() <= 31,
        "DOMAIN_TAG_HOP_SALT_BYTES must fit in 31 LE bytes (one Fr) to keep \
         the in-circuit constant a single field element"
    );
    let mut buf = [0u8; 32];
    buf[..DOMAIN_TAG_HOP_SALT_BYTES.len()].copy_from_slice(DOMAIN_TAG_HOP_SALT_BYTES);
    bytes_to_fr(&buf)
}

/// Native: `salt = Poseidon([DOMAIN_TAG_HOP_SALT_FR, sk_u])`.
pub fn compute_salt_native(sk_u: Fr) -> Fr {
    poseidon_hash_native(&[domain_tag_hop_salt_fr(), sk_u])
}

/// Native: `salt_commitment = Poseidon([salt])`.
pub fn compute_salt_commitment_native(salt: Fr) -> Fr {
    poseidon_hash_native(&[salt])
}

/// Native: `salted_block_id = Poseidon([salt_chunk0, salt_hi + 256·lo30, hi2, position_fr])`.
///
/// The salt is decomposed as `salt = salt_chunk0 + 2^248 · salt_hi` (LE, 248+8
/// bits). The 32-byte block_id decomposes as `lo30` (bytes 0..30) and `hi2`
/// (bytes 30..32). The 4th Poseidon input is `position` — a bundle-global
/// counter that makes each salted endpoint slot a fresh Poseidon image even
/// when the same `(salt, block_id)` pair recurs across hops. See module docs
/// for the position enumeration.
///
/// This must stay byte-for-byte equivalent to
/// [`salted_block_id_poseidon_circuit`].
pub fn compute_salted_block_id_native(salt: Fr, block_id_le: &[u8; 32], position: u64) -> Fr {
    let salt_bytes = fr_to_bytes(salt);
    // salt = salt_chunk0 (bytes 0..31 LE) + 2^248 * salt_hi (byte 31)
    let mut chunk0_bytes = [0u8; 32];
    chunk0_bytes[..31].copy_from_slice(&salt_bytes[..31]);
    let salt_chunk0 = bytes_to_fr(&chunk0_bytes);
    let salt_hi = Fr::from(salt_bytes[31] as u64);

    // chunk1 = salt_hi + 256 * LE(block_id[0..30])
    let mut lo30_bytes = [0u8; 32];
    lo30_bytes[..30].copy_from_slice(&block_id_le[..30]);
    let block_id_lo30 = bytes_to_fr(&lo30_bytes);
    let chunk1 = salt_hi + Fr::from(256u64) * block_id_lo30;

    // chunk2 = LE(block_id[30..32])
    let chunk2 = Fr::from(block_id_le[30] as u64) + Fr::from(256u64) * Fr::from(block_id_le[31] as u64);

    poseidon_hash_native(&[salt_chunk0, chunk1, chunk2, Fr::from(position)])
}

/// In-circuit twin of [`compute_salted_block_id_native`].
///
/// Computes `Poseidon([salt_chunk0, chunk1, chunk2, position])` where
/// `chunk1 = salt_hi + 256 · LE(block_id_bytes[0..30])` and
/// `chunk2 = LE(block_id_bytes[30..32])`.
///
/// The `position` input is a bundle-global endpoint counter (see module
/// docs) that ensures each salted-block-id is a fresh Poseidon output
/// even when the same `(salt, block_id)` pair recurs across hops. Without
/// it, the same-thread (t=0) case would produce equal publics in a
/// pattern distinguishable from the cross-thread case.
///
/// Callers must supply:
///   * `salt_chunk0` / `salt_hi` — a prior 248+8-bit decomposition of the
///     salt Fr (constrained elsewhere to equal the Poseidon-derived `salt`).
///   * `powers_le_32` — a shared `[256^i]` table with at least 30 entries.
///   * `block_id_bytes` — exactly 32 cells, already range-checked to 8 bits.
///   * `position` — assigned cell holding the bundle-global position.
pub(crate) fn salted_block_id_poseidon_circuit(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    powers_le_32: &[QuantumCell<Fr>],
    salt_chunk0: AssignedValue<Fr>,
    salt_hi: AssignedValue<Fr>,
    block_id_bytes: &[AssignedValue<Fr>],
    position: AssignedValue<Fr>,
) -> AssignedValue<Fr> {
    assert_eq!(block_id_bytes.len(), 32, "block_id must be exactly 32 bytes");
    assert!(powers_le_32.len() >= 30, "powers_le_32 needs at least 30 entries");
    let block_id_lo30 = {
        let cells: Vec<QuantumCell<Fr>> = block_id_bytes[0..30]
            .iter()
            .map(|c| QuantumCell::Existing(*c))
            .collect();
        gate.inner_product(ctx, cells, powers_le_32[0..30].iter().cloned())
    };
    let chunk1 = gate.mul_add(
        ctx,
        QuantumCell::Existing(block_id_lo30),
        QuantumCell::Constant(Fr::from(256u64)),
        QuantumCell::Existing(salt_hi),
    );
    let chunk2 = {
        let cells: Vec<QuantumCell<Fr>> = block_id_bytes[30..32]
            .iter()
            .map(|c| QuantumCell::Existing(*c))
            .collect();
        gate.inner_product(ctx, cells, powers_le_32[0..2].iter().cloned())
    };
    hasher.hash_fix_len_array(ctx, gate, &[salt_chunk0, chunk1, chunk2, position])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: tag fits in 31 bytes.
    #[test]
    fn domain_tag_fits_in_one_fr() {
        assert!(DOMAIN_TAG_HOP_SALT_BYTES.len() <= 31);
        assert_eq!(DOMAIN_TAG_HOP_SALT_BYTES, b"acki-nacki:voucher-hop-salt:v1");
        // Force the panic path to not trigger.
        let _ = domain_tag_hop_salt_fr();
    }

    /// Determinism: the salt chain is purely functional.
    #[test]
    fn salt_chain_is_deterministic() {
        let sk_u = Fr::from(123456u64);
        let salt = compute_salt_native(sk_u);
        let comm = compute_salt_commitment_native(salt);
        let block_id = [7u8; 32];
        let salted = compute_salted_block_id_native(salt, &block_id, 0);

        assert_eq!(salt, compute_salt_native(sk_u));
        assert_eq!(comm, compute_salt_commitment_native(salt));
        assert_eq!(salted, compute_salted_block_id_native(salt, &block_id, 0));

        // Position tag: different positions produce different outputs.
        let salted_pos_1 = compute_salted_block_id_native(salt, &block_id, 1);
        assert_ne!(salted, salted_pos_1);
    }

    /// Different `sk_u` ⇒ different salt.
    #[test]
    fn different_sk_u_produce_different_salt() {
        let a = compute_salt_native(Fr::from(1u64));
        let b = compute_salt_native(Fr::from(2u64));
        assert_ne!(a, b);
    }
}
