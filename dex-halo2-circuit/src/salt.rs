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
//!   `hash_bytes_flat(fr_to_bytes(salt) ‖ block_id)`

use crate::multi_hop_witness::poseidon_bytes_flat_native;
use gosh_dense_balanced_tree::{bytes_to_fr, fr_to_bytes, poseidon_hash_native};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

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

/// Native: `salted_block_id = hash_bytes_flat(fr_to_bytes(salt) ‖ block_id_le)`.
///
/// The salt is serialised as its 32-byte LE field-element representation
/// (top byte < `0x40` because `salt < Fr_modulus`), concatenated with the
/// 32-byte block_id, and the 64-byte stream is fed through the byte-flat
/// Poseidon sponge. Every absorbed Fr chunk is guaranteed `< Fr_modulus`,
/// so no silent mod-p reduction.
pub fn compute_salted_block_id_native(salt: Fr, block_id_le: &[u8; 32]) -> Fr {
    let mut concat = [0u8; 64];
    concat[..32].copy_from_slice(&fr_to_bytes(salt));
    concat[32..].copy_from_slice(block_id_le);
    bytes_to_fr(&poseidon_bytes_flat_native(&concat))
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
        let salted = compute_salted_block_id_native(salt, &block_id);

        assert_eq!(salt, compute_salt_native(sk_u));
        assert_eq!(comm, compute_salt_commitment_native(salt));
        assert_eq!(salted, compute_salted_block_id_native(salt, &block_id));
    }

    /// Different `sk_u` ⇒ different salt.
    #[test]
    fn different_sk_u_produce_different_salt() {
        let a = compute_salt_native(Fr::from(1u64));
        let b = compute_salt_native(Fr::from(2u64));
        assert_ne!(a, b);
    }
}
