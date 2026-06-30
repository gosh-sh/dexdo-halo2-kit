//! Bundle-binding integration test.
//!
//! Wires together the **real** salt math from `dex_halo2_circuit::salt` with
//! the pure-Rust `RootPN.sol` mock from `dex_halo2_circuit::bundle_verifier`,
//! on a synthetic 5-snark claim bundle (1 DexFinal + 4 MultiHops).
//!
//! No halo2 prover is invoked here — we synthesize the public-input vectors
//! using the same native helpers the in-circuit version constrains
//! (`compute_salt_native`, `compute_salt_commitment_native`,
//! `compute_salted_block_id_native`), then exercise the verifier on the
//! happy path and on every tampering vector that `verify_bundle` can
//! distinguish. The `synthesize_bundle_instances` helper is reusable with
//! **real** `gen_proof_with_instances` outputs instead of native synthesis —
//! the bundle-verifier API is shape-invariant.

use dex_halo2_circuit::bundle_verifier::{
    verify_bundle, BundleError, BundleProof, DEX_FINAL_LEN, MULTI_HOP_LEN,
};
use dex_halo2_circuit::salt::{
    compute_salt_commitment_native, compute_salt_native, compute_salted_block_id_native,
};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Number of MultiHopProofs per spec §6.4 (`N_BUNDLE`).
const N_BUNDLE: usize = 4;

/// Build a DexFinal instance vector with the given `salt_commitment`
/// and bundle-head `salted_block_id`. Slots [0..=4] are filled with
/// distinguishable sentinels — the verifier only reads [5] and [6].
fn make_dex_final_instances(salt_commitment: Fr, head_salted_block_id: Fr) -> Vec<Fr> {
    vec![
        Fr::from(0xD0u64),   // [0] poseidon_commitment (depositIdentifierHash)
        Fr::from(0xD1u64),   // [1] final_root
        Fr::from(0xD2u64),   // [2] voucher_nominal
        Fr::from(0xD3u64),   // [3] token_type
        Fr::from(0xD4u64),   // [4] ephemeral_pubkey
        salt_commitment,     // [5]
        head_salted_block_id, // [6] event_salted_block_id
    ]
}

/// MultiHop instance shape: `[salted_start_block_id, salted_end_block_id, salt_commitment]`.
fn multihop_instances(salted_start_block_id: Fr, salted_end_block_id: Fr, salt_commitment: Fr) -> Vec<Fr> {
    vec![salted_start_block_id, salted_end_block_id, salt_commitment]
}

/// Generate the full instance vectors for a synthetic 5-snark bundle.
///
/// Returns `(dex_final_instances, [hop_instances; N_BUNDLE])`. Endpoints chain
/// as: head → b_id[0] → b_id[1] → b_id[2] → b_id[3] → b_id[4] (terminal).
///
/// All `salt_commitment` slots get the same canonical value, derived from
/// `sk_u` via `compute_salt_native` then `compute_salt_commitment_native`.
fn synthesize_bundle_instances(sk_u: Fr, block_ids: &[[u8; 32]; 5]) -> (Vec<Fr>, [Vec<Fr>; N_BUNDLE]) {
    let salt = compute_salt_native(sk_u);
    let sc = compute_salt_commitment_native(salt);

    // Pre-compute compute_salted_block_id_native(salt, b_id) for every block_id.
    let salted: Vec<Fr> = block_ids
        .iter()
        .map(|b| compute_salted_block_id_native(salt, b))
        .collect();

    // DexFinal's bundle-head = `salted[0]` (i.e. salted_id of the
    // event-block-id we just claimed — same as what hop[0] starts from).
    let dex_final = make_dex_final_instances(sc, salted[0]);
    let hops = [
        multihop_instances(salted[0], salted[1], sc),
        multihop_instances(salted[1], salted[2], sc),
        multihop_instances(salted[2], salted[3], sc),
        multihop_instances(salted[3], salted[4], sc),
    ];

    (dex_final, hops)
}

/// Pack synthesized instance vectors into the `BundleProof` slice the
/// verifier consumes.
fn build_bundle(dex_final: Vec<Fr>, hops: [Vec<Fr>; N_BUNDLE]) -> Vec<BundleProof> {
    let mut bundle = Vec::with_capacity(1 + N_BUNDLE);
    bundle.push(BundleProof::new_dex_final(dex_final));
    for h in hops {
        bundle.push(BundleProof::new_multi_hop(h));
    }
    bundle
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: 1 DexFinal + 4 MultiHops, all derived from a single `sk_u` and
/// 5 distinct synthetic block_ids. RootPN mock accepts.
#[test]
fn synthetic_bundle_happy_path() {
    let sk_u = Fr::from(0x5EEDu64);
    let block_ids: [[u8; 32]; 5] = [
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
        [5u8; 32],
    ];

    let (dex_final, hops) = synthesize_bundle_instances(sk_u, &block_ids);

    // Sanity: shape matches what the verifier expects.
    assert_eq!(dex_final.len(), DEX_FINAL_LEN);
    for h in &hops {
        assert_eq!(h.len(), MULTI_HOP_LEN);
    }
    // Sanity: all salt_commitment slots agree.
    let canonical_sc = dex_final[5];
    for h in &hops {
        assert_eq!(h[2], canonical_sc);
    }

    let bundle = build_bundle(dex_final, hops);
    assert_eq!(verify_bundle(&bundle), Ok(()));
}

/// `salt_commitment` is genuinely a function of `sk_u`: two different users
/// produce different bundle commitments, so cross-bundle splicing is detected.
#[test]
fn different_sk_u_produce_different_salt_commitments() {
    let sc_a = {
        let s = compute_salt_native(Fr::from(1u64));
        compute_salt_commitment_native(s)
    };
    let sc_b = {
        let s = compute_salt_native(Fr::from(2u64));
        compute_salt_commitment_native(s)
    };
    assert_ne!(sc_a, sc_b);
}

/// Tamper with one hop's `salt_commitment` (splicing simulation) — verifier
/// must reject with `SaltCommitmentMismatch` pointing at the bad index.
#[test]
fn tampered_salt_commitment_in_hop2_rejected() {
    let sk_u = Fr::from(0xABCDu64);
    let block_ids: [[u8; 32]; 5] = [[10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32], [14u8; 32]];

    let (dex_final, mut hops) = synthesize_bundle_instances(sk_u, &block_ids);

    // Splice in a salt_commitment from a different user's bundle.
    let evil = {
        let other_salt = compute_salt_native(Fr::from(0xDEADu64));
        compute_salt_commitment_native(other_salt)
    };
    hops[2][2] = evil;

    let bundle = build_bundle(dex_final, hops);
    match verify_bundle(&bundle) {
        Err(BundleError::SaltCommitmentMismatch { mismatch_at, got, .. }) => {
            // hops[2] sits at bundle index 3 (DexFinal + 3 prior hops).
            assert_eq!(mismatch_at, 3);
            assert_eq!(got, evil);
        }
        other => panic!("expected SaltCommitmentMismatch, got {:?}", other),
    }
}

/// Tamper with a hop's `salted_start_block_id` — verifier must reject with
/// `ContinuityBreak`.
#[test]
fn tampered_continuity_break_rejected() {
    let sk_u = Fr::from(0xBEEFu64);
    let block_ids: [[u8; 32]; 5] = [[20u8; 32], [21u8; 32], [22u8; 32], [23u8; 32], [24u8; 32]];

    let (dex_final, mut hops) = synthesize_bundle_instances(sk_u, &block_ids);

    // Break the chain between hop[1] and hop[2]: change hop[2]'s salted_start_block_id.
    hops[2][0] = Fr::from(0xBADu64);

    let bundle = build_bundle(dex_final, hops);
    match verify_bundle(&bundle) {
        Err(BundleError::ContinuityBreak { between_hops, .. }) => {
            // hops[1] at bundle idx 2, hops[2] at bundle idx 3.
            assert_eq!(between_hops, (2, 3));
        }
        other => panic!("expected ContinuityBreak, got {:?}", other),
    }
}

/// Tamper with the DexFinal's head (`event_salted_block_id`, instance [6])
/// so it no longer equals hop[0]'s `salted_start_block_id` — must reject with
/// `HeadLinkBreak`.
#[test]
fn tampered_dex_final_head_rejected() {
    let sk_u = Fr::from(0xCAFEu64);
    let block_ids: [[u8; 32]; 5] = [[30u8; 32], [31u8; 32], [32u8; 32], [33u8; 32], [34u8; 32]];

    let (mut dex_final, hops) = synthesize_bundle_instances(sk_u, &block_ids);
    dex_final[6] = Fr::from(0xF00u64); // bad head

    let bundle = build_bundle(dex_final, hops);
    matches!(verify_bundle(&bundle), Err(BundleError::HeadLinkBreak { .. }));
    match verify_bundle(&bundle) {
        Err(BundleError::HeadLinkBreak { first_hop_start, dex_final_head }) => {
            assert_eq!(dex_final_head, Fr::from(0xF00u64));
            assert_ne!(first_hop_start, dex_final_head);
        }
        other => panic!("expected HeadLinkBreak, got {:?}", other),
    }
}

/// All-inactive hops (T=0 case, §6.4): the chain degenerates to
/// `salted_start_block_id == salted_end_block_id == event_salted_block_id`. The verifier
/// accepts; this confirms the verifier's continuity check doesn't
/// over-constrain the "no real hops" case.
#[test]
fn all_inactive_hops_t_eq_0_accepted() {
    let sk_u = Fr::from(0x111u64);
    let single_block: [u8; 32] = [99u8; 32];

    // For an all-inactive bundle, every salted endpoint equals
    // `Poseidon(salt, single_block_id)`.
    let salt = compute_salt_native(sk_u);
    let sc = compute_salt_commitment_native(salt);
    let p = compute_salted_block_id_native(salt, &single_block);

    let dex_final = make_dex_final_instances(sc, p);
    let hops = [
        multihop_instances(p, p, sc),
        multihop_instances(p, p, sc),
        multihop_instances(p, p, sc),
        multihop_instances(p, p, sc),
    ];
    let bundle = build_bundle(dex_final, hops);
    assert_eq!(verify_bundle(&bundle), Ok(()));
}

/// Splicing attempt: replace one hop wholesale with a hop from a different
/// `sk_u`'s bundle. The verifier should reject — the spliced hop carries the
/// wrong `salt_commitment`, so the salt-binder check fires before continuity
/// is even considered.
#[test]
fn cross_bundle_splice_rejected() {
    let sk_u_alice = Fr::from(0xA11CEu64);
    let sk_u_eve = Fr::from(0xE7Eu64);
    let block_ids: [[u8; 32]; 5] = [[40u8; 32], [41u8; 32], [42u8; 32], [43u8; 32], [44u8; 32]];

    let (alice_dex_final, mut alice_hops) = synthesize_bundle_instances(sk_u_alice, &block_ids);
    let (_eve_dex_final, eve_hops) = synthesize_bundle_instances(sk_u_eve, &block_ids);

    // Splice eve's hop[1] into the middle of alice's bundle.
    alice_hops[1] = eve_hops[1].clone();

    let bundle = build_bundle(alice_dex_final, alice_hops);
    match verify_bundle(&bundle) {
        Err(BundleError::SaltCommitmentMismatch { mismatch_at, .. }) => {
            // alice_hops[1] sits at bundle idx 2.
            assert_eq!(mismatch_at, 2);
        }
        other => panic!("expected SaltCommitmentMismatch from spliced hop, got {:?}", other),
    }
}
