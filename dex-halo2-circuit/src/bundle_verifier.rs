//! Pure-Rust mock of the **`RootPN.sol` bundle-acceptance gate**.
//!
//! A "claim bundle" is one `DexFinalProof` + zero or more `MultiHopProof`s
//! (canonically `N_BUNDLE = 4` MultiHops, see `MULTITHREAD_CIRCUIT_SPEC.md` §6).
//! `RootPN.sol` accepts a bundle iff:
//!
//!   1. exactly one `DexFinalProof` is present;
//!   2. `salt_commitment` is **identical across all snarks** in the bundle
//!      (the salt-binder check — prevents splicing proofs from different
//!      bundles together);
//!   3. the **head** of the hop chain is linked to the DexFinalProof:
//!      `DexFinal.salted_C_start == MultiHop[0].salted_start_block_id`;
//!   4. consecutive MultiHopProofs satisfy **chain continuity**:
//!      `MultiHop[i].salted_end_block_id == MultiHop[i+1].salted_start_block_id`.
//!
//! This module reproduces that logic in pure Rust against the proofs' public
//! instance vectors. There is no on-chain or `tvm-sdk` dependency — the goal
//! is to drive synthetic + real-prover bundle E2E tests without touching the
//! contract or the verifier inside `tvm-sdk`.
//!
//! # Layouts
//!
//! `DexFinalProof` is 7 instances, as produced by `DarkDexCircuit`:
//! ```text
//!   [0] poseidon_commitment       (= depositIdentifierHash)
//!   [1] final_root                (= finalLayerHistoricalHashRoot)
//!   [2] voucher_nominal
//!   [3] token_type
//!   [4] ephemeral_pubkey
//!   [5] salt_commitment           ← used by check (2)
//!   [6] event_salted_block_id     ← used by check (3) as the "bundle head"
//! ```
//!
//! `MultiHopProof` is 3 instances (`MULTITHREAD_CIRCUIT_SPEC.md` §6.9):
//! ```text
//!   [0] salted_start_block_id
//!   [1] salted_end_block_id
//!   [2] salt_commitment
//! ```

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Tag identifying which kind of snark a `BundleProof` is.
///
/// The verifier dispatches on this to pick the right field offsets when
/// reading the proof's public instance vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// `DexFinalProof`. 7 instances.
    DexFinal,
    /// `MultiHopProof`. Always 3 instances.
    MultiHop,
}

/// One snark contributing to a claim bundle.
///
/// `instances` is the public-input vector exactly as it appears in the
/// proof's instance column (one `Fr` per instance slot, in declaration
/// order). The verifier does *not* call any halo2 verifier — it consumes
/// only the public instances, the same way `RootPN.sol` does.
#[derive(Debug, Clone)]
pub struct BundleProof {
    pub kind: ProofKind,
    pub instances: Vec<Fr>,
}

impl BundleProof {
    pub fn new_dex_final(instances: Vec<Fr>) -> Self {
        Self { kind: ProofKind::DexFinal, instances }
    }
    pub fn new_multi_hop(instances: Vec<Fr>) -> Self {
        Self { kind: ProofKind::MultiHop, instances }
    }
}

/// Reasons `verify_bundle` rejects a bundle.
///
/// Every variant mirrors one of the four checks (1)–(4) from the module
/// docs, plus structural sanity errors for malformed input.
#[derive(Debug, PartialEq, Eq)]
pub enum BundleError {
    /// The bundle has zero `DexFinalProof`s. Check (1) — `RootPN.sol`
    /// requires exactly one.
    MissingDexFinal,
    /// More than one `DexFinalProof` in the bundle. Check (1).
    DuplicateDexFinal { count: usize },
    /// The `DexFinalProof` is not at position 0 in the bundle. Convention
    /// (matches `RootPN.sol`'s `(dexProof, hopProofs[])` argument split):
    /// `bundle[0]` must be the DexFinal.
    DexFinalNotFirst { found_at: usize },
    /// A proof's instance-vector length doesn't match its declared `kind`.
    /// `expected_one_of` enumerates every accepted length for that kind
    /// (DexFinal: 7; MultiHop: 3).
    BadInstanceLen {
        proof_index: usize,
        kind: ProofKind,
        got: usize,
        expected_one_of: &'static [usize],
    },
    /// `salt_commitment` differs between snarks. Check (2). `first` is
    /// `bundle[0]`'s salt_commitment; `mismatch_at` is the index of the
    /// first snark that disagrees.
    SaltCommitmentMismatch { first: Fr, mismatch_at: usize, got: Fr },
    /// `DexFinal.event_salted_block_id` does not equal `bundle[1].salted_start_block_id`.
    /// Check (3). Only fires when there is at least one MultiHop in the bundle.
    HeadLinkBreak { dex_final_head: Fr, first_hop_start: Fr },
    /// `bundle[i].salted_end_block_id != bundle[i+1].salted_start_block_id`. Check (4).
    ContinuityBreak {
        between_hops: (usize, usize),
        salted_end_block_id: Fr,
        salted_start_block_id: Fr,
    },
}

// ---------------------------------------------------------------------------
// Instance-vector field offsets
// ---------------------------------------------------------------------------

/// `DarkDexCircuit` `DexFinalProof` instance count.
pub const DEX_FINAL_LEN: usize = 7;
/// `MultiHopProof` instance count (spec §6.9).
pub const MULTI_HOP_LEN: usize = 3;

const DEX_FINAL_LENGTHS: &[usize] = &[DEX_FINAL_LEN];
const MULTI_HOP_LENGTHS: &[usize] = &[MULTI_HOP_LEN];

/// MultiHop offsets per spec §6.9.
mod multihop_offset {
    pub const SALTED_START_BLOCK_ID: usize = 0;
    pub const SALTED_END_BLOCK_ID: usize = 1;
    pub const SALT_COMMITMENT: usize = 2;
}

/// DexFinal offsets — `DarkDexCircuit`'s 7-instance layout.
mod dexfinal_offset {
    pub const SALT_COMMITMENT: usize = 5;
    pub const HEAD_BLOCK_ID: usize = 6; // event_salted_block_id
}

// ---------------------------------------------------------------------------
// Field accessors (layout-aware)
// ---------------------------------------------------------------------------

/// Extract `salt_commitment` from any kind of proof.
///
/// Returns `BadInstanceLen` for malformed inputs.
pub fn salt_commitment(p: &BundleProof, proof_index: usize) -> Result<Fr, BundleError> {
    match p.kind {
        ProofKind::DexFinal => {
            if p.instances.len() == DEX_FINAL_LEN {
                Ok(p.instances[dexfinal_offset::SALT_COMMITMENT])
            } else {
                Err(BundleError::BadInstanceLen {
                    proof_index,
                    kind: ProofKind::DexFinal,
                    got: p.instances.len(),
                    expected_one_of: DEX_FINAL_LENGTHS,
                })
            }
        }
        ProofKind::MultiHop => {
            if p.instances.len() == MULTI_HOP_LEN {
                Ok(p.instances[multihop_offset::SALT_COMMITMENT])
            } else {
                Err(BundleError::BadInstanceLen {
                    proof_index,
                    kind: ProofKind::MultiHop,
                    got: p.instances.len(),
                    expected_one_of: MULTI_HOP_LENGTHS,
                })
            }
        }
    }
}

/// Extract the "bundle head" — the salted block_id that the first
/// MultiHopProof's `salted_start_block_id` must equal. This is
/// `event_salted_block_id` at instance [6].
pub fn dex_final_head(p: &BundleProof, proof_index: usize) -> Result<Fr, BundleError> {
    if p.kind != ProofKind::DexFinal || p.instances.len() != DEX_FINAL_LEN {
        return Err(BundleError::BadInstanceLen {
            proof_index,
            kind: p.kind,
            got: p.instances.len(),
            expected_one_of: DEX_FINAL_LENGTHS,
        });
    }
    Ok(p.instances[dexfinal_offset::HEAD_BLOCK_ID])
}

pub fn multihop_salted_start_block_id(p: &BundleProof, proof_index: usize) -> Result<Fr, BundleError> {
    if p.kind != ProofKind::MultiHop || p.instances.len() != MULTI_HOP_LEN {
        return Err(BundleError::BadInstanceLen {
            proof_index,
            kind: p.kind,
            got: p.instances.len(),
            expected_one_of: MULTI_HOP_LENGTHS,
        });
    }
    Ok(p.instances[multihop_offset::SALTED_START_BLOCK_ID])
}

pub fn multihop_salted_end_block_id(p: &BundleProof, proof_index: usize) -> Result<Fr, BundleError> {
    if p.kind != ProofKind::MultiHop || p.instances.len() != MULTI_HOP_LEN {
        return Err(BundleError::BadInstanceLen {
            proof_index,
            kind: p.kind,
            got: p.instances.len(),
            expected_one_of: MULTI_HOP_LENGTHS,
        });
    }
    Ok(p.instances[multihop_offset::SALTED_END_BLOCK_ID])
}

// ---------------------------------------------------------------------------
// Bundle verifier
// ---------------------------------------------------------------------------

/// Run all four `RootPN.sol` bundle-acceptance checks against an in-Rust
/// list of proofs. `bundle[0]` must be the `DexFinalProof`; `bundle[1..]`
/// are `MultiHopProof`s in hop-chain order (head first).
///
/// Returns `Ok(())` iff the bundle would be accepted by `RootPN.sol`.
///
/// **Does not** verify the underlying halo2 proofs — that's the prover/VK's
/// job. This is purely the public-input gate that the on-chain contract
/// runs on top of successful snark verification.
pub fn verify_bundle(bundle: &[BundleProof]) -> Result<(), BundleError> {
    // ---- check (1): exactly one DexFinal, at position 0 ----
    let dex_final_count = bundle.iter().filter(|p| p.kind == ProofKind::DexFinal).count();
    if dex_final_count == 0 {
        return Err(BundleError::MissingDexFinal);
    }
    if dex_final_count > 1 {
        return Err(BundleError::DuplicateDexFinal { count: dex_final_count });
    }
    // `bundle` is non-empty here (dex_final_count == 1).
    if bundle[0].kind != ProofKind::DexFinal {
        let found_at = bundle.iter().position(|p| p.kind == ProofKind::DexFinal).unwrap();
        return Err(BundleError::DexFinalNotFirst { found_at });
    }

    // ---- check (2): salt_commitment equality across all snarks ----
    let canonical_salt_commitment = salt_commitment(&bundle[0], 0)?;
    for (i, p) in bundle.iter().enumerate().skip(1) {
        let sc = salt_commitment(p, i)?;
        if sc != canonical_salt_commitment {
            return Err(BundleError::SaltCommitmentMismatch {
                first: canonical_salt_commitment,
                mismatch_at: i,
                got: sc,
            });
        }
    }

    // No MultiHops → checks (3) and (4) vacuous. Bundle is valid: a degenerate
    // single-proof claim (e.g. event in thread 0, K = 0 real hops).
    if bundle.len() == 1 {
        return Ok(());
    }

    // ---- check (3): head linkage ----
    let head = dex_final_head(&bundle[0], 0)?;
    let first_hop_start = multihop_salted_start_block_id(&bundle[1], 1)?;
    if head != first_hop_start {
        return Err(BundleError::HeadLinkBreak {
            dex_final_head: head,
            first_hop_start,
        });
    }

    // ---- check (4): continuity between consecutive MultiHops ----
    for i in 1..bundle.len() - 1 {
        let salted_end_block_id = multihop_salted_end_block_id(&bundle[i], i)?;
        let salted_start_block_id_next = multihop_salted_start_block_id(&bundle[i + 1], i + 1)?;
        if salted_end_block_id != salted_start_block_id_next {
            return Err(BundleError::ContinuityBreak {
                between_hops: (i, i + 1),
                salted_end_block_id,
                salted_start_block_id: salted_start_block_id_next,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ------------------------------------------------------------

    /// Build a DexFinal instance vector with the given `salt_commitment` and
    /// `head_block_id`. Other slots are filled with distinguishable sentinels
    /// so tests can spot accidental cross-talk.
    fn make_dex_final(salt_commitment: Fr, head_block_id: Fr) -> BundleProof {
        BundleProof::new_dex_final(vec![
            Fr::from(101u64), // [0] poseidon_commitment
            Fr::from(102u64), // [1] final_root
            Fr::from(103u64), // [2] voucher_nominal
            Fr::from(104u64), // [3] token_type
            Fr::from(105u64), // [4] ephemeral_pubkey
            salt_commitment,  // [5]
            head_block_id,    // [6] event_salted_block_id
        ])
    }

    fn multi_hop(salted_start_block_id: Fr, salted_end_block_id: Fr, salt_commitment: Fr) -> BundleProof {
        BundleProof::new_multi_hop(vec![salted_start_block_id, salted_end_block_id, salt_commitment])
    }

    // -- happy paths --------------------------------------------------------

    #[test]
    fn single_dex_final_phase3_ok() {
        let sc = Fr::from(0xC0FFEEu64);
        let head = Fr::from(0xBEEFu64);
        let b = vec![make_dex_final(sc, head)];
        assert_eq!(verify_bundle(&b), Ok(()));
    }

    #[test]
    fn full_bundle_phase3_dexfinal_plus_four_multihops_ok() {
        // Mirrors the canonical N_BUNDLE = 4 layout. Chain endpoints:
        //   DexFinal.head -> hop[0].start
        //   hop[0].end    -> hop[1].start
        //   hop[1].end    -> hop[2].start
        //   hop[2].end    -> hop[3].start
        //   hop[3].end    -> (terminal; not checked)
        let sc = Fr::from(0xA11C0FFEEu64);
        let p0 = Fr::from(1000u64);
        let p1 = Fr::from(1001u64);
        let p2 = Fr::from(1002u64);
        let p3 = Fr::from(1003u64);
        let p4 = Fr::from(1004u64);

        let b = vec![
            make_dex_final(sc, p0),
            multi_hop(p0, p1, sc),
            multi_hop(p1, p2, sc),
            multi_hop(p2, p3, sc),
            multi_hop(p3, p4, sc),
        ];
        assert_eq!(verify_bundle(&b), Ok(()));
    }

    #[test]
    fn inactive_hops_with_salted_start_block_id_eq_salted_end_block_id_ok() {
        // §6.4: when a MultiHopProof is `is_active = 0` everywhere, the
        // circuit constrains `salted_start_block_id == salted_end_block_id`. Bundle continuity
        // then degenerates to all-equal salted endpoints.
        let sc = Fr::from(7u64);
        let p = Fr::from(42u64); // the shared "no progress" endpoint
        let b = vec![
            make_dex_final(sc, p),
            multi_hop(p, p, sc),
            multi_hop(p, p, sc),
            multi_hop(p, p, sc),
            multi_hop(p, p, sc),
        ];
        assert_eq!(verify_bundle(&b), Ok(()));
    }

    // -- check (1): DexFinal presence/uniqueness/position -------------------

    #[test]
    fn empty_bundle_rejected() {
        let b: Vec<BundleProof> = vec![];
        assert_eq!(verify_bundle(&b), Err(BundleError::MissingDexFinal));
    }

    #[test]
    fn no_dex_final_rejected() {
        let sc = Fr::from(7u64);
        let b = vec![multi_hop(Fr::from(1u64), Fr::from(2u64), sc)];
        assert_eq!(verify_bundle(&b), Err(BundleError::MissingDexFinal));
    }

    #[test]
    fn two_dex_finals_rejected() {
        let sc = Fr::from(9u64);
        let b = vec![
            make_dex_final(sc, Fr::from(1u64)),
            make_dex_final(sc, Fr::from(1u64)),
        ];
        assert_eq!(verify_bundle(&b), Err(BundleError::DuplicateDexFinal { count: 2 }));
    }

    #[test]
    fn dex_final_not_first_rejected() {
        let sc = Fr::from(9u64);
        let b = vec![
            multi_hop(Fr::from(1u64), Fr::from(2u64), sc),
            make_dex_final(sc, Fr::from(1u64)),
        ];
        assert_eq!(verify_bundle(&b), Err(BundleError::DexFinalNotFirst { found_at: 1 }));
    }

    // -- check (2): salt_commitment equality --------------------------------

    #[test]
    fn salt_commitment_mismatch_on_first_hop_rejected() {
        let sc = Fr::from(11u64);
        let evil = Fr::from(12u64);
        let p0 = Fr::from(100u64);
        let p1 = Fr::from(101u64);
        let b = vec![
            make_dex_final(sc, p0),
            multi_hop(p0, p1, evil),
        ];
        match verify_bundle(&b) {
            Err(BundleError::SaltCommitmentMismatch { first, mismatch_at, got }) => {
                assert_eq!(first, sc);
                assert_eq!(mismatch_at, 1);
                assert_eq!(got, evil);
            }
            other => panic!("expected SaltCommitmentMismatch, got {:?}", other),
        }
    }

    #[test]
    fn salt_commitment_mismatch_deep_in_bundle_rejected() {
        let sc = Fr::from(11u64);
        let evil = Fr::from(99u64);
        let p0 = Fr::from(100u64);
        let p1 = Fr::from(101u64);
        let p2 = Fr::from(102u64);
        let p3 = Fr::from(103u64);
        let b = vec![
            make_dex_final(sc, p0),
            multi_hop(p0, p1, sc),
            multi_hop(p1, p2, sc),
            multi_hop(p2, p3, evil), // spliced from a different bundle
        ];
        match verify_bundle(&b) {
            Err(BundleError::SaltCommitmentMismatch { mismatch_at, .. }) => {
                assert_eq!(mismatch_at, 3);
            }
            other => panic!("expected SaltCommitmentMismatch, got {:?}", other),
        }
    }

    // -- check (3): head linkage --------------------------------------------

    #[test]
    fn head_link_break_rejected() {
        let sc = Fr::from(11u64);
        let head = Fr::from(100u64);
        let wrong_start = Fr::from(999u64);
        let b = vec![
            make_dex_final(sc, head),
            multi_hop(wrong_start, Fr::from(101u64), sc),
        ];
        match verify_bundle(&b) {
            Err(BundleError::HeadLinkBreak { dex_final_head, first_hop_start }) => {
                assert_eq!(dex_final_head, head);
                assert_eq!(first_hop_start, wrong_start);
            }
            other => panic!("expected HeadLinkBreak, got {:?}", other),
        }
    }

    // -- check (4): continuity between hops ---------------------------------

    #[test]
    fn continuity_break_between_hop1_and_hop2_rejected() {
        let sc = Fr::from(11u64);
        let p0 = Fr::from(100u64);
        let p1 = Fr::from(101u64);
        let wrong = Fr::from(999u64);
        let p2 = Fr::from(102u64);
        let b = vec![
            make_dex_final(sc, p0),
            multi_hop(p0, p1, sc),
            multi_hop(wrong, p2, sc), // start ≠ previous end
        ];
        match verify_bundle(&b) {
            Err(BundleError::ContinuityBreak { between_hops, salted_end_block_id, salted_start_block_id }) => {
                assert_eq!(between_hops, (1, 2));
                assert_eq!(salted_end_block_id, p1);
                assert_eq!(salted_start_block_id, wrong);
            }
            other => panic!("expected ContinuityBreak, got {:?}", other),
        }
    }

    // -- malformed inputs ---------------------------------------------------

    #[test]
    fn dex_final_with_wrong_instance_count_rejected() {
        let bad = BundleProof::new_dex_final(vec![Fr::from(1u64); 6]); // not 7
        let b = vec![bad];
        match verify_bundle(&b) {
            Err(BundleError::BadInstanceLen { proof_index, kind, got, .. }) => {
                assert_eq!(proof_index, 0);
                assert_eq!(kind, ProofKind::DexFinal);
                assert_eq!(got, 6);
            }
            other => panic!("expected BadInstanceLen, got {:?}", other),
        }
    }

    #[test]
    fn multihop_with_wrong_instance_count_rejected() {
        let sc = Fr::from(7u64);
        let bad = BundleProof::new_multi_hop(vec![Fr::from(1u64); 2]); // not 3
        let b = vec![make_dex_final(sc, Fr::from(1u64)), bad];
        match verify_bundle(&b) {
            Err(BundleError::BadInstanceLen { proof_index, kind, got, .. }) => {
                assert_eq!(proof_index, 1);
                assert_eq!(kind, ProofKind::MultiHop);
                assert_eq!(got, 2);
            }
            other => panic!("expected BadInstanceLen, got {:?}", other),
        }
    }
}
