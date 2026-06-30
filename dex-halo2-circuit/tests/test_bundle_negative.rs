//! Real-prover bundle negative tests.
//!
//! `bundle_verifier.rs` already has thorough negative coverage at the
//! synthetic instance-vector level. This test re-runs the same gate checks
//! against bundles assembled from **real KZG proofs**, to confirm that:
//!
//!   * a snark genuinely produced by `MultiHopProofCircuit` (and accepted
//!     by `check_proof_with_instances`) cannot be smuggled into a bundle
//!     that violates any of `RootPN.sol`'s four acceptance checks; and
//!   * the same proof's public instances trigger the same error path in
//!     `verify_bundle` as the synthetic stand-ins do.
//!
//! Cost optimization: only **two** real proofs are generated.
//!   1. `A.snark[0]` — 5 active hops, chain A's salt.
//!   2. `B.snark[0]` — 5 active hops, chain B's salt (different `sk_u`).
//!
//! Five negative scenarios are exercised by re-shuffling those two
//! proofs' instance vectors plus synthetic DexFinal entries:
//!
//!   * `SaltCommitmentMismatch` — bundle mixes A and B snarks.
//!   * `HeadLinkBreak` — DexFinal head ≠ first hop's `salted_start_block_id`.
//!   * `ContinuityBreak` — `A.snark[0]` placed at positions 1 *and* 2;
//!     its `salted_end_block_id` ≠ its own `salted_start_block_id`, so the continuity gate
//!     fires.
//!   * `DexFinalNotFirst` — DexFinal placed after a MultiHop.
//!   * `DuplicateDexFinal` — two DexFinal proofs in the bundle.
//!
//! `#[ignore]`; run with
//! `cargo test --release --test test_bundle_negative -- --ignored --nocapture`.

use dex_halo2_circuit::bundle_verifier::{
    verify_bundle, BundleError, BundleProof, DEX_FINAL_LEN,
};
use dex_halo2_circuit::multi_hop_proof::{MultiHopProofCircuit, MultiHopWitness};
use dex_halo2_circuit::multi_hop_witness::H_HOPS_PER_PROOF;
use dex_halo2_circuit::test_helpers::{split_into_bundle_snarks, synth_chain};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
use std::time::Instant;

const K: u32 = 19;
const K_HOPS: usize = 5;

fn bundle_circuit_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: K as usize,
        num_advice_per_phase: vec![56],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![4],
        lookup_bits: Some(18),
        num_instance_columns: 1,
    }
}

fn synthetic_dex_final(salt_commitment: Fr, bundle_head_salted: Fr) -> BundleProof {
    let mut instances = vec![Fr::zero(); DEX_FINAL_LEN];
    instances[0] = Fr::from(0xD0u64);
    instances[1] = Fr::from(0xD1u64);
    instances[2] = Fr::from(0xD2u64);
    instances[3] = Fr::from(0xD3u64);
    instances[4] = Fr::from(0xD4u64);
    instances[5] = salt_commitment;
    instances[6] = bundle_head_salted;
    BundleProof::new_dex_final(instances)
}

fn hop_to_multi_hop(
    h: &dex_halo2_circuit::multi_hop_witness::HopWitness,
) -> MultiHopWitness {
    let parent_id = if h.block.proof_block_refs.is_empty() {
        [0u8; 32]
    } else {
        h.block.proof_block_refs[0]
    };
    MultiHopWitness {
        is_active: h.is_active,
        parent_id,
        block_id: h.block.block_id,
        l7: h.block.block_merkle_tree_leaves[7],
        block_merkle_leaf_proof_l7: h.block_merkle_leaf_proof_l7,
        ref_index: h.ref_index,
        proof_block_ref_inner_path: h.proof_block_ref_inner_path,
        salted_start_block_id: h.salted_start_block_id,
        salted_end_block_id: h.salted_end_block_id,
    }
}

#[test]
#[ignore]
fn bundle_e2e_negatives() {
    // -- 1. Two chains with distinct sk_u -------------------------------
    let chain_a = synth_chain(0xAAAA_5EEDu64, K_HOPS);
    let chain_b = synth_chain(0xBBBB_5EEDu64, K_HOPS);
    assert_ne!(
        chain_a.salt_commitment, chain_b.salt_commitment,
        "different seeds must produce different salt_commitments"
    );

    let snarks_a = split_into_bundle_snarks(&chain_a);
    let snarks_b = split_into_bundle_snarks(&chain_b);

    let params = bundle_circuit_params();

    // -- 2. SRS + shared keygen (uses chain A's active snark[0]) --------
    println!("Generating SRS K={}...", K);
    let srs = gen_srs(K);

    let keygen_hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
        std::array::from_fn(|i| hop_to_multi_hop(&snarks_a[0].hops[i]));
    let keygen_circuit =
        MultiHopProofCircuit::new(chain_a.sk_u, keygen_hops, params.clone());

    let t0 = Instant::now();
    let vk = keygen_vk(&srs, &keygen_circuit).expect("keygen_vk failed");
    println!("  keygen_vk: {:?}", t0.elapsed());

    let t0 = Instant::now();
    let pk = keygen_pk(&srs, vk, &keygen_circuit).expect("keygen_pk failed");
    println!("  keygen_pk: {:?}", t0.elapsed());

    let break_points = keygen_circuit
        .base_circuit_builder
        .borrow()
        .break_points();

    // -- 3. Helper: prove a snark, return its public instances ----------
    let prove_snark = |chain_sk_u: Fr,
                       hops_full: &[dex_halo2_circuit::multi_hop_witness::HopWitness;
                                H_HOPS_PER_PROOF],
                       label: &str|
     -> Vec<Fr> {
        let hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_multi_hop(&hops_full[i]));
        let first = hops_full[0].salted_start_block_id;
        let last = hops_full[H_HOPS_PER_PROOF - 1].salted_end_block_id;
        // Compute salt_commitment from chain (always equal to chain.salt_commitment
        // for hops produced by synth_chain).
        let salt_commitment = dex_halo2_circuit::salt::compute_salt_commitment_native(
            dex_halo2_circuit::salt::compute_salt_native(chain_sk_u),
        );
        let instances = vec![first, last, salt_commitment];

        let prover_circuit = MultiHopProofCircuit::new_for_proving(
            chain_sk_u,
            hops,
            params.clone(),
            break_points.clone(),
        );
        let t0 = Instant::now();
        let proof_bytes =
            gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instances]);
        println!("[{label}] prove: {:?} ({} bytes)", t0.elapsed(), proof_bytes.len());

        let t0 = Instant::now();
        check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instances], true);
        println!("[{label}] verify: {:?}", t0.elapsed());

        instances
    };

    // -- 4. Produce the 2 real proofs we'll reshuffle -------------------
    let a_snark0 = prove_snark(chain_a.sk_u, &snarks_a[0].hops, "A.snark[0]");
    let b_snark0 = prove_snark(chain_b.sk_u, &snarks_b[0].hops, "B.snark[0]");

    let dex_a = synthetic_dex_final(chain_a.salt_commitment, chain_a.bundle_head_salted);
    let multihop_a = BundleProof::new_multi_hop(a_snark0.clone());
    let multihop_b = BundleProof::new_multi_hop(b_snark0.clone());

    // -- 5. Sanity: A's snark0 alone produces a valid 2-proof bundle ----
    {
        let bundle = vec![dex_a.clone(), multihop_a.clone()];
        verify_bundle(&bundle).expect("control bundle must verify");
        println!("[control] dex_a + A.snark[0] OK");
    }

    // -- 6. NEGATIVE: SaltCommitmentMismatch -----------------------------
    // dex_a + A.snark[0] + B.snark[0] → A and B have different salts.
    {
        let bundle = vec![dex_a.clone(), multihop_a.clone(), multihop_b.clone()];
        match verify_bundle(&bundle) {
            Err(BundleError::SaltCommitmentMismatch { mismatch_at, first, got }) => {
                assert_eq!(mismatch_at, 2);
                assert_eq!(first, chain_a.salt_commitment);
                assert_eq!(got, chain_b.salt_commitment);
                println!("[neg] SaltCommitmentMismatch at idx 2 ✓");
            }
            other => panic!("expected SaltCommitmentMismatch, got {:?}", other),
        }
    }

    // -- 7. NEGATIVE: HeadLinkBreak --------------------------------------
    {
        let dex_a_wrong = synthetic_dex_final(chain_a.salt_commitment, Fr::from(0xDEADBEEFu64));
        let bundle = vec![dex_a_wrong, multihop_a.clone()];
        match verify_bundle(&bundle) {
            Err(BundleError::HeadLinkBreak { dex_final_head, first_hop_start }) => {
                assert_eq!(dex_final_head, Fr::from(0xDEADBEEFu64));
                assert_eq!(first_hop_start, chain_a.bundle_head_salted);
                println!("[neg] HeadLinkBreak ✓");
            }
            other => panic!("expected HeadLinkBreak, got {:?}", other),
        }
    }

    // -- 8. NEGATIVE: ContinuityBreak ------------------------------------
    // Re-use A.snark[0] twice. Its salted_end_block_id (= salted(b_5)) ≠ its
    // salted_start_block_id (= salted(b_0)) → continuity at idx 1→2 fails.
    {
        let bundle = vec![dex_a.clone(), multihop_a.clone(), multihop_a.clone()];
        match verify_bundle(&bundle) {
            Err(BundleError::ContinuityBreak {
                between_hops,
                salted_end_block_id,
                salted_start_block_id,
            }) => {
                assert_eq!(between_hops, (1, 2));
                assert_eq!(salted_end_block_id, snarks_a[0].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id);
                assert_eq!(salted_start_block_id, snarks_a[0].hops[0].salted_start_block_id);
                println!("[neg] ContinuityBreak between (1, 2) ✓");
            }
            other => panic!("expected ContinuityBreak, got {:?}", other),
        }
    }

    // -- 9. NEGATIVE: DexFinalNotFirst -----------------------------------
    {
        let bundle = vec![multihop_a.clone(), dex_a.clone()];
        match verify_bundle(&bundle) {
            Err(BundleError::DexFinalNotFirst { found_at }) => {
                assert_eq!(found_at, 1);
                println!("[neg] DexFinalNotFirst ✓");
            }
            other => panic!("expected DexFinalNotFirst, got {:?}", other),
        }
    }

    // -- 10. NEGATIVE: DuplicateDexFinal ---------------------------------
    {
        let bundle = vec![dex_a.clone(), dex_a.clone(), multihop_a.clone()];
        match verify_bundle(&bundle) {
            Err(BundleError::DuplicateDexFinal { count }) => {
                assert_eq!(count, 2);
                println!("[neg] DuplicateDexFinal ✓");
            }
            other => panic!("expected DuplicateDexFinal, got {:?}", other),
        }
    }

    println!("\nAll 5 negative scenarios rejected as expected.");
}
