//! Real-prover bundle stress test at K_HOPS=20.
//!
//! Mirrors `test_bundle_e2e.rs::bundle_e2e_k5_happy_path` but at maximum
//! capacity: `K_HOPS = N_BUNDLE * H_HOPS_PER_PROOF = 20`, so **every** hop
//! in every snark is active (no inactive padding anywhere). Validates that:
//!
//!   * the splitter routes a 20-hop synth chain into 4 fully-active snarks,
//!   * `MultiHopProofCircuit` proves each all-active snark under the same
//!     VK/PK as a mixed-activity snark (the gate body is unconditional —
//!     `is_active` only multiplies equality residuals), and
//!   * `verify_bundle` accepts the assembled 5-proof bundle (1 synthetic
//!     DexFinal + 4 MultiHop snarks).
//!
//! Cost: 4 real KZG proofs × K=19 ≈ 4 × ~100 s prove + ~60 s keygen
//! ≈ ~7.5 min on the same hardware that ran the K_HOPS=5 happy-path.
//!
//! `#[ignore]`; run with
//! `cargo test --release --test test_bundle_stress -- --ignored --nocapture`.

use dex_halo2_circuit::bundle_verifier::{
    verify_bundle, BundleProof, DEX_FINAL_LEN,
};
use dex_halo2_circuit::multi_hop_proof::{MultiHopProofCircuit, MultiHopWitness};
use dex_halo2_circuit::multi_hop_witness::{H_HOPS_PER_PROOF, N_BUNDLE};
use dex_halo2_circuit::test_helpers::{split_into_bundle_snarks, synth_chain};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
use std::time::Instant;

const K: u32 = 19;

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

/// K_HOPS=20 (full bundle capacity): 4 fully-active snarks chained
/// end-to-end. `#[ignore]` due to multi-minute real KZG cost.
#[test]
#[ignore]
fn bundle_stress_k20_full_capacity() {
    const SEED: u64 = 0xF00D_5EEDu64;
    const K_HOPS: usize = N_BUNDLE * H_HOPS_PER_PROOF; // 20

    // -- 1. Synth chain --------------------------------------------------
    let chain = synth_chain(SEED, K_HOPS);
    let snarks = split_into_bundle_snarks(&chain);

    // Sanity: every hop in every snark is active at K=20.
    for (s_idx, snark) in snarks.iter().enumerate() {
        for (h_idx, hop) in snark.hops.iter().enumerate() {
            assert!(
                hop.is_active,
                "snark {s_idx} hop {h_idx} expected active at K=20"
            );
        }
    }

    // Cross-snark continuity: snark[i].last.end == snark[i+1].first.start.
    for i in 0..N_BUNDLE - 1 {
        assert_eq!(
            snarks[i].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id,
            snarks[i + 1].hops[0].salted_start_block_id,
            "cross-snark continuity broken at boundary {i} → {}",
            i + 1
        );
    }

    let params = bundle_circuit_params();

    // -- 2. Keygen (shared across 4 snarks) ------------------------------
    println!("Generating SRS K={}...", K);
    let t0 = Instant::now();
    let srs = gen_srs(K);
    println!("  gen_srs: {:?}", t0.elapsed());

    let keygen_hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
        std::array::from_fn(|i| hop_to_multi_hop(&snarks[0].hops[i]));
    let keygen_circuit =
        MultiHopProofCircuit::new(chain.sk_u, keygen_hops, params.clone());

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

    // -- 3. Prove + verify each of the 4 snarks --------------------------
    let mut multihop_bundle_proofs: Vec<BundleProof> = Vec::with_capacity(N_BUNDLE);

    let overall = Instant::now();
    for snark_idx in 0..N_BUNDLE {
        let snark = &snarks[snark_idx];
        let hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_multi_hop(&snark.hops[i]));

        let first_salted_start_block_id = snark.hops[0].salted_start_block_id;
        let last_salted_end_block_id = snark.hops[H_HOPS_PER_PROOF - 1].salted_end_block_id;
        let salt_commitment = snark.salt_commitment;
        let instances = vec![first_salted_start_block_id, last_salted_end_block_id, salt_commitment];

        let prover_circuit = MultiHopProofCircuit::new_for_proving(
            chain.sk_u,
            hops,
            params.clone(),
            break_points.clone(),
        );

        println!(
            "\n[snark {}] active hops = {} / {}",
            snark_idx,
            snark.hops.iter().filter(|h| h.is_active).count(),
            H_HOPS_PER_PROOF
        );
        let t0 = Instant::now();
        let proof_bytes =
            gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instances]);
        println!(
            "  prove: {:?} ({} bytes)",
            t0.elapsed(),
            proof_bytes.len()
        );

        let t0 = Instant::now();
        check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instances], true);
        println!("  verify: {:?}", t0.elapsed());

        multihop_bundle_proofs.push(BundleProof::new_multi_hop(instances));
    }
    println!("\n4-snark prove+verify wall: {:?}", overall.elapsed());

    // -- 4. Build synthetic DexFinal -------------------------------------
    let dex_final = synthetic_dex_final(chain.salt_commitment, chain.bundle_head_salted);

    // -- 5. Assemble bundle and run bundle_verifier ----------------------
    let mut bundle: Vec<BundleProof> = Vec::with_capacity(1 + N_BUNDLE);
    bundle.push(dex_final);
    bundle.extend(multihop_bundle_proofs);
    assert_eq!(bundle.len(), 1 + N_BUNDLE);

    println!("\nRunning bundle_verifier on {} proofs (K_HOPS=20)...", bundle.len());
    verify_bundle(&bundle).expect("bundle_verifier rejected the K=20 full-capacity bundle");
    println!("BUNDLE OK (K_HOPS=20, all 20 hops active)");
}
