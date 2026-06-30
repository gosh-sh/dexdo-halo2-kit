//! Real-prover bundle E2E happy-path test.
//!
//! Validates the full bundle flow against `bundle_verifier.rs`:
//!
//! 1. `synth_chain(seed, K_HOPS)` produces a synthetic K-hop chain.
//! 2. `split_into_bundle_snarks` splits it into N_BUNDLE = 4
//!    `MultiHopProofWitness`es.
//! 3. Each snark is proved with a **real** KZG prover
//!    (`MultiHopProofCircuit` with `is_active` selectors) and verified.
//! 4. A synthetic `DexFinal` `BundleProof` is constructed from the synth
//!    chain's `salt_commitment` + `bundle_head_salted` — the bundle
//!    verifier only consumes public-instance vectors, so we don't need a
//!    real `DarkDexCircuitNew` proof here (its instance-shape is validated
//!    by its own test suite).
//! 5. `verify_bundle` accepts the assembled bundle.
//!
//! The DexFinal proof is intentionally synthetic — this test is the
//! "bundle gel" check, not a DexFinal regression. To avoid running real KZG
//! proofs in fast CI by default the test is `#[ignore]`d; run with
//! `cargo test --release bundle_e2e -- --ignored --nocapture`.

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

const K: u32 = 17;

fn bundle_circuit_params() -> BaseCircuitParams {
    // Matches the MockProver sizing in `multi_hop_proof.rs`.
    // Smartphone budget: K ≤ 17 per MULTITHREAD_CIRCUIT_SPEC §8.1.
    BaseCircuitParams {
        k: K as usize,
        num_advice_per_phase: vec![110],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![8],
        lookup_bits: Some(16),
        num_instance_columns: 1,
    }
}

/// Build a `DexFinalProof`-shaped `BundleProof` from the synth chain's
/// bundle-wide values. Slots that the bundle verifier doesn't read are
/// filled with distinguishable sentinels.
fn synthetic_dex_final(salt_commitment: Fr, bundle_head_salted: Fr) -> BundleProof {
    let mut instances = vec![Fr::zero(); DEX_FINAL_LEN];
    instances[0] = Fr::from(0xD0u64); // [0] poseidon_commitment
    instances[1] = Fr::from(0xD1u64); // [1] final_root
    instances[2] = Fr::from(0xD2u64); // [2] voucher_nominal
    instances[3] = Fr::from(0xD3u64); // [3] token_type
    instances[4] = Fr::from(0xD4u64); // [4] ephemeral_pubkey
    instances[5] = salt_commitment;   // [5] salt_commitment
    instances[6] = bundle_head_salted; // [6] event_salted_block_id (head)
    BundleProof::new_dex_final(instances)
}

/// Project a single `HopWitness` into `MultiHopWitness`.
fn hop_to_multi_hop(
    h: &dex_halo2_circuit::multi_hop_witness::HopWitness,
) -> MultiHopWitness {
    let ref_block_id = if h.block.proof_block_refs.is_empty() {
        [0u8; 32]
    } else {
        h.block.proof_block_refs[h.ref_index]
    };
    MultiHopWitness {
        is_active: h.is_active,
        ref_block_id,
        block_id: h.block.block_id,
        l7: h.block.block_merkle_tree_leaves[7],
        block_merkle_leaf_proof_l7: h.block_merkle_leaf_proof_l7,
        ref_index: h.ref_index,
        proof_block_ref_inner_path: h.proof_block_ref_inner_path,
        salted_start_block_id: h.salted_start_block_id,
        salted_end_block_id: h.salted_end_block_id,
    }
}

/// End-to-end bundle test at K_HOPS=5 (snark 0 = 5 active hops; snarks 1..3
/// = 15 inactive padding hops carrying the terminal salted endpoint).
///
/// `#[ignore]` because real KZG proving × 4 snarks at K=19 is multi-minute.
#[test]
#[ignore]
fn bundle_e2e_k5_happy_path() {
    const SEED: u64 = 0xBEEF_5EEDu64;
    const K_HOPS: usize = 5;

    // -- 1. Synth chain --------------------------------------------------
    let chain = synth_chain(SEED, K_HOPS);
    let snarks = split_into_bundle_snarks(&chain);

    // Sanity: snark 0 should be fully active; snarks 1..3 fully inactive
    // (k_hops == H_HOPS_PER_PROOF means exactly one snark of real hops).
    for hop in snarks[0].hops.iter() {
        assert!(hop.is_active, "snark 0 must be all-active for K_HOPS=5");
    }
    for snark in snarks.iter().skip(1) {
        for hop in snark.hops.iter() {
            assert!(!hop.is_active, "snarks 1..3 must be all-inactive for K_HOPS=5");
        }
    }

    let params = bundle_circuit_params();

    // -- 2. Keygen (single VK/PK shared across all 4 snarks) -------------
    println!("Generating SRS K={}...", K);
    let t0 = Instant::now();
    let srs = gen_srs(K);
    println!("  gen_srs: {:?}", t0.elapsed());

    // Use snark 0 (fully active) for keygen — same gate topology as
    // inactive snarks, since the loop body is unconditional.
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
            "\n[snark {}] active hops = {}",
            snark_idx,
            snark.hops.iter().filter(|h| h.is_active).count()
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

    // -- 4. Build synthetic DexFinal -------------------------------------
    let dex_final = synthetic_dex_final(chain.salt_commitment, chain.bundle_head_salted);

    // -- 5. Assemble bundle and run bundle_verifier ----------------------
    let mut bundle: Vec<BundleProof> = Vec::with_capacity(1 + N_BUNDLE);
    bundle.push(dex_final);
    bundle.extend(multihop_bundle_proofs);
    assert_eq!(bundle.len(), 1 + N_BUNDLE);

    println!("\nRunning bundle_verifier on {} proofs...", bundle.len());
    verify_bundle(&bundle).expect("bundle_verifier rejected the happy-path bundle");
    println!("BUNDLE OK");
}
