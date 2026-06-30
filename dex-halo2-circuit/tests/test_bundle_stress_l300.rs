//! Real-prover bundle stress test at chain-length L = 300.
//!
//! Pushes the §10.2 Open Question #1 path A escape to the colleagues-
//! reported worst-case cap of 300: `n_bundle = 60`, all 60 snarks fully
//! active. Per-snark circuit (`H = 5`, circuit K = 19) unchanged.
//! Extrapolated wall: ~60 × ~100 s ≈ ~100 min (modulo thermal/host noise).
//!
//! `#[ignore]`; run with
//! `cargo test --release --test test_bundle_stress_l300 -- --ignored --nocapture`.

use dex_halo2_circuit::bundle_verifier::{
    verify_bundle, BundleProof, DEX_FINAL_LEN,
};
use dex_halo2_circuit::multi_hop_proof::{MultiHopProofCircuit, MultiHopWitness};
use dex_halo2_circuit::multi_hop_witness::H_HOPS_PER_PROOF;
use dex_halo2_circuit::test_helpers::{split_into_bundle_snarks_n, synth_chain_n};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
use std::time::Instant;

const K: u32 = 17;

fn bundle_circuit_params() -> BaseCircuitParams {
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

#[test]
#[ignore]
fn bundle_stress_l300_n60() {
    const SEED: u64 = 0x0300_BEEFu64;
    const N_BUNDLE: usize = 60;
    const L_HOPS: usize = N_BUNDLE * H_HOPS_PER_PROOF; // 300

    let chain = synth_chain_n(SEED, L_HOPS, N_BUNDLE);
    let snarks = split_into_bundle_snarks_n(&chain, N_BUNDLE);

    assert_eq!(snarks.len(), N_BUNDLE);
    for (s_idx, snark) in snarks.iter().enumerate() {
        for (h_idx, hop) in snark.hops.iter().enumerate() {
            assert!(hop.is_active, "snark {s_idx} hop {h_idx} expected active");
        }
    }
    for i in 0..N_BUNDLE - 1 {
        assert_eq!(
            snarks[i].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id,
            snarks[i + 1].hops[0].salted_start_block_id,
            "cross-snark continuity broken at boundary {i} → {}",
            i + 1
        );
    }

    let params = bundle_circuit_params();

    println!("Generating SRS (circuit K = {})...", K);
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

    let mut multihop_bundle_proofs: Vec<BundleProof> = Vec::with_capacity(N_BUNDLE);
    let mut per_snark_times: Vec<f64> = Vec::with_capacity(N_BUNDLE);

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

        println!("\n[snark {} / {}]", snark_idx + 1, N_BUNDLE);
        let t0 = Instant::now();
        let proof_bytes =
            gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instances]);
        let prove_secs = t0.elapsed().as_secs_f64();
        per_snark_times.push(prove_secs);
        println!("  prove: {:.2}s ({} bytes)", prove_secs, proof_bytes.len());

        let t0 = Instant::now();
        check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instances], true);
        println!("  verify: {:?}", t0.elapsed());

        multihop_bundle_proofs.push(BundleProof::new_multi_hop(instances));
    }
    println!("\n{}-snark prove+verify wall: {:?}", N_BUNDLE, overall.elapsed());

    // Summary stats — useful for spotting thermal throttling in long runs.
    let sum: f64 = per_snark_times.iter().sum();
    let mean = sum / per_snark_times.len() as f64;
    let min = per_snark_times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = per_snark_times
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);
    println!(
        "per-snark prove (s): mean={:.1}, min={:.1}, max={:.1}, total={:.1}",
        mean, min, max, sum
    );

    let dex_final = synthetic_dex_final(chain.salt_commitment, chain.bundle_head_salted);

    let mut bundle: Vec<BundleProof> = Vec::with_capacity(1 + N_BUNDLE);
    bundle.push(dex_final);
    bundle.extend(multihop_bundle_proofs);
    assert_eq!(bundle.len(), 1 + N_BUNDLE);

    println!(
        "\nRunning bundle_verifier on {} proofs (L = {}, n_bundle = {})...",
        bundle.len(),
        L_HOPS,
        N_BUNDLE
    );
    verify_bundle(&bundle).expect("bundle_verifier rejected L = 300 bundle");
    println!("BUNDLE OK (L = {}, n_bundle = {}, all hops active)", L_HOPS, N_BUNDLE);
}
