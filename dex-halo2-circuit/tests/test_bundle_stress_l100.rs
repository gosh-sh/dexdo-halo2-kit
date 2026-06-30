//! Real-prover bundle stress test at chain-length L = 100.
//!
//! Continues the §10.2 Open Question #1 path A escape: `n_bundle = 20`
//! supports L = 100 hops, all fully active. Per-snark circuit unchanged
//! (`H = 5`, circuit K = 19). Extrapolated wall: ~20 × ~104 s ≈ ~35 min.
//!
//! `#[ignore]`; run with
//! `cargo test --release --test test_bundle_stress_l100 -- --ignored --nocapture`.

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
        proof_block_ref_inner_path: h.proof_block_ref_inner_path,
        salted_start_block_id: h.salted_start_block_id,
        salted_end_block_id: h.salted_end_block_id,
    }
}

#[test]
#[ignore]
fn bundle_stress_l100_n20() {
    const SEED: u64 = 0x0100_BEEFu64;
    const N_BUNDLE: usize = 20;
    const L_HOPS: usize = N_BUNDLE * H_HOPS_PER_PROOF; // 100

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
            "\n[snark {} / {}] active hops = {} / {}",
            snark_idx + 1,
            N_BUNDLE,
            snark.hops.iter().filter(|h| h.is_active).count(),
            H_HOPS_PER_PROOF
        );
        let t0 = Instant::now();
        let proof_bytes =
            gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instances]);
        println!("  prove: {:?} ({} bytes)", t0.elapsed(), proof_bytes.len());

        let t0 = Instant::now();
        check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instances], true);
        println!("  verify: {:?}", t0.elapsed());

        multihop_bundle_proofs.push(BundleProof::new_multi_hop(instances));
    }
    println!("\n{}-snark prove+verify wall: {:?}", N_BUNDLE, overall.elapsed());

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
    verify_bundle(&bundle).expect("bundle_verifier rejected L = 100 bundle");
    println!("BUNDLE OK (L = {}, n_bundle = {}, all hops active)", L_HOPS, N_BUNDLE);
}
