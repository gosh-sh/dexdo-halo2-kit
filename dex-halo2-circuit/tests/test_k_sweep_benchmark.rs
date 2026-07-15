//! Approximate K-sweep benchmark for `DarkDexCircuitNew`.
//!
//! Cell counts (`total_advice/lookup/fixed`) are measured **once** at the
//! production K (see `common::K`), then extrapolated to each K via
//! `usable_rows = 2^K − 12` (+5% slack). This is a **rough** estimate:
//! `lookup_bits = K − 1` changes with K, so the range-check advice cost
//! shifts with K — the extrapolation understates demand at small K and
//! overstates it at large K.
//!
//! Also: K=19 is baked into the deployed VK (`DARK_DEX_W128_VK_BYTES` in
//! tvm-sdk), `params/kzg_bn254_19.srs`, and the OnceLock warmup path.
//! Nothing downstream consumes a K ≠ 19 layout without regenerating VK +
//! SRS everywhere. Treat this as a one-off characterization, not a repeatable
//! test — hence `#[ignore]`.
//!
//! Run:
//! ```bash
//! cargo test --test test_k_sweep_benchmark --release -- --ignored --nocapture
//! ```
//!
//! Prints per-K keygen_vk / keygen_pk / prove / verify (median of 5) / proof size.

mod common;

use std::time::Instant;

use common::{
    base_circuit_params, build_circuit, build_circuit_for_proving, compute_instances,
    discover_fixtures, load_fixture, parse_fixture, K,
};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};

#[test]
#[ignore]
fn test_k_sweep_benchmark() {
    let fixtures = discover_fixtures();
    assert!(!fixtures.is_empty(), "No fixture files found");
    let json = load_fixture(&fixtures[0]);

    // ── Step 1: Measure cell usage at production K ──
    println!("\n=== Step 1: Measuring circuit cell usage at K={} ===\n", K);
    let (total_advice, total_lookup, total_fixed) = {
        let parsed = parse_fixture(&json);
        let measure_circuit = build_circuit(parsed, base_circuit_params());
        let srs_measure = gen_srs(K);
        let _ = keygen_vk(&srs_measure, &measure_circuit).expect("keygen_vk (measurement)");
        let stats = measure_circuit.base_circuit_builder.borrow().statistics();
        let a = stats.gate.total_advice_per_phase[0];
        let l = stats.total_lookup_advice_per_phase[0];
        let f = stats.gate.total_fixed;
        println!("Total advice cells:        {}", a);
        println!("Total lookup advice cells: {}", l);
        println!("Total fixed (constants):   {}", f);
        (a, l, f)
    };

    // ── Step 2: Sweep K ──
    println!("\n=== Step 2: K sweep benchmark ===\n");

    struct BenchResult {
        k: u32,
        num_advice: usize,
        num_lookup_advice: usize,
        num_fixed: usize,
        lookup_bits: usize,
        total_columns: usize,
        keygen_vk_ms: u128,
        keygen_pk_ms: u128,
        prove_ms: u128,
        verify_ms: u128,
        proof_size: usize,
    }
    let mut results: Vec<BenchResult> = Vec::new();

    for k_val in 17u32..=20 {
        println!("────────────────────────────────────────────");
        println!("  K = {} (2^{} = {} rows)", k_val, k_val, 1u64 << k_val);
        println!("────────────────────────────────────────────");

        let usable_rows = (1usize << k_val) - 12;
        let lookup_bits = (k_val - 1) as usize;

        let num_advice = (((total_advice as f64) / usable_rows as f64) * 1.05).ceil() as usize;
        let num_advice = num_advice.max(1);
        let num_lookup_advice = (((total_lookup as f64) / usable_rows as f64) * 1.05).ceil() as usize;
        let num_lookup_advice = num_lookup_advice.max(1);
        let num_fixed = (((total_fixed as f64) / usable_rows as f64) * 1.05).ceil() as usize;
        let num_fixed = num_fixed.max(1);

        let total_columns = num_advice + num_lookup_advice + num_fixed + 1;

        println!("  Usable rows: {}", usable_rows);
        println!(
            "  Config: num_advice={}, num_lookup_advice={}, num_fixed={}, lookup_bits={}",
            num_advice, num_lookup_advice, num_fixed, lookup_bits
        );
        println!("  Total polynomial columns: {}", total_columns);

        let params = BaseCircuitParams {
            k: k_val as usize,
            num_advice_per_phase: vec![num_advice],
            num_fixed,
            num_lookup_advice_per_phase: vec![num_lookup_advice],
            lookup_bits: Some(lookup_bits),
            num_instance_columns: 1,
        };

        let t = Instant::now();
        let srs = gen_srs(k_val);
        println!("  SRS gen:   {}ms", t.elapsed().as_millis());

        let keygen_circuit = build_circuit(parse_fixture(&json), params.clone());

        let t = Instant::now();
        let vk = keygen_vk(&srs, &keygen_circuit).expect("keygen_vk");
        let keygen_vk_ms = t.elapsed().as_millis();
        println!("  keygen_vk: {}ms", keygen_vk_ms);

        let t = Instant::now();
        let pk = keygen_pk(&srs, vk, &keygen_circuit).expect("keygen_pk");
        let keygen_pk_ms = t.elapsed().as_millis();
        println!("  keygen_pk: {}ms", keygen_pk_ms);

        let break_points = keygen_circuit.base_circuit_builder.borrow().break_points();

        // Prove
        let parsed_prove = parse_fixture(&json);
        let instances = compute_instances(&parsed_prove);
        let prover_circuit = build_circuit_for_proving(parsed_prove, params, break_points);

        let t = Instant::now();
        let proof_bytes = gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instances]);
        let prove_ms = t.elapsed().as_millis();
        println!("  prove:     {}ms", prove_ms);
        println!("  proof size: {} bytes", proof_bytes.len());

        // Verify (median of 5)
        let mut verify_times = Vec::new();
        for _ in 0..5 {
            let t = Instant::now();
            check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instances], true);
            verify_times.push(t.elapsed().as_millis());
        }
        verify_times.sort();
        let verify_ms = verify_times[2];
        println!("  verify:    {}ms (median of 5)", verify_ms);

        results.push(BenchResult {
            k: k_val,
            num_advice,
            num_lookup_advice,
            num_fixed,
            lookup_bits,
            total_columns,
            keygen_vk_ms,
            keygen_pk_ms,
            prove_ms,
            verify_ms,
            proof_size: proof_bytes.len(),
        });
    }

    println!("\n\n╔══════╤═════════╤══════════╤═══════╤═══════════╤═══════╤═══════════╤═══════════╤═══════════╤════════════╤════════════╗");
    println!("║  K   │ advice  │ lkp_adv  │ fixed │ lkp_bits  │ cols  │ keygen_vk │ keygen_pk │  prove    │  verify    │ proof_size ║");
    println!("╠══════╪═════════╪══════════╪═══════╪═══════════╪═══════╪═══════════╪═══════════╪═══════════╪════════════╪════════════╣");
    for r in &results {
        println!(
            "║  {:>2}  │  {:>5}  │   {:>4}   │  {:>3}  │    {:>2}     │ {:>4}  │  {:>6}ms │  {:>6}ms │  {:>6}ms │   {:>6}ms  │  {:>6}B   ║",
            r.k, r.num_advice, r.num_lookup_advice, r.num_fixed,
            r.lookup_bits, r.total_columns,
            r.keygen_vk_ms, r.keygen_pk_ms, r.prove_ms, r.verify_ms, r.proof_size,
        );
    }
    println!("╚══════╧═════════╧══════════╧═══════╧═══════════╧═══════╧═══════════╧═══════════╧═══════════╧════════════╧════════════╝");
}
