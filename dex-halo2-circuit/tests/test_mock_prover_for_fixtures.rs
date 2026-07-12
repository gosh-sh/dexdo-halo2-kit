//! MockProver smoke test — runs the circuit on every fixture in `tests/fixtures/`.
//!
//! ```bash
//! cargo test --test test_mock_prover_for_fixtures -- --nocapture
//! ```

mod common;

use common::{
    base_circuit_params, build_circuit, compute_instances, discover_fixtures, load_fixture, K,
};
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;

#[test]
fn test_mock_prover_all_fixtures() {
    let fixtures = discover_fixtures();
    assert!(
        !fixtures.is_empty(),
        "No fixture files found in tests/fixtures/"
    );

    let params = base_circuit_params();

    for fixture_path in &fixtures {
        let filename = fixture_path.file_name().unwrap().to_str().unwrap();
        println!("\n========== MockProver: {} ==========", filename);

        let json = load_fixture(fixture_path);
        println!("  Description: {}", json.description);
        println!("  Chain steps: {}", json.num_active_chain_steps);

        let parsed = common::parse_fixture(&json);
        let instances = compute_instances(&parsed);
        println!(
            "  Instances: poseidon={}, final_root={}, voucher={}, token={}, epk={}",
            hex::encode(instances[0].to_repr()),
            hex::encode(instances[1].to_repr()),
            hex::encode(instances[2].to_repr()),
            hex::encode(instances[3].to_repr()),
            hex::encode(instances[4].to_repr()),
        );

        let circuit = build_circuit(parsed, params.clone());

        let prover = MockProver::<Fr>::run(K, &circuit, vec![instances]).unwrap();
        match prover.verify() {
            Ok(()) => println!("  {} PASSED", filename),
            Err(errors) => {
                println!("  {} FAILED with {} errors:", filename, errors.len());
                for (i, err) in errors.iter().enumerate().take(30) {
                    println!("    Error {}: {}", i, err);
                }
                panic!("MockProver failed for {}", filename);
            }
        }
    }

    println!("\nAll {} fixture(s) passed MockProver!", fixtures.len());
}
