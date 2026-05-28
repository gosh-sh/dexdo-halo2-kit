//! Verify that the native Poseidon commitment `poseidon_hash([sk_u, 0])`
//! (used by sk-commit-tool and halo2-proover) is identical to the in-circuit
//! `PoseidonHasher::hash_fix_len_array` with the same spec constants.
//!
//! This confirms that sk_u_commit values produced by sk-commit-tool will
//! satisfy the constraint `ctx.constrain_equal(&sk_u_commit, &hasher_result)`
//! in `DarkDexCircuitNew::synthesize`.

use gosh_dark_dex_halo2_new_circuit::poseidon::{poseidon_hash, R_F, R_P, RATE, T};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        RangeInstructions,
    },
    halo2_proofs::halo2curves::bn256::Fr,
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
};

/// Compute sk_u_commit using the in-circuit PoseidonHasher (off-circuit mode).
fn poseidon_hash_in_circuit(inputs: &[Fr]) -> Fr {
    let params = BaseCircuitParams {
        k: 10,
        num_advice_per_phase: vec![1],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![1],
        lookup_bits: Some(9),
        num_instance_columns: 0,
    };
    let mut builder = BaseCircuitBuilder::<Fr>::new(false).use_params(params);
    let range = builder.range_chip();
    let gate = range.gate();
    let ctx = builder.pool(0).main();

    let assigned: Vec<_> = inputs.iter().map(|&v| ctx.load_witness(v)).collect();

    let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
    let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
    hasher.initialize_consts(ctx, gate);
    let result = hasher.hash_fix_len_array(ctx, gate, &assigned);

    *result.value()
}

#[test]
fn test_native_vs_circuit_poseidon_zero_key() {
    let sk_u = Fr::zero();
    let native = poseidon_hash(&[sk_u, Fr::zero()]);
    let circuit = poseidon_hash_in_circuit(&[sk_u, Fr::zero()]);
    assert_eq!(
        native, circuit,
        "Native and in-circuit Poseidon disagree for sk_u = 0"
    );
    println!("sk_u=0: commit = {}", hex::encode(native.to_bytes()));
}

#[test]
fn test_native_vs_circuit_poseidon_nonzero_key() {
    // Deterministic non-zero sk_u (same value used in sk-commit-tool test)
    let sk_u_bytes: [u8; 32] =
        hex::decode("e2559befd891c2c1ee1175f5c86e8908d6c06acbe13e13069ec14158f18de40c")
            .unwrap()
            .try_into()
            .unwrap();
    let sk_u = Fr::from_bytes(&sk_u_bytes).unwrap();

    let native = poseidon_hash(&[sk_u, Fr::zero()]);
    let circuit = poseidon_hash_in_circuit(&[sk_u, Fr::zero()]);
    assert_eq!(
        native, circuit,
        "Native and in-circuit Poseidon disagree for non-zero sk_u"
    );
    println!(
        "sk_u={}: commit = {}",
        hex::encode(sk_u_bytes),
        hex::encode(native.to_bytes())
    );
}

#[test]
fn test_native_vs_circuit_poseidon_random_keys() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    for i in 0..5 {
        let mut sk_bytes = [0u8; 32];
        rng.fill(&mut sk_bytes);
        // Clamp top byte to stay in field
        sk_bytes[31] &= 0x2F;

        let sk_u = Fr::from_bytes(&sk_bytes).unwrap();
        let native = poseidon_hash(&[sk_u, Fr::zero()]);
        let circuit = poseidon_hash_in_circuit(&[sk_u, Fr::zero()]);
        assert_eq!(
            native, circuit,
            "Mismatch at random key #{}: sk_u={}",
            i,
            hex::encode(sk_bytes)
        );
    }
    println!("5 random keys: native == circuit for all");
}

#[test]
fn test_sk_commit_tool_output_matches() {
    // This test verifies the exact output of sk-commit-tool.
    // sk-commit-tool computes: hex::encode(poseidon_hash([Fr::from_bytes(sk_u), Fr::zero()]).to_bytes())
    // which is exactly what the native poseidon_hash does.
    let sk_u_hex = "e2559befd891c2c1ee1175f5c86e8908d6c06acbe13e13069ec14158f18de40c";
    let sk_u_bytes: [u8; 32] = hex::decode(sk_u_hex).unwrap().try_into().unwrap();
    let sk_u = Fr::from_bytes(&sk_u_bytes).unwrap();

    let commit = poseidon_hash(&[sk_u, Fr::zero()]);
    let commit_hex = hex::encode(commit.to_bytes());

    // This value was produced by running:
    //   sk-commit-tool e2559befd891c2c1ee1175f5c86e8908d6c06acbe13e13069ec14158f18de40c
    let expected = "1511ed0b9a3d3c7b25cb52ac178cd1f4ccb2684dcab3a1ad66c1509a853b021f";
    assert_eq!(
        commit_hex, expected,
        "Native poseidon_hash output doesn't match sk-commit-tool output"
    );

    // Also verify the in-circuit version produces the same
    let circuit_commit = poseidon_hash_in_circuit(&[sk_u, Fr::zero()]);
    let circuit_hex = hex::encode(circuit_commit.to_bytes());
    assert_eq!(
        circuit_hex, expected,
        "In-circuit PoseidonHasher output doesn't match sk-commit-tool output"
    );

    println!("sk-commit-tool output verified: {}", expected);
}
