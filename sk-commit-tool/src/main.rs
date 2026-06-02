use dex_halo2_circuit::poseidon::poseidon_hash;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: sk-commit-tool <sk_u_hex_32bytes>");
        std::process::exit(1);
    }

    let sk_u_hex = &args[1];
    let sk_u_bytes: [u8; 32] = hex::decode(sk_u_hex)
        .expect("invalid hex string")
        .try_into()
        .expect("sk_u must be exactly 32 bytes");

    let sk_u = Fr::from_bytes(&sk_u_bytes).expect("invalid BN254 field element");
    let sk_u_commit = poseidon_hash(&[sk_u, Fr::zero()]);

    print!("{}", hex::encode(sk_u_commit.to_bytes()));
}
