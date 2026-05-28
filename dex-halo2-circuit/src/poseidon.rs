use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use pse_poseidon::Poseidon;

pub const T: usize = 3;
pub const RATE: usize = 2;
pub const R_F: usize = 8;
pub const R_P: usize = 57;

pub fn poseidon_hash(message: &[Fr]) -> Fr {
    let mut native_sponge = Poseidon::<Fr, T, RATE>::new(R_F, R_P);
    native_sponge.update(message);
    native_sponge.squeeze()
}

#[test]
fn test() {
    let digest = poseidon_hash(&[Fr::zero()]);
    //println!("{:?}", hex::encode(digest.to_bytes()));
}
