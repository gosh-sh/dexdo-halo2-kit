//! HopProof circuit — single-hop proof.
//!
//! Proves that a single block `block_id` has a parent `parent_id` recorded
//! at `proof_block_refs[0]` of its on-chain ref list, by opening the
//! production-shape merkle path: block-merkle SHA-256 leaf 7 down to the
//! Poseidon ref-tree leaf at index 0. Exposes the two salted endpoints and
//! the bundle's `salt_commitment` as public instances.
//!
//! [`HopProofCircuit`] is the elementary building block; the bundle-scope
//! production circuit is [`crate::multi_hop_proof::MultiHopProofCircuit`],
//! which proves `H_HOPS_PER_PROOF` hops at once and adds an `is_active`
//! padding selector.
//!
//! ## Scope
//!
//! - **H=1** (one hop).
//! - **All active** (no padding selector).
//! - **`ref_index = 0`** (parent slot only — the only case the synthetic
//!   chain helper produces).
//! - **`leaf_index = 7`** (L7 sits at block-merkle leaf index 7, so all 3
//!   SHA-256 levels put the current node on the right).
//!
//! ## Public instance layout (3 Fr — same as the bundle-scope circuit's
//! per-hop slot)
//!
//! | idx | name | derivation |
//! |---|---|---|
//! | 0 | `salted_start_block_id` | `bytes_to_fr(hash_bytes_flat(fr_to_bytes(salt) ‖ parent_id))` |
//! | 1 | `salted_end_block_id`   | `bytes_to_fr(hash_bytes_flat(fr_to_bytes(salt) ‖ block_id))` |
//! | 2 | `salt_commitment`       | `Poseidon([salt])` |
//!
//! ## Private witnesses
//!
//! - `sk_u`: drives `salt = Poseidon([DOMAIN_TAG_HOP_SALT_FR, sk_u])` and
//!   `salt_commitment = Poseidon([salt])`.
//! - `parent_id` (32 B): the predecessor block referenced by the hop. Feeds
//!   the ref-tree leaf computation and `salted_start_block_id`.
//! - `block_id` (32 B): the hop's target block. Feeds the SHA-256 path
//!   target and `salted_end_block_id`.
//! - `l7` (32 B): the L7 ref-tree root sitting at `block_merkle_tree_leaves[7]`.
//! - `block_merkle_leaf_proof_l7`: 3 SHA-256 siblings opening L7 against
//!   `block_id` at leaf index 7.
//! - `proof_block_ref_inner_path`: `MAX_PROOF_BLOCK_REFS_DEPTH` byte-flat
//!   Poseidon siblings opening the ref-leaf against L7 at ref-index 0.
//!
//! ## Constraints (byte-flat production parity)
//!
//! 1. **SHA-256 path** — three `Sha256Chip::digest_bytes` calls, each consuming
//!    `sibling_bytes ‖ current_bytes` (leaf 7 puts the current node on the
//!    right at every level). Final 32-byte digest is constrained equal to
//!    `block_id` byte-by-byte.
//! 2. **Ref-tree path (byte-flat)** —
//!    - `ref_leaf = Poseidon([c0, c1, c2])` where `(c0, c1, c2)` are the
//!      31-byte chunks of `tag(37 B) ‖ parent_id(32 B)`: `c0` is constant
//!      (`tag[0..31]`), `c1` combines `tag[31..37]` (constant) with
//!      `parent_id[0..25]` (witness bytes via `inner_product`), `c2 =
//!      inner_product(parent_id[25..32], 256^[0..7])`.
//!    - Ref-tree walk uses `gosh_dense_balanced_tree::dense_merkle_root_circuit`
//!      (`MAX_PROOF_BLOCK_REFS_DEPTH` levels, ref-index = 0 ⇒ current always
//!      on the left). Internally each level chunks `cur(32) ‖ sibling(32)`
//!      at 31+31+2 and Poseidons the 3 chunks — byte-for-byte equal to
//!      production's `dense_combine = hash_bytes_flat(left ‖ right)`.
//! 3. **Salt math** — `salt = Poseidon([DOMAIN_TAG_HOP_SALT_FR, sk_u])` and
//!    `salt_commitment = Poseidon([salt])` (Fr-vector, both inputs canonical
//!    Fr). The salted endpoints use the byte-flat encoding of
//!    `fr_to_bytes(salt) ‖ other(32 B)`: `salt_fr` is decomposed once into
//!    `chunk0(31 B) + salt_hi(1 B) · 2^248` (range-checked, algebraically
//!    linked), then reused for both endpoints. `chunk1 = salt_hi + 256 ·
//!    inner_product(other[0..30], 256^[0..30])` and `chunk2 =
//!    inner_product(other[30..32], 256^[0..2])` are computed for
//!    `other = parent_id` (start) and `other = block_id` (end). This is the
//!    production rule of `compute_salted_block_id_native`.

use gosh_dense_balanced_tree::{
    bytes_to_fr, dense_merkle_root_circuit, fr_to_bytes, preprocess_dense_proof_padded, R_F, R_P,
    RATE, T,
};
use gosh_sha256_chip::Sha256Chip;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::{BaseCircuitParams, BaseConfig};
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::Field as _;
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};
use halo2_base::{AssignedValue, QuantumCell};
use std::cell::RefCell;

use crate::multi_hop_witness::{
    ref_leaf_hash_native, ref_leaf_tag_chunk0_fr, ref_leaf_tag_chunk1_lo_fr, BLOCK_MERKLE_DEPTH,
    MAX_PROOF_BLOCK_REFS_DEPTH,
};
use crate::salt::{compute_salt_native, domain_tag_hop_salt_fr};

const SHA256_HASH_LEN: usize = 32;

/// Public-instance count: `[salted_start_block_id, salted_end_block_id, salt_commitment]`.
pub const HOP_PROOF_PUBLIC_LEN: usize = 3;

/// Single-hop witness shape: `ref_index = 0`, `leaf_index = 7`, hop always
/// active. Mirrors the relevant slice of `multi_hop_witness::HopWitness`
/// while dropping the fields this circuit doesn't consume.
#[derive(Clone, Debug)]
pub struct HopProofWitness {
    pub parent_id: [u8; 32],
    pub block_id: [u8; 32],
    pub l7: [u8; 32],
    /// 3 SHA-256 siblings opening L7 to `block_id` at leaf 7. Order: bottom-up
    /// (siblings[0] = pair with L7 → next level up; etc).
    pub block_merkle_leaf_proof_l7: [[u8; 32]; BLOCK_MERKLE_DEPTH],
    /// Poseidon siblings opening the ref-leaf to L7 at ref-index 0.
    pub proof_block_ref_inner_path: [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
}

#[derive(Clone, Debug)]
pub struct HopProofCircuitConfig {
    base_circuit_config: BaseConfig<Fr>,
}

pub struct HopProofCircuit {
    /// Private witness: voucher secret. Drives `salt` and `salt_commitment`.
    pub sk_u: Fr,
    pub hop: HopProofWitness,
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl HopProofCircuit {
    pub fn new(
        sk_u: Fr,
        hop: HopProofWitness,
        base_circuit_params: BaseCircuitParams,
    ) -> Self {
        let base_circuit_builder = RefCell::new(
            BaseCircuitBuilder::<Fr>::new(false).use_params(base_circuit_params.clone()),
        );
        Self {
            sk_u,
            hop,
            base_circuit_params,
            base_circuit_builder,
        }
    }

    pub fn new_for_proving(
        sk_u: Fr,
        hop: HopProofWitness,
        base_circuit_params: BaseCircuitParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        let base_circuit_builder = RefCell::new(BaseCircuitBuilder::<Fr>::prover(
            base_circuit_params.clone(),
            break_points,
        ));
        Self {
            sk_u,
            hop,
            base_circuit_params,
            base_circuit_builder,
        }
    }
}

impl Circuit<Fr> for HopProofCircuit {
    type Config = HopProofCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base_circuit_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        let dummy_hop = HopProofWitness {
            parent_id: [0u8; 32],
            block_id: [0u8; 32],
            l7: [0u8; 32],
            block_merkle_leaf_proof_l7: [[0u8; 32]; BLOCK_MERKLE_DEPTH],
            proof_block_ref_inner_path: [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
        };
        Self::new(Fr::zero(), dummy_hop, self.base_circuit_params.clone())
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::configure_with_params(meta, Default::default())
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        let base_circuit_config = BaseCircuitBuilder::<Fr>::configure_with_params(meta, params);
        HopProofCircuitConfig {
            base_circuit_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Reset the builder so repeated synthesize calls (keygen_vk + keygen_pk)
        // don't accumulate gates — same pattern as `DarkDexCircuitNew`.
        {
            let old = self.base_circuit_builder.borrow();
            let mut fresh = if old.witness_gen_only() {
                BaseCircuitBuilder::<Fr>::prover(
                    self.base_circuit_params.clone(),
                    old.break_points(),
                )
            } else {
                BaseCircuitBuilder::<Fr>::new(false)
                    .use_params(self.base_circuit_params.clone())
            };
            while fresh.assigned_instances.len()
                < self.base_circuit_params.num_instance_columns
            {
                fresh.assigned_instances.push(vec![]);
            }
            drop(old);
            *self.base_circuit_builder.borrow_mut() = fresh;
        }

        {
            let mut builder = self.base_circuit_builder.borrow_mut();
            let range = builder.range_chip();

            let (salted_start_block_id, salted_end_block_id, salt_commitment) = {
                let gate = range.gate();
                let ctx = builder.pool(0).main();
                let sha256_chip = Sha256Chip::new(&range);

                // === Poseidon hasher init ===
                let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
                let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
                hasher.initialize_consts(ctx, gate);

                // === Salt + salt_commitment ===
                let sk_u_assigned = ctx.load_witness(self.sk_u);
                let domain_tag_fr_const = ctx.load_constant(domain_tag_hop_salt_fr());
                let salt_assigned = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[domain_tag_fr_const, sk_u_assigned],
                );
                let salt_commitment =
                    hasher.hash_fix_len_array(ctx, gate, &[salt_assigned]);

                // === LE 32-byte powers (only used for the L7 byte→Fr pack) ===
                let powers_le_32: Vec<QuantumCell<Fr>> = (0..32)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();

                // === L7 bytes (input to SHA-256 walk + LE-packed to L7 Fr) ===
                let l7_bytes: Vec<AssignedValue<Fr>> = self
                    .hop
                    .l7
                    .iter()
                    .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                    .collect();
                let l7_fr = {
                    let cells: Vec<QuantumCell<Fr>> = l7_bytes
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    gate.inner_product(ctx, cells, powers_le_32)
                };

                // === parent_id as 32 byte cells (range-checked 8 bits each) ===
                // Byte-flat encoding needs byte-level access at two
                // different split points (byte 25 for ref-leaf, byte 30 for
                // salted-start), so we witness all 32 bytes once.
                let parent_id_bytes: Vec<AssignedValue<Fr>> = self
                    .hop
                    .parent_id
                    .iter()
                    .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                    .collect();
                for cell in &parent_id_bytes {
                    range.range_check(ctx, *cell, 8);
                }

                // === Byte-flat ref-leaf = Poseidon([c0, c1, c2]) ===
                // chunk0 = LE(tag[0..31])                              [constant]
                // chunk1 = LE(tag[31..37] || parent_id[0..25])
                //        = tag_lo_const + parent_id_lo25 · 256^6
                // chunk2 = LE(parent_id[25..32]) = inner_product(.., 256^[0..7])
                let ref_leaf_c0 = ctx.load_constant(ref_leaf_tag_chunk0_fr());
                let ref_leaf_tag_lo = ctx.load_constant(ref_leaf_tag_chunk1_lo_fr());
                let pow_256_6 = ctx.load_constant(Fr::from(256u64).pow([6u64]));
                let powers_le_25: Vec<QuantumCell<Fr>> = (0..25)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();
                let powers_le_7: Vec<QuantumCell<Fr>> = (0..7)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();

                let parent_id_lo25 = {
                    let cells: Vec<QuantumCell<Fr>> = parent_id_bytes[0..25]
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    gate.inner_product(ctx, cells, powers_le_25)
                };
                let parent_id_lo25_shifted = gate.mul(
                    ctx,
                    QuantumCell::Existing(parent_id_lo25),
                    QuantumCell::Existing(pow_256_6),
                );
                let ref_leaf_c1 = gate.add(
                    ctx,
                    QuantumCell::Existing(ref_leaf_tag_lo),
                    QuantumCell::Existing(parent_id_lo25_shifted),
                );
                let ref_leaf_c2 = {
                    let cells: Vec<QuantumCell<Fr>> = parent_id_bytes[25..32]
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    gate.inner_product(ctx, cells, powers_le_7)
                };
                let ref_leaf_fr = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[ref_leaf_c0, ref_leaf_c1, ref_leaf_c2],
                );

                // === Ref-tree walk (byte-flat dense Merkle) ===
                // Native preprocess produces the chunk witnesses for each
                // level; `dense_merkle_root_circuit` enforces the byte-flat
                // chunking algebra + Poseidon at each level.
                let ref_leaf_native_bytes =
                    ref_leaf_hash_native(0, &self.hop.parent_id);
                let ref_proof = preprocess_dense_proof_padded(
                    ref_leaf_native_bytes,
                    &self.hop.proof_block_ref_inner_path,
                    0, // ref_index hardcoded to 0
                    MAX_PROOF_BLOCK_REFS_DEPTH,
                );
                let computed_l7_fr =
                    dense_merkle_root_circuit(ctx, &range, &hasher, &ref_proof, ref_leaf_fr);
                ctx.constrain_equal(&computed_l7_fr, &l7_fr);

                // === block_id bytes (output target of SHA-256 walk) ===
                let block_id_bytes: Vec<AssignedValue<Fr>> = self
                    .hop
                    .block_id
                    .iter()
                    .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                    .collect();

                // === SHA-256 walk: 3 levels, leaf_index=7 (cur always on right) ===
                let mut cur_bytes = l7_bytes;
                for sib_bytes in &self.hop.block_merkle_leaf_proof_l7 {
                    let sib_cells: Vec<AssignedValue<Fr>> = sib_bytes
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();
                    // sibling || current (leaf 7 always on the right)
                    let mut concat: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
                    concat.extend_from_slice(&sib_cells);
                    concat.extend_from_slice(&cur_bytes);
                    let next = sha256_chip.digest_bytes(ctx, &concat);
                    assert_eq!(next.len(), SHA256_HASH_LEN);
                    cur_bytes = next;
                }
                for i in 0..SHA256_HASH_LEN {
                    ctx.constrain_equal(&cur_bytes[i], &block_id_bytes[i]);
                }

                // === Salted endpoints (byte-flat) ===
                // Data = fr_to_bytes(salt)(32 B) || other(32 B); chunks 31+31+2:
                //   chunk0 = LE(salt[0..31])                        (shared)
                //   chunk1 = salt_hi + 256 · LE(other[0..30])
                //   chunk2 = LE(other[30..32])
                // salt is an Fr (Poseidon output) — decompose once:
                //   salt_fr == salt_chunk0 + salt_hi · 2^248
                //   range_check(salt_chunk0, 248) + range_check(salt_hi, 8)
                let pow_248 =
                    ctx.load_constant(Fr::from_raw([0u64, 0u64, 0u64, 1u64 << 56]));
                let pow_256 = ctx.load_constant(Fr::from(256u64));
                let powers_le_30: Vec<QuantumCell<Fr>> = (0..30)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();
                let powers_le_2: Vec<QuantumCell<Fr>> = (0..2)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();

                let salt_native = compute_salt_native(self.sk_u);
                let salt_bytes_native = fr_to_bytes(salt_native);
                let mut salt_chunk0_native_buf = [0u8; 32];
                salt_chunk0_native_buf[..31]
                    .copy_from_slice(&salt_bytes_native[..31]);
                let salt_chunk0_native = bytes_to_fr(&salt_chunk0_native_buf);
                let salt_hi_native = Fr::from(salt_bytes_native[31] as u64);

                let salt_chunk0 = ctx.load_witness(salt_chunk0_native);
                let salt_hi = ctx.load_witness(salt_hi_native);
                range.range_check(ctx, salt_chunk0, 248);
                range.range_check(ctx, salt_hi, 8);
                {
                    // salt_chunk0 + salt_hi · 2^248 == salt_assigned
                    let reconstructed = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(salt_hi),
                        QuantumCell::Existing(pow_248),
                        QuantumCell::Existing(salt_chunk0),
                    );
                    ctx.constrain_equal(&reconstructed, &salt_assigned);
                }

                // Helper closure body inlined twice (parent_id, block_id).
                let salted_endpoint = |ctx: &mut halo2_base::Context<Fr>,
                                       other: &[AssignedValue<Fr>]|
                 -> AssignedValue<Fr> {
                    let other_lo30 = {
                        let cells: Vec<QuantumCell<Fr>> = other[0..30]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_30.clone())
                    };
                    let chunk1 = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(other_lo30),
                        QuantumCell::Existing(pow_256),
                        QuantumCell::Existing(salt_hi),
                    );
                    let chunk2 = {
                        let cells: Vec<QuantumCell<Fr>> = other[30..32]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_2.clone())
                    };
                    hasher.hash_fix_len_array(ctx, gate, &[salt_chunk0, chunk1, chunk2])
                };

                let salted_start_block_id =
                    salted_endpoint(ctx, &parent_id_bytes);
                let salted_end_block_id = salted_endpoint(ctx, &block_id_bytes);

                (salted_start_block_id, salted_end_block_id, salt_commitment)
            };

            // Public instances [salted_start_block_id, salted_end_block_id, salt_commitment]
            builder.assigned_instances[0].push(salted_start_block_id);
            builder.assigned_instances[0].push(salted_end_block_id);
            builder.assigned_instances[0].push(salt_commitment);
        }

        let builder = self.base_circuit_builder.borrow();
        builder.synthesize(config.base_circuit_config, layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_hop_witness::{
        block_merkle_leaf_proof, block_merkle_root, proof_block_ref_inner_path_native,
        proof_block_refs_root_native, BLOCK_MERKLE_LEAF_COUNT,
    };
    use crate::salt::{
        compute_salt_commitment_native, compute_salt_native, compute_salted_block_id_native,
    };
    use halo2_base::gates::circuit::BaseCircuitParams;
    use halo2_base::halo2_proofs::dev::MockProver;

    /// Single-hop MockProver: one hop, single-ref ref-tree (parent only).
    #[test]
    fn hop_proof_single_hop_mock_prover() {
        // === Hand-build the hop witness ===
        let sk_u = Fr::from(0xCAFEu64);
        let parent_id: [u8; 32] = [0x11u8; 32];

        // Block: proof_block_refs = [parent_id]; L7 = ref-tree root; leaves
        // [0..7] sentinels; leaves[7] = L7; block_id = block_merkle_root.
        let proof_block_refs: Vec<[u8; 32]> = vec![parent_id];
        let l7 = proof_block_refs_root_native(&proof_block_refs);
        let mut leaves = [[0u8; 32]; BLOCK_MERKLE_LEAF_COUNT];
        for (j, slot) in leaves.iter_mut().enumerate().take(7) {
            *slot = [0x20 + j as u8; 32];
        }
        leaves[7] = l7;
        let block_id = block_merkle_root(&leaves);

        let block_merkle_leaf_proof_l7 = block_merkle_leaf_proof(&leaves, 7);
        let proof_block_ref_inner_path =
            proof_block_ref_inner_path_native(&proof_block_refs, 0);

        let hop = HopProofWitness {
            parent_id,
            block_id,
            l7,
            block_merkle_leaf_proof_l7,
            proof_block_ref_inner_path,
        };

        // === Expected publics ===
        let salt = compute_salt_native(sk_u);
        let salt_commitment = compute_salt_commitment_native(salt);
        let salted_start_block_id = compute_salted_block_id_native(salt, &parent_id);
        let salted_end_block_id = compute_salted_block_id_native(salt, &block_id);

        // === Circuit params ===
        // Single hop uses 3 SHA-256s (~354k advice cells each) + ~10 Poseidon
        // hashes + a couple of inner-products.
        const K: u32 = 19;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![8],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: Some(18),
            num_instance_columns: 1,
        };

        let circuit = HopProofCircuit::new(sk_u, hop, params);
        let instances = vec![vec![salted_start_block_id, salted_end_block_id, salt_commitment]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }
}
