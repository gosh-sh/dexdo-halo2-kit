//! Phase 4 MultiHopProof circuit — Stage 2c Phase A (single-hop, all-active).
//!
//! ## Scope (Phase A)
//!
//! Smallest possible MultiHopProof: **H=1** (one hop), **all active** (no
//! padding selector), **ref_index=0 hardcoded** (parent slot only — the only
//! case `synth_chain` produces), **leaf_index=7 hardcoded** (L7 sits at block-
//! merkle leaf index 7, so all 3 SHA-256 levels put the current node on the
//! right).
//!
//! ## Public instance layout (3 Fr per `bundle_verifier::MULTI_HOP_LEN`)
//!
//! | idx | name | derivation |
//! |---|---|---|
//! | 0 | `salted_start_block_id` | `Poseidon([salt, bytes_to_fr(parent_id)])` |
//! | 1 | `salted_end_block_id`   | `Poseidon([salt, bytes_to_fr(block_id)])` |
//! | 2 | `salt_commitment` | `Poseidon([salt])` |
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
//! - `proof_block_ref_inner_path`: 4 Poseidon siblings opening the ref-leaf
//!   against L7 at ref-index 0.
//!
//! ## Constraints (shape-mirror, NOT byte-flat production parity)
//!
//! 1. **SHA-256 path** — three `Sha256Chip::digest_bytes` calls, each consuming
//!    `sibling_bytes ‖ current_bytes` (leaf 7 puts the current node on the
//!    right at every level). Final 32-byte digest is constrained equal to
//!    `block_id` byte-by-byte.
//! 2. **Ref-tree path** — `ref_leaf = Poseidon([parent_tag_chunk_0,
//!    parent_tag_chunk_1, parent_id_fr])` (2 31-byte LE chunks of the 37-byte
//!    `REFERENCED_PARENT_BLOCK_TAG`, then `bytes_to_fr(parent_id)`). Four
//!    `Poseidon([cur, sibling])` calls walk to the L7 root (ref-index 0:
//!    current always on the left). Final Fr is constrained equal to the
//!    LE-byte-packed L7 value.
//! 3. **Salt math** — `salt`, `salt_commitment`, `salted_start_block_id`, `salted_end_block_id`
//!    all derived via `PoseidonHasher::hash_fix_len_array` using the
//!    `gosh_dense_balanced_tree::{T,RATE,R_F,R_P}` parameters.
//!
//! ## Not yet covered (later phases)
//!
//! - `TODO(stage-2c-phase-b)`: extend to H=5 with internal hop continuity
//!   (`ctx.constrain_equal(hops[i].salted_end_block_id, hops[i+1].salted_start_block_id)`).
//! - `TODO(stage-2c-phase-c)`: `is_active` selector + inactive padding.
//! - `TODO(stage-2c-suffix)`: byte-flat-Poseidon variant of the ref-tree
//!   walk (production-wire parity against live GQL L7 roots).
//! - `TODO(phase-4-prod)`: bump `MAX_PROOF_BLOCK_REFS` from 16 → 256.

use gosh_dense_balanced_tree::{bytes_to_fr, R_F, R_P, RATE, T};
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
    BLOCK_MERKLE_DEPTH, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH, REFERENCED_PARENT_BLOCK_TAG,
};
use crate::salt::domain_tag_hop_salt_fr;

const SHA256_HASH_LEN: usize = 32;

/// Public-instance count: `[salted_start_block_id, salted_end_block_id, salt_commitment]`.
pub const MULTI_HOP_PUBLIC_LEN: usize = 3;

/// Pack `REFERENCED_PARENT_BLOCK_TAG` (37 bytes) into 2 × 31-byte-LE Fr
/// chunks. Used as `ctx.load_constant` inputs to the in-circuit ref-leaf
/// Poseidon hash — must produce the same `Fr` values that
/// `multi_hop_witness::pack_tag_chunks` produces natively, otherwise the
/// in-circuit ref-leaf will not equal `ref_leaf_hash_native(0, parent_id)`.
fn parent_tag_fr_chunks() -> [Fr; 2] {
    let bytes = REFERENCED_PARENT_BLOCK_TAG;
    assert!(
        bytes.len() <= 62,
        "parent tag (>62 B) needs more than 2 31-byte chunks"
    );
    let mut c0 = [0u8; 32];
    c0[..31].copy_from_slice(&bytes[..31]);
    let mut c1 = [0u8; 32];
    let rem = bytes.len() - 31;
    c1[..rem].copy_from_slice(&bytes[31..]);
    [bytes_to_fr(&c0), bytes_to_fr(&c1)]
}

/// Phase A witness shape — one hop, ref_index=0, leaf_index=7.
///
/// Mirrors the relevant slice of `multi_hop_witness::HopWitness` (active
/// case, single reference) while dropping the fields the Phase A circuit
/// doesn't consume yet (e.g. `is_active`, `block_merkle_tree_leaves[0..7]`).
#[derive(Clone, Debug)]
pub struct PhaseAHopWitness {
    pub parent_id: [u8; 32],
    pub block_id: [u8; 32],
    pub l7: [u8; 32],
    /// 3 SHA-256 siblings opening L7 to `block_id` at leaf 7. Order: bottom-up
    /// (siblings[0] = pair with L7 → next level up; etc).
    pub block_merkle_leaf_proof_l7: [[u8; 32]; BLOCK_MERKLE_DEPTH],
    /// 4 Poseidon siblings opening the ref-leaf to L7 at ref-index 0.
    pub proof_block_ref_inner_path: [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
}

#[derive(Clone, Debug)]
pub struct MultiHopProofCircuitConfig {
    base_circuit_config: BaseConfig<Fr>,
}

pub struct MultiHopProofCircuit {
    /// Private witness: voucher secret. Drives `salt` and `salt_commitment`.
    pub sk_u: Fr,
    /// Phase A: single hop.
    pub hop: PhaseAHopWitness,
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl MultiHopProofCircuit {
    pub fn new(
        sk_u: Fr,
        hop: PhaseAHopWitness,
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
        hop: PhaseAHopWitness,
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

impl Circuit<Fr> for MultiHopProofCircuit {
    type Config = MultiHopProofCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base_circuit_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        let dummy_hop = PhaseAHopWitness {
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
        MultiHopProofCircuitConfig {
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

                // === LE 32-byte powers (used twice: for L7 and block_id Fr packing) ===
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
                    gate.inner_product(ctx, cells, powers_le_32.clone())
                };

                // === parent_id_fr (witness Fr; not byte-level, only used in
                //     ref-leaf and salted_start_block_id Poseidon inputs) ===
                let parent_id_fr =
                    ctx.load_witness(bytes_to_fr(&self.hop.parent_id));

                // === Ref-leaf = Poseidon([tag_c0, tag_c1, parent_id_fr]) ===
                let tag_chunks = parent_tag_fr_chunks();
                let tag_c0 = ctx.load_constant(tag_chunks[0]);
                let tag_c1 = ctx.load_constant(tag_chunks[1]);
                let ref_leaf_fr = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[tag_c0, tag_c1, parent_id_fr],
                );

                // === Ref-tree walk (4 levels, ref_index=0 → cur always on left) ===
                let mut cur_fr = ref_leaf_fr;
                for sib_bytes in &self.hop.proof_block_ref_inner_path {
                    let sib_fr = ctx.load_witness(bytes_to_fr(sib_bytes));
                    cur_fr = hasher.hash_fix_len_array(ctx, gate, &[cur_fr, sib_fr]);
                }
                ctx.constrain_equal(&cur_fr, &l7_fr);

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

                // === block_id_fr from byte cells (LE inner product) ===
                let block_id_fr = {
                    let cells: Vec<QuantumCell<Fr>> = block_id_bytes
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    gate.inner_product(ctx, cells, powers_le_32)
                };

                // === Salted endpoints ===
                let salted_start_block_id = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[salt_assigned, parent_id_fr],
                );
                let salted_end_block_id = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[salt_assigned, block_id_fr],
                );

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

// ===========================================================================
// Phase B — H=5 (all active, ref_index=0, leaf_index=7), with internal
// continuity constraints between consecutive hops.
// ===========================================================================
//
// Phase B keeps every per-hop constraint from Phase A and adds:
// - 5 hops, each constrained exactly as in Phase A
// - `ctx.constrain_equal(hops[i].salted_end_block_id, hops[i+1].salted_start_block_id)` for
//   i in 0..4 (intra-snark continuity)
// - Public instances: `[hops[0].salted_start_block_id, hops[4].salted_end_block_id,
//   salt_commitment]`
//
// Phase A remains in this file as a regression-checked single-hop scaffold.
// Phase C (later) will add an `is_active` selector for padding slots.

pub struct MultiHopProofCircuitB {
    /// Private witness: voucher secret.
    pub sk_u: Fr,
    /// H_HOPS_PER_PROOF (=5) hops, all active in Phase B.
    pub hops: [PhaseAHopWitness; H_HOPS_PER_PROOF],
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl MultiHopProofCircuitB {
    pub fn new(
        sk_u: Fr,
        hops: [PhaseAHopWitness; H_HOPS_PER_PROOF],
        base_circuit_params: BaseCircuitParams,
    ) -> Self {
        let base_circuit_builder = RefCell::new(
            BaseCircuitBuilder::<Fr>::new(false).use_params(base_circuit_params.clone()),
        );
        Self {
            sk_u,
            hops,
            base_circuit_params,
            base_circuit_builder,
        }
    }

    pub fn new_for_proving(
        sk_u: Fr,
        hops: [PhaseAHopWitness; H_HOPS_PER_PROOF],
        base_circuit_params: BaseCircuitParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        let base_circuit_builder = RefCell::new(BaseCircuitBuilder::<Fr>::prover(
            base_circuit_params.clone(),
            break_points,
        ));
        Self {
            sk_u,
            hops,
            base_circuit_params,
            base_circuit_builder,
        }
    }
}

impl Circuit<Fr> for MultiHopProofCircuitB {
    type Config = MultiHopProofCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base_circuit_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        let dummy_hop = || PhaseAHopWitness {
            parent_id: [0u8; 32],
            block_id: [0u8; 32],
            l7: [0u8; 32],
            block_merkle_leaf_proof_l7: [[0u8; 32]; BLOCK_MERKLE_DEPTH],
            proof_block_ref_inner_path: [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
        };
        let hops: [PhaseAHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|_| dummy_hop());
        Self::new(Fr::zero(), hops, self.base_circuit_params.clone())
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::configure_with_params(meta, Default::default())
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        let base_circuit_config = BaseCircuitBuilder::<Fr>::configure_with_params(meta, params);
        MultiHopProofCircuitConfig {
            base_circuit_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Same builder-reset dance as Phase A.
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

            let (first_salted_start_block_id, last_salted_end_block_id, salt_commitment) = {
                let gate = range.gate();
                let ctx = builder.pool(0).main();
                let sha256_chip = Sha256Chip::new(&range);

                let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
                let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
                hasher.initialize_consts(ctx, gate);

                // Salt + salt_commitment (bundle-wide; same for every hop).
                let sk_u_assigned = ctx.load_witness(self.sk_u);
                let domain_tag_fr_const = ctx.load_constant(domain_tag_hop_salt_fr());
                let salt_assigned = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[domain_tag_fr_const, sk_u_assigned],
                );
                let salt_commitment =
                    hasher.hash_fix_len_array(ctx, gate, &[salt_assigned]);

                // Constants reused across hops.
                let tag_chunks = parent_tag_fr_chunks();
                let tag_c0_const = tag_chunks[0];
                let tag_c1_const = tag_chunks[1];
                let powers_le_32_const: Vec<Fr> = (0..32)
                    .map(|i| Fr::from(256u64).pow([i as u64]))
                    .collect();

                let mut hop_endpoints: Vec<(AssignedValue<Fr>, AssignedValue<Fr>)> =
                    Vec::with_capacity(H_HOPS_PER_PROOF);

                for hop in &self.hops {
                    let powers_le_32: Vec<QuantumCell<Fr>> = powers_le_32_const
                        .iter()
                        .map(|p| QuantumCell::Constant(*p))
                        .collect();

                    // L7 bytes + LE Fr packing.
                    let l7_bytes: Vec<AssignedValue<Fr>> = hop
                        .l7
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();
                    let l7_fr = {
                        let cells: Vec<QuantumCell<Fr>> = l7_bytes
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_32.clone())
                    };

                    let parent_id_fr = ctx.load_witness(bytes_to_fr(&hop.parent_id));

                    let tag_c0 = ctx.load_constant(tag_c0_const);
                    let tag_c1 = ctx.load_constant(tag_c1_const);
                    let ref_leaf_fr = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[tag_c0, tag_c1, parent_id_fr],
                    );

                    let mut cur_fr = ref_leaf_fr;
                    for sib_bytes in &hop.proof_block_ref_inner_path {
                        let sib_fr = ctx.load_witness(bytes_to_fr(sib_bytes));
                        cur_fr = hasher.hash_fix_len_array(ctx, gate, &[cur_fr, sib_fr]);
                    }
                    ctx.constrain_equal(&cur_fr, &l7_fr);

                    let block_id_bytes: Vec<AssignedValue<Fr>> = hop
                        .block_id
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();

                    let mut cur_bytes = l7_bytes;
                    for sib_bytes in &hop.block_merkle_leaf_proof_l7 {
                        let sib_cells: Vec<AssignedValue<Fr>> = sib_bytes
                            .iter()
                            .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                            .collect();
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

                    let block_id_fr = {
                        let cells: Vec<QuantumCell<Fr>> = block_id_bytes
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_32)
                    };

                    let salted_start_block_id = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[salt_assigned, parent_id_fr],
                    );
                    let salted_end_block_id = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[salt_assigned, block_id_fr],
                    );

                    hop_endpoints.push((salted_start_block_id, salted_end_block_id));
                }

                // Intra-snark continuity: hops[i].salted_end_block_id == hops[i+1].salted_start_block_id.
                for i in 0..H_HOPS_PER_PROOF - 1 {
                    ctx.constrain_equal(&hop_endpoints[i].1, &hop_endpoints[i + 1].0);
                }

                (
                    hop_endpoints[0].0,
                    hop_endpoints[H_HOPS_PER_PROOF - 1].1,
                    salt_commitment,
                )
            };

            builder.assigned_instances[0].push(first_salted_start_block_id);
            builder.assigned_instances[0].push(last_salted_end_block_id);
            builder.assigned_instances[0].push(salt_commitment);
        }

        let builder = self.base_circuit_builder.borrow();
        builder.synthesize(config.base_circuit_config, layouter)?;
        Ok(())
    }
}

// ===========================================================================
// Phase C — H=5 with `is_active` selector for inactive padding hops.
// ===========================================================================
//
// Differences vs Phase B:
// - `PhaseCHopWitness` carries `is_active: bool` plus explicit `salted_start_block_id`
//   and `salted_end_block_id` (the synth chain's authoritative endpoints — needed
//   because inactive padding hops carry the terminal value, not
//   `Poseidon(salt, 0)` which the Phase B derivation would compute from the
//   zeroed `parent_id`/`block_id` witness).
// - Per-hop equality constraints are gated by `is_active`:
//   * ref-tree:   `(cur_fr - l7_fr) * is_active == 0`
//   * SHA-256:    `(cur_bytes[i] - block_id_bytes[i]) * is_active == 0`
//   * salted endpoints: `(salted_start_block_id - Poseidon(salt, parent_id_fr)) *
//                        is_active == 0` (and similarly for end)
// - For inactive hops: `(salted_start_block_id - salted_end_block_id) * (1 - is_active) == 0`
//   so padding propagates the terminal value.
// - Continuity `hops[i].salted_end_block_id == hops[i+1].salted_start_block_id` stays
//   unconditional (works for both active and inactive transitions).
// - `is_active` is range-constrained to {0,1} via `gate.assert_bit`.

#[derive(Clone, Debug)]
pub struct PhaseCHopWitness {
    pub is_active: bool,
    pub parent_id: [u8; 32],
    pub block_id: [u8; 32],
    pub l7: [u8; 32],
    pub block_merkle_leaf_proof_l7: [[u8; 32]; BLOCK_MERKLE_DEPTH],
    pub proof_block_ref_inner_path: [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
    pub salted_start_block_id: Fr,
    pub salted_end_block_id: Fr,
}

pub struct MultiHopProofCircuitC {
    pub sk_u: Fr,
    pub hops: [PhaseCHopWitness; H_HOPS_PER_PROOF],
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl MultiHopProofCircuitC {
    pub fn new(
        sk_u: Fr,
        hops: [PhaseCHopWitness; H_HOPS_PER_PROOF],
        base_circuit_params: BaseCircuitParams,
    ) -> Self {
        let base_circuit_builder = RefCell::new(
            BaseCircuitBuilder::<Fr>::new(false).use_params(base_circuit_params.clone()),
        );
        Self {
            sk_u,
            hops,
            base_circuit_params,
            base_circuit_builder,
        }
    }

    pub fn new_for_proving(
        sk_u: Fr,
        hops: [PhaseCHopWitness; H_HOPS_PER_PROOF],
        base_circuit_params: BaseCircuitParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        let base_circuit_builder = RefCell::new(BaseCircuitBuilder::<Fr>::prover(
            base_circuit_params.clone(),
            break_points,
        ));
        Self {
            sk_u,
            hops,
            base_circuit_params,
            base_circuit_builder,
        }
    }
}

impl Circuit<Fr> for MultiHopProofCircuitC {
    type Config = MultiHopProofCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base_circuit_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        let dummy_hop = || PhaseCHopWitness {
            is_active: false,
            parent_id: [0u8; 32],
            block_id: [0u8; 32],
            l7: [0u8; 32],
            block_merkle_leaf_proof_l7: [[0u8; 32]; BLOCK_MERKLE_DEPTH],
            proof_block_ref_inner_path: [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
            salted_start_block_id: Fr::zero(),
            salted_end_block_id: Fr::zero(),
        };
        let hops: [PhaseCHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|_| dummy_hop());
        Self::new(Fr::zero(), hops, self.base_circuit_params.clone())
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::configure_with_params(meta, Default::default())
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        let base_circuit_config = BaseCircuitBuilder::<Fr>::configure_with_params(meta, params);
        MultiHopProofCircuitConfig {
            base_circuit_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
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

            let (first_salted_start_block_id, last_salted_end_block_id, salt_commitment) = {
                let gate = range.gate();
                let ctx = builder.pool(0).main();
                let sha256_chip = Sha256Chip::new(&range);

                let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
                let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
                hasher.initialize_consts(ctx, gate);

                let sk_u_assigned = ctx.load_witness(self.sk_u);
                let domain_tag_fr_const = ctx.load_constant(domain_tag_hop_salt_fr());
                let salt_assigned = hasher.hash_fix_len_array(
                    ctx,
                    gate,
                    &[domain_tag_fr_const, sk_u_assigned],
                );
                let salt_commitment =
                    hasher.hash_fix_len_array(ctx, gate, &[salt_assigned]);

                let tag_chunks = parent_tag_fr_chunks();
                let tag_c0_const = tag_chunks[0];
                let tag_c1_const = tag_chunks[1];
                let powers_le_32_const: Vec<Fr> = (0..32)
                    .map(|i| Fr::from(256u64).pow([i as u64]))
                    .collect();

                let mut hop_endpoints: Vec<(AssignedValue<Fr>, AssignedValue<Fr>)> =
                    Vec::with_capacity(H_HOPS_PER_PROOF);

                for hop in &self.hops {
                    let is_active = ctx.load_witness(if hop.is_active {
                        Fr::one()
                    } else {
                        Fr::zero()
                    });
                    gate.assert_bit(ctx, is_active);
                    let one_const = ctx.load_constant(Fr::one());
                    let not_active = gate.sub(
                        ctx,
                        QuantumCell::Existing(one_const),
                        QuantumCell::Existing(is_active),
                    );

                    let powers_le_32: Vec<QuantumCell<Fr>> = powers_le_32_const
                        .iter()
                        .map(|p| QuantumCell::Constant(*p))
                        .collect();

                    let l7_bytes: Vec<AssignedValue<Fr>> = hop
                        .l7
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();
                    let l7_fr = {
                        let cells: Vec<QuantumCell<Fr>> = l7_bytes
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_32.clone())
                    };

                    let parent_id_fr = ctx.load_witness(bytes_to_fr(&hop.parent_id));

                    let tag_c0 = ctx.load_constant(tag_c0_const);
                    let tag_c1 = ctx.load_constant(tag_c1_const);
                    let ref_leaf_fr = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[tag_c0, tag_c1, parent_id_fr],
                    );

                    let mut cur_fr = ref_leaf_fr;
                    for sib_bytes in &hop.proof_block_ref_inner_path {
                        let sib_fr = ctx.load_witness(bytes_to_fr(sib_bytes));
                        cur_fr = hasher.hash_fix_len_array(ctx, gate, &[cur_fr, sib_fr]);
                    }
                    // Gated ref-tree root equality: (cur_fr - l7_fr) * is_active == 0
                    {
                        let diff = gate.sub(
                            ctx,
                            QuantumCell::Existing(cur_fr),
                            QuantumCell::Existing(l7_fr),
                        );
                        let gated = gate.mul(
                            ctx,
                            QuantumCell::Existing(diff),
                            QuantumCell::Existing(is_active),
                        );
                        gate.assert_is_const(ctx, &gated, &Fr::zero());
                    }

                    let block_id_bytes: Vec<AssignedValue<Fr>> = hop
                        .block_id
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();

                    let mut cur_bytes = l7_bytes;
                    for sib_bytes in &hop.block_merkle_leaf_proof_l7 {
                        let sib_cells: Vec<AssignedValue<Fr>> = sib_bytes
                            .iter()
                            .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                            .collect();
                        let mut concat: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
                        concat.extend_from_slice(&sib_cells);
                        concat.extend_from_slice(&cur_bytes);
                        let next = sha256_chip.digest_bytes(ctx, &concat);
                        assert_eq!(next.len(), SHA256_HASH_LEN);
                        cur_bytes = next;
                    }
                    // Gated SHA-256 byte equality.
                    for i in 0..SHA256_HASH_LEN {
                        let diff = gate.sub(
                            ctx,
                            QuantumCell::Existing(cur_bytes[i]),
                            QuantumCell::Existing(block_id_bytes[i]),
                        );
                        let gated = gate.mul(
                            ctx,
                            QuantumCell::Existing(diff),
                            QuantumCell::Existing(is_active),
                        );
                        gate.assert_is_const(ctx, &gated, &Fr::zero());
                    }

                    let block_id_fr = {
                        let cells: Vec<QuantumCell<Fr>> = block_id_bytes
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_32)
                    };

                    // Compute the "active" endpoint values.
                    let start_computed = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[salt_assigned, parent_id_fr],
                    );
                    let end_computed = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[salt_assigned, block_id_fr],
                    );

                    // Witness the salted endpoints (authoritative for both
                    // active and inactive hops).
                    let salted_start_block_id_w = ctx.load_witness(hop.salted_start_block_id);
                    let salted_end_block_id_w = ctx.load_witness(hop.salted_end_block_id);

                    // Active-gated: salted_start_block_id == start_computed.
                    {
                        let diff = gate.sub(
                            ctx,
                            QuantumCell::Existing(salted_start_block_id_w),
                            QuantumCell::Existing(start_computed),
                        );
                        let gated = gate.mul(
                            ctx,
                            QuantumCell::Existing(diff),
                            QuantumCell::Existing(is_active),
                        );
                        gate.assert_is_const(ctx, &gated, &Fr::zero());
                    }
                    // Active-gated: salted_end_block_id == end_computed.
                    {
                        let diff = gate.sub(
                            ctx,
                            QuantumCell::Existing(salted_end_block_id_w),
                            QuantumCell::Existing(end_computed),
                        );
                        let gated = gate.mul(
                            ctx,
                            QuantumCell::Existing(diff),
                            QuantumCell::Existing(is_active),
                        );
                        gate.assert_is_const(ctx, &gated, &Fr::zero());
                    }
                    // Inactive-gated: salted_start_block_id == salted_end_block_id (propagate
                    // terminal value through padding hops).
                    {
                        let diff = gate.sub(
                            ctx,
                            QuantumCell::Existing(salted_start_block_id_w),
                            QuantumCell::Existing(salted_end_block_id_w),
                        );
                        let gated = gate.mul(
                            ctx,
                            QuantumCell::Existing(diff),
                            QuantumCell::Existing(not_active),
                        );
                        gate.assert_is_const(ctx, &gated, &Fr::zero());
                    }

                    hop_endpoints.push((salted_start_block_id_w, salted_end_block_id_w));
                }

                // Unconditional continuity (works across active/inactive).
                for i in 0..H_HOPS_PER_PROOF - 1 {
                    ctx.constrain_equal(&hop_endpoints[i].1, &hop_endpoints[i + 1].0);
                }

                (
                    hop_endpoints[0].0,
                    hop_endpoints[H_HOPS_PER_PROOF - 1].1,
                    salt_commitment,
                )
            };

            builder.assigned_instances[0].push(first_salted_start_block_id);
            builder.assigned_instances[0].push(last_salted_end_block_id);
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

    /// Phase A MockProver: one hop, single-ref ref-tree (parent only).
    #[test]
    fn phase_a_single_hop_mock_prover() {
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

        let hop = PhaseAHopWitness {
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
        // Phase A uses 3 SHA-256s (~354k advice cells each) + ~10 Poseidon
        // hashes + a couple of inner-products. Start generous; tune later.
        const K: u32 = 19;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![8],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: Some(18),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuit::new(sk_u, hop, params);
        let instances = vec![vec![salted_start_block_id, salted_end_block_id, salt_commitment]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }

    /// Phase B MockProver: H=5 hops, all active, intra-snark continuity.
    ///
    /// Uses `test_helpers::synth_chain(seed, 5)` so all 5 hops are real
    /// (k_hops = H_HOPS_PER_PROOF, no padding needed). Takes the first snark
    /// from `split_into_bundle_snarks` — its 5 hops form a contiguous chain
    /// `genesis → b_1 → b_2 → b_3 → b_4 → b_5`.
    #[test]
    fn phase_b_five_hops_mock_prover() {
        use crate::test_helpers::{split_into_bundle_snarks, synth_chain};

        let chain = synth_chain(0xB00B_5EEDu64, H_HOPS_PER_PROOF);
        let snarks = split_into_bundle_snarks(&chain);
        let snark0 = &snarks[0];
        // All 5 hops in snark0 are real (k_hops == H_HOPS_PER_PROOF).
        for hop in snark0.hops.iter() {
            assert!(hop.is_active);
        }

        // Project the full HopWitness fields into PhaseAHopWitness.
        let phase_a_hops: [PhaseAHopWitness; H_HOPS_PER_PROOF] = std::array::from_fn(|i| {
            let h = &snark0.hops[i];
            PhaseAHopWitness {
                parent_id: h.block.proof_block_refs[0],
                block_id: h.block.block_id,
                l7: h.block.block_merkle_tree_leaves[7],
                block_merkle_leaf_proof_l7: h.block_merkle_leaf_proof_l7,
                proof_block_ref_inner_path: h.proof_block_ref_inner_path,
            }
        });

        // Expected publics: first hop's salted_start_block_id, last hop's salted_end_block_id,
        // salt_commitment.
        let first_salted_start_block_id = snark0.hops[0].salted_start_block_id;
        let last_salted_end_block_id = snark0.hops[H_HOPS_PER_PROOF - 1].salted_end_block_id;
        let salt_commitment = snark0.salt_commitment;

        // Sanity: continuity holds in the synth chain (the circuit will assert it).
        for i in 0..H_HOPS_PER_PROOF - 1 {
            assert_eq!(snark0.hops[i].salted_end_block_id, snark0.hops[i + 1].salted_start_block_id);
        }

        // Sizing: Phase A used 8 cols for 3 SHA-256s. Phase B has 15 SHA-256s
        // → ~5× more cells; bump to 48 cols at K=19 for comfortable headroom.
        const K: u32 = 19;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![48],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![4],
            lookup_bits: Some(18),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuitB::new(chain.sk_u, phase_a_hops, params);
        let instances = vec![vec![first_salted_start_block_id, last_salted_end_block_id, salt_commitment]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }

    /// Helper: project a `HopWitness` into `PhaseCHopWitness` for Phase C
    /// circuit input.
    fn hop_to_phase_c(
        h: &crate::multi_hop_witness::HopWitness,
    ) -> PhaseCHopWitness {
        let parent_id = if h.block.proof_block_refs.is_empty() {
            [0u8; 32]
        } else {
            h.block.proof_block_refs[0]
        };
        PhaseCHopWitness {
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

    /// Phase C MockProver — partial bundle, mixed active/inactive hops.
    ///
    /// `synth_chain(seed, 2)` ⇒ snark0 has hops[0..2] active (chain
    /// `genesis → b_1 → b_2`) and hops[2..5] inactive (each carrying the
    /// terminal salted endpoint of b_2). Exercises the gated equality
    /// constraints and the active↔inactive continuity transition at i=1→i=2.
    #[test]
    fn phase_c_mixed_hops_mock_prover() {
        use crate::test_helpers::{split_into_bundle_snarks, synth_chain};

        let chain = synth_chain(0xC0FFEEu64, 2);
        let snarks = split_into_bundle_snarks(&chain);
        let snark0 = &snarks[0];
        assert!(snark0.hops[0].is_active);
        assert!(snark0.hops[1].is_active);
        for i in 2..H_HOPS_PER_PROOF {
            assert!(!snark0.hops[i].is_active);
        }

        let phase_c_hops: [PhaseCHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_phase_c(&snark0.hops[i]));

        let first_salted_start_block_id = snark0.hops[0].salted_start_block_id;
        let last_salted_end_block_id = snark0.hops[H_HOPS_PER_PROOF - 1].salted_end_block_id;
        let salt_commitment = snark0.salt_commitment;

        // Sanity: continuity holds.
        for i in 0..H_HOPS_PER_PROOF - 1 {
            assert_eq!(snark0.hops[i].salted_end_block_id, snark0.hops[i + 1].salted_start_block_id);
        }

        // Phase C adds ~34 mul + ~34 sub per hop on top of Phase B work.
        // Bump to 56 cols at K=19 for headroom.
        const K: u32 = 19;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![56],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![4],
            lookup_bits: Some(18),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuitC::new(chain.sk_u, phase_c_hops, params);
        let instances = vec![vec![first_salted_start_block_id, last_salted_end_block_id, salt_commitment]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }

    /// Phase C MockProver — all-inactive snark (chain ends before this snark).
    ///
    /// `synth_chain(seed, 0)` ⇒ every hop in every snark is inactive, all
    /// salted endpoints equal `bundle_head_salted`. Exercises the case where
    /// no SHA-256 / ref-tree constraint is enforced at all.
    #[test]
    fn phase_c_all_inactive_mock_prover() {
        use crate::test_helpers::{split_into_bundle_snarks, synth_chain};

        let chain = synth_chain(0xDEADBEEFu64, 0);
        let snarks = split_into_bundle_snarks(&chain);
        let snark0 = &snarks[0];
        for hop in snark0.hops.iter() {
            assert!(!hop.is_active);
            assert_eq!(hop.salted_start_block_id, hop.salted_end_block_id);
            assert_eq!(hop.salted_start_block_id, chain.bundle_head_salted);
        }

        let phase_c_hops: [PhaseCHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_phase_c(&snark0.hops[i]));

        const K: u32 = 19;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![56],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![4],
            lookup_bits: Some(18),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuitC::new(chain.sk_u, phase_c_hops, params);
        let instances = vec![vec![
            chain.bundle_head_salted,
            chain.bundle_head_salted,
            chain.salt_commitment,
        ]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }
}
