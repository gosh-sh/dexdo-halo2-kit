//! MultiHopProof circuit — production bundle-scope proof.
//!
//! Proves `H_HOPS_PER_PROOF = 5` hops (spec §6.4) in one snark with an
//! `is_active` selector for inactive padding hops, so a snark covering
//! fewer real hops can collapse its tail to the bundle's terminal salted
//! endpoint. Exposes the first hop's `salted_start_block_id`, the last
//! hop's `salted_end_block_id`, and the bundle's `salt_commitment` as
//! public instances.
//!
//! For a standalone single-hop example circuit (not used here, but with
//! the same per-hop constraint shape), see
//! [`crate::hop_proof::HopProofCircuit`].
//!
//! ## Public instance layout (3 Fr — `MULTI_HOP_PUBLIC_LEN`)
//!
//! | idx | name | derivation |
//! |---|---|---|
//! | 0 | `salted_start_block_id` | `hops[0].salted_start_block_id` |
//! | 1 | `salted_end_block_id`   | `hops[H_HOPS_PER_PROOF-1].salted_end_block_id` |
//! | 2 | `salt_commitment`       | `Poseidon([salt])` |
//!
//! ## Witness ([`MultiHopWitness`])
//!
//! Each hop carries:
//! - `is_active`: bool selector. Inactive hops skip ref-tree / SHA-256 /
//!   salted-endpoint equality enforcement and instead propagate the bundle's
//!   terminal salted value.
//! - `ref_block_id`, `block_id`, `l7`, `block_merkle_leaf_proof_l7`,
//!   `ref_index`, `proof_block_ref_inner_path`: same shape as
//!   [`crate::hop_proof::HopProofWitness`]. `ref_index` is a private
//!   per-hop witness in `1..MAX_PROOF_BLOCK_REFS` selecting which slot of
//!   the on-chain `proof_block_refs` list holds `ref_block_id`. Slot 0
//!   (parent) is same-thread by producer construction (spec §2.3) and
//!   excluded from the L7 walk (spec §5.1); only
//!   `REFERENCED_REF_BLOCK_TAG` (34 B) is used.
//! - `salted_start_block_id`, `salted_end_block_id`: explicit authoritative
//!   endpoints (the synth chain's terminal values for inactive padding,
//!   matching `compute_salted_block_id_native` for active hops).
//!
//! ## Constraints
//!
//! Bundle-wide (once per snark):
//! - `salt = Poseidon([DOMAIN_TAG_HOP_SALT_FR, sk_u])` and
//!   `salt_commitment = Poseidon([salt])`.
//! - `salt` is decomposed once into `salt_chunk0 (31 B) + salt_hi (1 B) ·
//!   2^248`, range-checked and algebraically linked back to `salt`.
//!
//! Per hop:
//! - `is_active` is range-constrained to `{0, 1}` via `gate.assert_bit`.
//! - **Ref-tree** — `ref_leaf = Poseidon([c0, c1, c2])` (byte-flat chunks of
//!   `REFERENCED_REF_BLOCK_TAG (34 B) ‖ ref_block_id`, see
//!   [`crate::hop_proof`]) is walked through
//!   `dense_merkle_root_circuit` to produce `computed_l7_fr`. The internal
//!   range checks and chunk-link constraints inside the walk are
//!   unconditional decomposition constraints. Only the final equality
//!   `computed_l7_fr == l7_fr` is gated:
//!   `(computed_l7_fr - l7_fr) * is_active == 0`.
//! - **SHA-256** — three `Sha256Chip::digest_bytes` calls open L7 to the
//!   target `block_id` at leaf index 7. Byte equality is gated:
//!   `(cur_bytes[i] - block_id_bytes[i]) * is_active == 0`.
//! - **Salted endpoints** — `start_computed` and `end_computed` are derived
//!   unconditionally via the byte-flat `Poseidon([salt_chunk0,
//!   salt_hi + 256·LE(endpoint_id_bytes[0..30]),
//!   LE(endpoint_id_bytes[30..32])])` rule. Equality vs
//!   the witnessed `salted_*_block_id` is active-gated:
//!   `(salted_start_block_id - start_computed) * is_active == 0` (and
//!   similarly for end).
//! - **Padding propagation** — inactive hops must carry a terminal value
//!   through, so `(salted_start_block_id - salted_end_block_id) * (1 -
//!   is_active) == 0`.
//!
//! Intra-snark continuity (unconditional, holds across active↔inactive
//! transitions): `hops[i].salted_end_block_id == hops[i+1].salted_start_block_id`
//! for `i = 0..H_HOPS_PER_PROOF-1`.
//!
//! ## Open scope items
//!
//! - **`MAX_PROOF_BLOCK_REFS = 16`** — first-cut testing value; production
//!   needs 256 (spec §10.1). Bumping only enlarges the L7-inner-path padding.

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

use crate::boc_helper::SHA256_HASH_LEN;
use crate::multi_hop_witness::{
    ref_leaf_hash_native, ref_leaf_ref_tag_chunk0_fr, ref_leaf_ref_tag_chunk1_lo_fr,
    BLOCK_MERKLE_DEPTH, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH,
};
use crate::salt::{compute_salt_native, domain_tag_hop_salt_fr};

/// Public-instance count: `[salted_start_block_id, salted_end_block_id, salt_commitment]`.
pub const MULTI_HOP_PUBLIC_LEN: usize = 3;

/// Per-hop witness shape for [`MultiHopProofCircuit`].
///
/// Carries `is_active` plus the authoritative `salted_start_block_id` and
/// `salted_end_block_id` for the hop (the synth chain's endpoints — needed
/// because inactive padding hops carry the bundle's terminal value, not
/// `Poseidon(salt, 0)` which would be derived from zeroed
/// `ref_block_id`/`block_id` witness bytes).
#[derive(Clone, Debug)]
pub struct MultiHopWitness {
    pub is_active: bool,
    pub ref_block_id: [u8; 32],
    pub block_id: [u8; 32],
    pub l7: [u8; 32],
    pub block_merkle_leaf_proof_l7: [[u8; 32]; BLOCK_MERKLE_DEPTH],
    /// Position of `ref_block_id` within the on-chain `proof_block_refs` list
    /// (`1..MAX_PROOF_BLOCK_REFS`). Slot 0 is the same-thread `parent_block_id`
    /// (spec §2.3) and never opened as a cross-thread hop edge (spec §5.1), so
    /// `ref_index == 0` is rejected in-circuit. Drives the orientation bits
    /// inside `dense_merkle_root_circuit`.
    pub ref_index: usize,
    pub proof_block_ref_inner_path: [[u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
    pub salted_start_block_id: Fr,
    pub salted_end_block_id: Fr,
}

#[derive(Clone, Debug)]
pub struct MultiHopProofCircuitConfig {
    base_circuit_config: BaseConfig<Fr>,
}

pub struct MultiHopProofCircuit {
    pub sk_u: Fr,
    pub hops: [MultiHopWitness; H_HOPS_PER_PROOF],
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl MultiHopProofCircuit {
    pub fn new(
        sk_u: Fr,
        hops: [MultiHopWitness; H_HOPS_PER_PROOF],
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
        hops: [MultiHopWitness; H_HOPS_PER_PROOF],
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

impl Circuit<Fr> for MultiHopProofCircuit {
    type Config = MultiHopProofCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base_circuit_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        let dummy_hop = || MultiHopWitness {
            is_active: false,
            ref_block_id: [0u8; 32],
            block_id: [0u8; 32],
            l7: [0u8; 32],
            block_merkle_leaf_proof_l7: [[0u8; 32]; BLOCK_MERKLE_DEPTH],
            // Slot 0 is same-thread parent — excluded from L7 walk (spec §5.1).
            // Even for inactive padding, ref_index must be ≥ 1 since the
            // range/nonzero constraint on ref_index is unconditional.
            ref_index: 1,
            proof_block_ref_inner_path: [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
            salted_start_block_id: Fr::zero(),
            salted_end_block_id: Fr::zero(),
        };
        let hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
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

                // === Byte-flat constants (reused across all hops) ===
                // Ref-tag (34 B) chunk constants. Slot 0 (parent) is same-thread
                // by producer construction (spec §2.3) and excluded from the
                // L7 walk (spec §5.1), so only the ref-tag layout is used.
                let ref_leaf_c0_const = ctx.load_constant(ref_leaf_ref_tag_chunk0_fr());
                let ref_leaf_c1_tag_const = ctx.load_constant(ref_leaf_ref_tag_chunk1_lo_fr());
                let pow_256_3 = ctx.load_constant(Fr::from(256u64).pow([3u64]));
                let pow_248 =
                    ctx.load_constant(Fr::from_raw([0u64, 0u64, 0u64, 1u64 << 56]));
                let pow_256 = ctx.load_constant(Fr::from(256u64));
                // LE byte→Fr power-of-256 table, shared by every inner_product in
                // the per-hop loop (L7 pack, ref-leaf chunk math, salted-endpoint
                // chunk math). Built once; sliced at each call site.
                let powers_le_32: Vec<QuantumCell<Fr>> = (0..32)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();

                // === Salt decomposition: salt_fr == salt_chunk0 + salt_hi · 2^248 ===
                let salt_native = compute_salt_native(self.sk_u);
                let salt_bytes_native = fr_to_bytes(salt_native);
                let mut salt_chunk0_buf = [0u8; 32];
                salt_chunk0_buf[..31].copy_from_slice(&salt_bytes_native[..31]);
                let salt_chunk0_native = bytes_to_fr(&salt_chunk0_buf);
                let salt_hi_native = Fr::from(salt_bytes_native[31] as u64);
                let salt_chunk0 = ctx.load_witness(salt_chunk0_native);
                let salt_hi = ctx.load_witness(salt_hi_native);
                range.range_check(ctx, salt_chunk0, 248);
                range.range_check(ctx, salt_hi, 8);
                {
                    let reconstructed = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(salt_hi),
                        QuantumCell::Existing(pow_248),
                        QuantumCell::Existing(salt_chunk0),
                    );
                    ctx.constrain_equal(&reconstructed, &salt_assigned);
                }

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

                    // === ref_index witness (1..MAX_PROOF_BLOCK_REFS) ===
                    // Slot 0 (parent) is same-thread by producer construction
                    // (spec §2.3) and never opened as a hop edge (spec §5.1).
                    // For inactive padding hops the witness carries
                    // `ref_index = 1` (see MultiHopWitness::without_witnesses
                    // and test helpers) to satisfy the same constraint.
                    let ref_index_assigned =
                        ctx.load_witness(Fr::from(hop.ref_index as u64));
                    range.range_check(
                        ctx,
                        ref_index_assigned,
                        MAX_PROOF_BLOCK_REFS_DEPTH,
                    );
                    {
                        let is_zero_ref_index = gate.is_zero(ctx, ref_index_assigned);
                        gate.assert_is_const(ctx, &is_zero_ref_index, &Fr::zero());
                    }

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
                        gate.inner_product(ctx, cells, powers_le_32[..32].iter().cloned())
                    };

                    // ref_block_id as 32 byte cells (range-checked 8 bits each).
                    let ref_block_id_bytes: Vec<AssignedValue<Fr>> = hop
                        .ref_block_id
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();
                    for cell in &ref_block_id_bytes {
                        range.range_check(ctx, *cell, 8);
                    }

                    // Byte-flat ref-leaf chunks — ref-tag layout only (34 B tag):
                    // chunks 31+31+4
                    //   c0 = tag_r_hi (31 B)
                    //   c1 = tag_r_lo (3 B) + ref_block_id_lo28 · 256^3
                    //   c2 = LE(ref_block_id[28..32])
                    let ref_block_id_lo28 = {
                        let cells: Vec<QuantumCell<Fr>> = ref_block_id_bytes[0..28]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_32[..28].iter().cloned())
                    };
                    let ref_block_id_lo28_shifted = gate.mul(
                        ctx,
                        QuantumCell::Existing(ref_block_id_lo28),
                        QuantumCell::Existing(pow_256_3),
                    );
                    let ref_leaf_c1 = gate.add(
                        ctx,
                        QuantumCell::Existing(ref_leaf_c1_tag_const),
                        QuantumCell::Existing(ref_block_id_lo28_shifted),
                    );
                    let ref_leaf_c2 = {
                        let cells: Vec<QuantumCell<Fr>> = ref_block_id_bytes[28..32]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(ctx, cells, powers_le_32[..4].iter().cloned())
                    };
                    let ref_leaf_fr = hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[ref_leaf_c0_const, ref_leaf_c1, ref_leaf_c2],
                    );

                    // Byte-flat ref-tree walk. The internal range checks and
                    // chunk-link constraints inside `dense_merkle_root_circuit`
                    // are unconditional decomposition constraints — they hold
                    // for any leaf/sibling input (active or padded). Only the
                    // final equality against `l7_fr` is gated by `is_active`.
                    let ref_leaf_native_bytes =
                        ref_leaf_hash_native(hop.ref_index, &hop.ref_block_id);
                    let ref_proof = preprocess_dense_proof_padded(
                        ref_leaf_native_bytes,
                        &hop.proof_block_ref_inner_path,
                        hop.ref_index,
                        MAX_PROOF_BLOCK_REFS_DEPTH,
                    );
                    let computed_l7_fr = dense_merkle_root_circuit(
                        ctx,
                        &range,
                        &hasher,
                        &ref_proof,
                        ref_leaf_fr,
                    );
                    // Gated ref-tree root equality: (computed_l7_fr - l7_fr) * is_active == 0
                    {
                        let diff = gate.sub(
                            ctx,
                            QuantumCell::Existing(computed_l7_fr),
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

                    // Byte-flat salted endpoints (data = salt || endpoint_id_bytes, 31+31+2).
                    // Computed unconditionally — only the equality vs the
                    // witnessed salted_*_block_id is gated.
                    let salted_endpoint = |ctx: &mut halo2_base::Context<Fr>,
                                           endpoint_id_bytes: &[AssignedValue<Fr>]|
                     -> AssignedValue<Fr> {
                        let endpoint_id_lo30 = {
                            let cells: Vec<QuantumCell<Fr>> = endpoint_id_bytes[0..30]
                                .iter()
                                .map(|c| QuantumCell::Existing(*c))
                                .collect();
                            gate.inner_product(ctx, cells, powers_le_32[..30].iter().cloned())
                        };
                        let chunk1 = gate.mul_add(
                            ctx,
                            QuantumCell::Existing(endpoint_id_lo30),
                            QuantumCell::Existing(pow_256),
                            QuantumCell::Existing(salt_hi),
                        );
                        let chunk2 = {
                            let cells: Vec<QuantumCell<Fr>> = endpoint_id_bytes[30..32]
                                .iter()
                                .map(|c| QuantumCell::Existing(*c))
                                .collect();
                            gate.inner_product(ctx, cells, powers_le_32[..2].iter().cloned())
                        };
                        hasher.hash_fix_len_array(
                            ctx,
                            gate,
                            &[salt_chunk0, chunk1, chunk2],
                        )
                    };
                    let start_computed = salted_endpoint(ctx, &ref_block_id_bytes);
                    let end_computed = salted_endpoint(ctx, &block_id_bytes);

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
    use halo2_base::gates::circuit::BaseCircuitParams;
    use halo2_base::halo2_proofs::dev::MockProver;

    /// Project a `HopWitness` into [`MultiHopWitness`] for circuit input.
    fn hop_to_multi_hop(
        h: &crate::multi_hop_witness::HopWitness,
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

    /// MockProver — partial bundle, mixed active/inactive hops.
    ///
    /// `synth_chain(seed, 2)` ⇒ snark0 has hops[0..2] active (chain
    /// `genesis → b_1 → b_2`) and hops[2..5] inactive (each carrying the
    /// terminal salted endpoint of b_2). Exercises the gated equality
    /// constraints and the active↔inactive continuity transition at i=1→i=2.
    #[test]
    fn mixed_hops_mock_prover() {
        use crate::test_helpers::{split_into_bundle_snarks, synth_chain};

        let chain = synth_chain(0xC0FFEEu64, 2);
        let snarks = split_into_bundle_snarks(&chain);
        let snark0 = &snarks[0];
        assert!(snark0.hops[0].is_active);
        assert!(snark0.hops[1].is_active);
        for i in 2..H_HOPS_PER_PROOF {
            assert!(!snark0.hops[i].is_active);
        }

        let multi_hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_multi_hop(&snark0.hops[i]));

        let first_salted_start_block_id = snark0.hops[0].salted_start_block_id;
        let last_salted_end_block_id = snark0.hops[H_HOPS_PER_PROOF - 1].salted_end_block_id;
        let salt_commitment = snark0.salt_commitment;

        // Sanity: continuity holds.
        for i in 0..H_HOPS_PER_PROOF - 1 {
            assert_eq!(snark0.hops[i].salted_end_block_id, snark0.hops[i + 1].salted_start_block_id);
        }

        const K: u32 = 17;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![110],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![8],
            lookup_bits: Some(16),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuit::new(chain.sk_u, multi_hops, params);
        let instances = vec![vec![first_salted_start_block_id, last_salted_end_block_id, salt_commitment]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }

    /// MockProver — all-inactive snark (chain ends before this snark).
    ///
    /// `synth_chain(seed, 0)` ⇒ every hop in every snark is inactive, all
    /// salted endpoints equal `bundle_head_salted`. Exercises the case where
    /// no SHA-256 / ref-tree constraint is enforced at all.
    #[test]
    fn all_inactive_mock_prover() {
        use crate::test_helpers::{split_into_bundle_snarks, synth_chain};

        let chain = synth_chain(0xDEADBEEFu64, 0);
        let snarks = split_into_bundle_snarks(&chain);
        let snark0 = &snarks[0];
        for hop in snark0.hops.iter() {
            assert!(!hop.is_active);
            assert_eq!(hop.salted_start_block_id, hop.salted_end_block_id);
            assert_eq!(hop.salted_start_block_id, chain.bundle_head_salted);
        }

        let multi_hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_multi_hop(&snark0.hops[i]));

        const K: u32 = 17;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![110],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![8],
            lookup_bits: Some(16),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuit::new(chain.sk_u, multi_hops, params);
        let instances = vec![vec![
            chain.bundle_head_salted,
            chain.bundle_head_salted,
            chain.salt_commitment,
        ]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }
}
