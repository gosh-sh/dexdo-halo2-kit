//! MultiHopProof circuit — production bundle-scope proof.
//!
//! Proves `H_HOPS_PER_PROOF = 5` hops (spec §6.4) in one snark with an
//! `is_active` selector for inactive padding hops, so a snark covering
//! fewer real hops can collapse its tail to the bundle's terminal salted
//! endpoint. Exposes the first hop's `salted_start_block_id`, the last
//! hop's `salted_end_block_id`, and the bundle's `salt_commitment` as
//! public instances.
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
//!   `ref_index`, `proof_block_ref_inner_path`: per-hop reference-tree
//!   opening data. `ref_index` is a private
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
//!   `REFERENCED_REF_BLOCK_TAG (34 B) ‖ ref_block_id`) is walked through
//!   `dense_merkle_root_circuit_padded` to produce `computed_l7_fr`. The walk
//!   is always `MAX_PROOF_BLOCK_REFS_DEPTH` levels wide; per-hop
//!   `refs_tree_depth: u8` (spec §5.2 & §12.4) gates each level with
//!   `gate.select`, so the effective fold covers the chain's variable-width
//!   L7 tree (`width = proof_block_refs.len().next_power_of_two()`) without
//!   requiring a fixed-shape protocol change. The internal range checks and
//!   chunk-link constraints inside the walk are unconditional decomposition
//!   constraints. Only the final equality `computed_l7_fr == l7_fr` is gated:
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
//! - **`MAX_PROOF_BLOCK_REFS = 256`** matches the protocol cap (spec §10.1);
//!   real chain widths are typically 1..16, so the gated fold spends most of
//!   its 8 levels on inactive padding. Further tightening is a K-budget
//!   tradeoff, not a soundness question.

use gosh_dense_balanced_tree::{
    bytes_to_fr, fr_to_bytes, preprocess_dense_proof_padded,
    R_F, R_P, RATE, T,
};
use gosh_sha256_chip::Sha256Chip;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::{BaseCircuitParams, BaseConfig};
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::gates::{GateInstructions, RangeChip, RangeInstructions};
use halo2_base::halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::Field as _;
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use halo2_base::poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher};
use halo2_base::{AssignedValue, Context, QuantumCell};
use std::cell::RefCell;

use crate::boc_helper::SHA256_HASH_LEN;
use crate::dense_merkle_bound::dense_merkle_root_padded_bound;
use crate::multi_hop_witness::{
    ref_leaf_hash_native, ref_leaf_ref_tag_chunk0_fr, ref_leaf_ref_tag_chunk1_lo_fr,
    BLOCK_MERKLE_DEPTH, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH, N_BUNDLE,
};
use crate::salt::{compute_salt_native, domain_tag_hop_salt_fr, salted_block_id_poseidon_circuit};

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
    /// Real depth of this hop's L7 dense-merkle tree, matching the chain's
    /// variable-width convention (`proof_block_refs.len().next_power_of_two()
    /// .ilog2()`). Range `[0, MAX_PROOF_BLOCK_REFS_DEPTH]`. Drives the
    /// per-level `gate.select` inside `dense_merkle_root_circuit_padded`
    /// (spec §5.2).
    pub refs_tree_depth: u8,
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
    /// Snark's position within the bundle (`0..N_BUNDLE`). Feeds the
    /// per-hop bundle-global position tag mixed into salted-endpoint Poseidon.
    /// Private witness, range-checked to `[0, N_BUNDLE)` in `synthesize`.
    pub bundle_index: u32,
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl MultiHopProofCircuit {
    pub fn new(
        sk_u: Fr,
        hops: [MultiHopWitness; H_HOPS_PER_PROOF],
        bundle_index: u32,
        base_circuit_params: BaseCircuitParams,
    ) -> Self {
        let base_circuit_builder = RefCell::new(
            BaseCircuitBuilder::<Fr>::new(false).use_params(base_circuit_params.clone()),
        );
        Self {
            sk_u,
            hops,
            bundle_index,
            base_circuit_params,
            base_circuit_builder,
        }
    }

    pub fn new_for_proving(
        sk_u: Fr,
        hops: [MultiHopWitness; H_HOPS_PER_PROOF],
        bundle_index: u32,
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
            bundle_index,
            base_circuit_params,
            base_circuit_builder,
        }
    }
}

// ============================================================================
// Per-hop gadgets
// ----------------------------------------------------------------------------
// The three functions below (`prove_hop_ref_tree_opening`,
// `prove_hop_block_merkle_sha256`, `prove_hop_salted_endpoints`) split the
// per-hop constraint body into named, spec-anchored units. They are pure
// gadgets (no columns of their own) — they take the shared
// `BaseCircuitBuilder` context and layer constraints onto it, exactly as
// the original inline body did. The outer `synthesize` loop is then a
// straightforward composition:
//
//     for hop in &self.hops {
//         let is_active   = load_is_active(ctx, gate, hop);
//         let not_active  = one - is_active;
//         let (l7_bytes, ref_block_id_bytes) =
//             prove_hop_ref_tree_opening(...);
//         let block_id_bytes = load_block_id_bytes(ctx, hop);
//         prove_hop_block_merkle_sha256(..., l7_bytes, &block_id_bytes, ...);
//         let (start_w, end_w) = prove_hop_salted_endpoints(...);
//         hop_endpoints.push((start_w, end_w));
//     }
//
// Constraints are byte-for-byte equivalent to the pre-refactor inline
// body; no gate widths, poseidon domains, or gating polynomials changed.
// ============================================================================

/// Prove one hop's variable-depth L7 ref-tree opening.
///
/// Layers the following constraints onto `ctx`:
/// * `ref_index ∈ (0, 2^MAX_PROOF_BLOCK_REFS_DEPTH)` — unconditional.
///   Slot 0 (same-thread parent, spec §2.3/§5.1) is excluded.
/// * `refs_tree_depth ∈ [0, 16)` — unconditional 4-bit range check (values
///   in `[8, 16)` collapse to "all levels active" via the library's
///   internal `is_less_than`, so no cheating window).
/// * **BC-004 binding**: `ref_index_assigned` is bit-decomposed via
///   `gate.num_to_bits` and those bits drive the direction bits of every
///   level inside the dense-merkle walk. For each bit `j`,
///   `pos_bits[j] · (1 - active_j) == 0` is enforced (where `active_j =
///   j < refs_tree_depth_assigned`), which forces
///   `ref_index_assigned < 2^refs_tree_depth_assigned`. Without this
///   binding the direction bits inside `dense_merkle_root_circuit_padded`
///   were free `assert_bit` witnesses, so `ref_index_assigned`'s range
///   check was dead and a malicious prover could choose any leaf position.
/// * `ref_leaf_fr = Poseidon([c0, c1, c2])` derived from the byte-flat
///   `REFERENCED_REF_BLOCK_TAG (34 B) ‖ ref_block_id` layout
///   (chunks 31+31+4).
/// * `computed_l7_fr = dense_merkle_root_padded_bound(...)` — 8-level walk,
///   gated per-level by `refs_tree_depth` (spec §5.2, §12.4), with direction
///   bits bound to `ref_index_pos_bits`.
/// * `(computed_l7_fr - l7_fr) · is_active == 0` — gated equality.
///
/// Returns the byte-cell views the caller needs downstream:
/// * `l7_bytes` — 32 witness cells (consumed by the block-merkle
///   SHA-256 walk).
/// * `ref_block_id_bytes` — 32 range-checked (8-bit) cells (consumed by
///   the salted-endpoint gadget).
fn prove_hop_ref_tree_opening(
    ctx: &mut Context<Fr>,
    range: &RangeChip<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    hop: &MultiHopWitness,
    is_active: AssignedValue<Fr>,
    ref_leaf_c0_const: AssignedValue<Fr>,
    ref_leaf_c1_tag_const: AssignedValue<Fr>,
    pow_256_3: AssignedValue<Fr>,
    powers_le_32: &[QuantumCell<Fr>],
) -> (Vec<AssignedValue<Fr>>, Vec<AssignedValue<Fr>>) {
    let gate = range.gate();

    // ref_index witness (1..MAX_PROOF_BLOCK_REFS).
    //
    // BC-004 fix: `num_to_bits` doubles as the range check (0..2^N) and
    // returns the little-endian bit decomposition. Those bits are re-used
    // below as the bound direction bits inside the ref-tree walk, so the
    // in-circuit `ref_index_assigned` witness is no longer a dead range check
    // — it is load-bearing at every level of the dense-merkle walk.
    let ref_index_assigned = ctx.load_witness(Fr::from(hop.ref_index as u64));
    let ref_index_pos_bits =
        gate.num_to_bits(ctx, ref_index_assigned, MAX_PROOF_BLOCK_REFS_DEPTH);
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

    // Byte-flat ref-leaf chunks — ref-tag layout only (34 B tag): 31+31+4.
    //   c0 = tag_r_hi (31 B)               ← ref_leaf_c0_const
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

    // Byte-flat ref-tree walk — gated variable-depth fold.
    //
    // The chain's L7 tree width is `proof_block_refs.len().next_power_of_two()`
    // (spec §2.3, §5.2). We pass only the first `refs_tree_depth` real
    // siblings to the preprocessor; `preprocess_dense_proof_padded` synthesizes
    // identity-pair dummies for the remaining `MAX_PROOF_BLOCK_REFS_DEPTH -
    // refs_tree_depth` levels. In-circuit `dense_merkle_root_circuit_padded`
    // masks inactive levels via `gate.select` keyed on
    // `num_active_levels = refs_tree_depth`, so the returned `computed_l7_fr`
    // equals the chain's variable-width root.
    //
    // Internal range checks + chunk-link constraints inside the walk stay
    // unconditional decomposition constraints (they hold on both real and
    // dummy levels). Only the final equality against `l7_fr` is gated by
    // `is_active`.
    let depth = hop.refs_tree_depth as usize;
    debug_assert!(
        depth <= MAX_PROOF_BLOCK_REFS_DEPTH,
        "refs_tree_depth {} > MAX_PROOF_BLOCK_REFS_DEPTH {}",
        depth,
        MAX_PROOF_BLOCK_REFS_DEPTH,
    );
    let ref_leaf_native_bytes = ref_leaf_hash_native(hop.ref_index, &hop.ref_block_id);
    let ref_proof = preprocess_dense_proof_padded(
        ref_leaf_native_bytes,
        &hop.proof_block_ref_inner_path[..depth],
        hop.ref_index,
        MAX_PROOF_BLOCK_REFS_DEPTH,
    );
    let refs_tree_depth_assigned = ctx.load_witness(Fr::from(hop.refs_tree_depth as u64));
    range.range_check(ctx, refs_tree_depth_assigned, 4);
    // BC-004 fix: force `ref_index < 2^refs_tree_depth`. For each bit j,
    // `pos_bits[j] * (1 - active_j) == 0` where `active_j = j < refs_tree_depth`.
    // Combined with the num_to_bits binding, this forces high bits of
    // `ref_index_assigned` to be zero on all inactive (padded) levels — which
    // in turn matches `preprocess_dense_proof_padded`'s convention of
    // `direction_bit = false` on padded levels, so the chunk-decomposition
    // constraints inside the walk still hold uniformly.
    for (j, bit) in ref_index_pos_bits.iter().enumerate() {
        let j_const = ctx.load_constant(Fr::from(j as u64));
        let active_j = range.is_less_than(ctx, j_const, refs_tree_depth_assigned, 4);
        let inactive_j = {
            let one = ctx.load_constant(Fr::one());
            gate.sub(
                ctx,
                QuantumCell::Existing(one),
                QuantumCell::Existing(active_j),
            )
        };
        let prod = gate.mul(
            ctx,
            QuantumCell::Existing(*bit),
            QuantumCell::Existing(inactive_j),
        );
        gate.assert_is_const(ctx, &prod, &Fr::zero());
    }
    let computed_l7_fr = dense_merkle_root_padded_bound(
        ctx,
        range,
        hasher,
        &ref_proof,
        ref_leaf_fr,
        refs_tree_depth_assigned,
        &ref_index_pos_bits,
    );
    // Gated ref-tree root equality: (computed_l7_fr - l7_fr) * is_active == 0.
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

    (l7_bytes, ref_block_id_bytes)
}

/// Prove one hop's L7 → block_id SHA-256 walk (spec §5.3).
///
/// Runs `BLOCK_MERKLE_DEPTH` levels of SHA-256 starting at leaf index 7.
/// For leaf 7 in a 16-leaf depth-4 tree the successive node indices are
/// 7, 3, 1, 0 — so the sibling sits on the LEFT for the first
/// `BLOCK_MERKLE_DEPTH - 1` levels and on the RIGHT for the top level.
/// Since the leaf index is fixed, orientation is compile-time constant
/// per level.
///
/// Enforces `(cur_bytes[i] - block_id_bytes[i]) · is_active == 0` for
/// all 32 output bytes. Sibling bytes are unconstrained witnesses in the
/// tail levels; SHA-256's internal range checks + the final gated equality
/// against the caller-provided `block_id_bytes` (transitively 8-bit via the
/// SHA-256 output chain) close the constraint.
fn prove_hop_block_merkle_sha256(
    ctx: &mut Context<Fr>,
    sha256_chip: &Sha256Chip<Fr>,
    gate: &impl GateInstructions<Fr>,
    l7_bytes: Vec<AssignedValue<Fr>>,
    block_id_bytes: &[AssignedValue<Fr>],
    block_merkle_leaf_proof_l7: &[[u8; 32]; BLOCK_MERKLE_DEPTH],
    is_active: AssignedValue<Fr>,
) {
    let mut cur_bytes = l7_bytes;
    for (level, sib_bytes) in block_merkle_leaf_proof_l7.iter().enumerate() {
        let sib_cells: Vec<AssignedValue<Fr>> = sib_bytes
            .iter()
            .map(|&b| ctx.load_witness(Fr::from(b as u64)))
            .collect();
        let mut concat: Vec<AssignedValue<Fr>> = Vec::with_capacity(64);
        // node_index at this level for leaf 7: 7 >> level.
        // Even → cur on left (cur ‖ sib); odd → cur on right (sib ‖ cur).
        let cur_on_right = ((7usize >> level) & 1) == 1;
        if cur_on_right {
            concat.extend_from_slice(&sib_cells);
            concat.extend_from_slice(&cur_bytes);
        } else {
            concat.extend_from_slice(&cur_bytes);
            concat.extend_from_slice(&sib_cells);
        }
        let next = sha256_chip.digest_bytes(ctx, &concat);
        assert_eq!(next.len(), SHA256_HASH_LEN);
        cur_bytes = next;
    }
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
}

/// Prove one hop's salted-endpoint bindings (BC-005 anonymity fix, position-tagged).
///
/// Constraints:
/// * `salted_start_w == Poseidon(salt, ref_block_id, start_position)`
///   — **unconditional** (both active and inactive hops).
/// * `salted_end_w   == Poseidon(salt, block_id,     end_position)`
///   — **unconditional**.
/// * `(ref_block_id_bytes[i] - block_id_bytes[i]) · not_active == 0` for all 32 bytes
///   — inactive hops must have `ref_block_id == block_id`, forcing padding
///   hops to carry a single block_id value.
///
/// This design replaces the pre-fix "inactive hop propagates
/// `salted_start == salted_end`" rule, which broke once each endpoint
/// absorbs a distinct bundle-global `position` (different positions ⇒
/// different Poseidon outputs even for the same block_id).
///
/// Why it stays sound:
/// * Active hops: block_id is bound by the SHA-256 block-merkle walk;
///   ref_block_id is bound by the L7 dense-merkle opening.
/// * Inactive hops: byte-equality collapses to a single "padding block_id"
///   value per hop. The intra-snark continuity equality
///   (`salted_end[i] == salted_start[i+1]`) combined with Poseidon
///   collision resistance and the byte-equality rule chains the padding
///   block_id across all inactive hops. The DexFinal head-link
///   (`salted_start[0] == Poseidon(salt, x_block_id, 0)`) and tail-link
///   (`salted_end[last] == Poseidon(salt, y_block_id, N·H)`) then force
///   the padding block_id to equal the last active hop's block_id (or
///   `x_block_id == y_block_id` in the same-thread case).
///
/// `start_computed` / `end_computed` are derived via
/// [`salted_block_id_poseidon_circuit`], using the caller's prior
/// `salt_chunk0 + salt_hi · 2^248` decomposition of `salt`, and mixing
/// the bundle-global `start_position` / `end_position` as the 4th
/// Poseidon input.
///
/// Returns the assigned `(salted_start_w, salted_end_w)` witnesses so the
/// caller can wire them into intra-snark continuity across hops.
fn prove_hop_salted_endpoints(
    ctx: &mut Context<Fr>,
    gate: &impl GateInstructions<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    powers_le_32: &[QuantumCell<Fr>],
    salt_chunk0: AssignedValue<Fr>,
    salt_hi: AssignedValue<Fr>,
    ref_block_id_bytes: &[AssignedValue<Fr>],
    block_id_bytes: &[AssignedValue<Fr>],
    start_position: AssignedValue<Fr>,
    end_position: AssignedValue<Fr>,
    not_active: AssignedValue<Fr>,
) -> (AssignedValue<Fr>, AssignedValue<Fr>) {
    let salted_start_block_id_w = salted_block_id_poseidon_circuit(
        ctx,
        gate,
        hasher,
        powers_le_32,
        salt_chunk0,
        salt_hi,
        ref_block_id_bytes,
        start_position,
    );
    let salted_end_block_id_w = salted_block_id_poseidon_circuit(
        ctx,
        gate,
        hasher,
        powers_le_32,
        salt_chunk0,
        salt_hi,
        block_id_bytes,
        end_position,
    );

    // Inactive-hop rule: force ref_block_id == block_id (byte-wise).
    // Combined with intra-snark continuity + Poseidon collision resistance,
    // this collapses all inactive hops to carry the terminal block_id.
    for (r, b) in ref_block_id_bytes.iter().zip(block_id_bytes.iter()) {
        let diff = gate.sub(
            ctx,
            QuantumCell::Existing(*r),
            QuantumCell::Existing(*b),
        );
        let gated = gate.mul(
            ctx,
            QuantumCell::Existing(diff),
            QuantumCell::Existing(not_active),
        );
        gate.assert_is_const(ctx, &gated, &Fr::zero());
    }

    (salted_start_block_id_w, salted_end_block_id_w)
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
            // Matches synth_chain inactive-padding convention: depth=1 covers
            // ref_index=1 without triggering an out-of-range live-flag; the
            // gated fold's output is discarded by `is_active` anyway.
            refs_tree_depth: 1,
            proof_block_ref_inner_path: [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH],
            salted_start_block_id: Fr::zero(),
            salted_end_block_id: Fr::zero(),
        };
        let hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|_| dummy_hop());
        Self::new(Fr::zero(), hops, 0, self.base_circuit_params.clone())
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

                // bundle_index: private witness, range-checked to
                // [0, N_BUNDLE). Position tag base = bundle_index * H.
                let bundle_index_assigned =
                    ctx.load_witness(Fr::from(self.bundle_index as u64));
                let bundle_index_bits = (N_BUNDLE as u64).next_power_of_two().trailing_zeros();
                assert!(
                    bundle_index_bits > 0 && bundle_index_bits < 32,
                    "N_BUNDLE must fit in a small range check"
                );
                range.range_check(ctx, bundle_index_assigned, bundle_index_bits as usize);
                let position_base = gate.mul(
                    ctx,
                    QuantumCell::Existing(bundle_index_assigned),
                    QuantumCell::Constant(Fr::from(H_HOPS_PER_PROOF as u64)),
                );

                let mut hop_endpoints: Vec<(AssignedValue<Fr>, AssignedValue<Fr>)> =
                    Vec::with_capacity(H_HOPS_PER_PROOF);

                for (h_idx, hop) in self.hops.iter().enumerate() {
                    // is_active + not_active flags for the whole hop.
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

                    // Bundle-global position tags for this hop.
                    //   start_pos = bundle_index * H + h_idx
                    //   end_pos   = bundle_index * H + h_idx + 1
                    let start_position = gate.add(
                        ctx,
                        QuantumCell::Existing(position_base),
                        QuantumCell::Constant(Fr::from(h_idx as u64)),
                    );
                    let end_position = gate.add(
                        ctx,
                        QuantumCell::Existing(position_base),
                        QuantumCell::Constant(Fr::from((h_idx + 1) as u64)),
                    );

                    // Gadget 1: L7 ref-tree opening (byte-flat Poseidon +
                    // variable-depth dense fold, spec §5.2).
                    let (l7_bytes, ref_block_id_bytes) = prove_hop_ref_tree_opening(
                        ctx,
                        &range,
                        &hasher,
                        hop,
                        is_active,
                        ref_leaf_c0_const,
                        ref_leaf_c1_tag_const,
                        pow_256_3,
                        &powers_le_32,
                    );

                    // block_id byte witnesses (used by gadgets 2 and 3).
                    let block_id_bytes: Vec<AssignedValue<Fr>> = hop
                        .block_id
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();

                    // Gadget 2: L7 → block_id SHA-256 walk (spec §5.3).
                    prove_hop_block_merkle_sha256(
                        ctx,
                        &sha256_chip,
                        gate,
                        l7_bytes,
                        &block_id_bytes,
                        &hop.block_merkle_leaf_proof_l7,
                        is_active,
                    );

                    // Gadget 3: salted endpoints (spec §5.4) — position-tagged
                    // Poseidon bound unconditionally + inactive byte-equality
                    // padding rule (BC-005 fix).
                    let (salted_start_block_id_w, salted_end_block_id_w) =
                        prove_hop_salted_endpoints(
                            ctx,
                            gate,
                            &hasher,
                            &powers_le_32,
                            salt_chunk0,
                            salt_hi,
                            &ref_block_id_bytes,
                            &block_id_bytes,
                            start_position,
                            end_position,
                            not_active,
                        );

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
            refs_tree_depth: h.refs_tree_depth,
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
            num_advice_per_phase: vec![200],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![14],
            lookup_bits: Some(16),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuit::new(chain.sk_u, multi_hops, 0, params);
        let instances = vec![vec![first_salted_start_block_id, last_salted_end_block_id, salt_commitment]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }

    /// MockProver — all-inactive snark (chain ends before this snark).
    ///
    /// `synth_chain(seed, 0)` ⇒ every hop in every snark is inactive. Under
    /// BC-005 position tags, salted endpoints step through Poseidon at
    /// consecutive positions (they are NOT equal to bundle_head_salted).
    /// Exercises the case where no SHA-256 / ref-tree constraint is
    /// enforced at all — only the `not_active` byte-equality rule.
    #[test]
    fn all_inactive_mock_prover() {
        use crate::test_helpers::{split_into_bundle_snarks, synth_chain};

        let chain = synth_chain(0xDEADBEEFu64, 0);
        let snarks = split_into_bundle_snarks(&chain);
        let snark0 = &snarks[0];
        for hop in snark0.hops.iter() {
            assert!(!hop.is_active);
        }
        assert_eq!(snark0.hops[0].salted_start_block_id, chain.bundle_head_salted);

        let multi_hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
            std::array::from_fn(|i| hop_to_multi_hop(&snark0.hops[i]));

        const K: u32 = 17;
        let params = BaseCircuitParams {
            k: K as usize,
            num_advice_per_phase: vec![200],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![14],
            lookup_bits: Some(16),
            num_instance_columns: 1,
        };

        let circuit = MultiHopProofCircuit::new(chain.sk_u, multi_hops, 0, params);
        let instances = vec![vec![
            snark0.hops[0].salted_start_block_id,
            snark0.hops[H_HOPS_PER_PROOF - 1].salted_end_block_id,
            chain.salt_commitment,
        ]];
        let prover = MockProver::<Fr>::run(K, &circuit, instances).unwrap();
        prover.assert_satisfied();
    }
}
