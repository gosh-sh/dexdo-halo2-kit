//! Bound-direction-bit variant of `gosh_dense_balanced_tree::dense_merkle_root_circuit_padded`.
//!
//! # Why this module exists
//!
//! The upstream `dense_merkle_root_circuit_padded` walker loads a fresh
//! `assert_bit`-only witness per level for its left/right direction bit
//! (`level.direction_bit`). That is soundness-neutral **only** when the
//! caller's position isn't publicly committed — the prover has full
//! freedom to pick any orientation that satisfies the root equation.
//!
//! Any circuit that either
//!   * exposes its position as a public input (dark_dex_circuit.rs's L8
//!     `x_ext_out_merkle_proof_position` — BC-011), or
//!   * range-checks a position witness expecting it to constrain the walk
//!     (multi_hop_proof.rs's L7 `ref_index` — BC-004),
//!
//! needs the walker's direction bits **bound** to a specific external
//! position witness. Otherwise the range/public commitment on the position
//! is dead: the walker uses whatever direction bits it likes.
//!
//! [`dense_merkle_root_padded_bound`] is byte-for-byte identical to the
//! upstream walker except the direction bit at level `j` is
//! `pos_bits[j]` (caller-supplied) instead of a fresh witness. The caller
//! is expected to derive `pos_bits` from the position witness via
//! `gate.num_to_bits` (which combines range check + bit decomposition),
//! and to enforce `pos_bits[j] == 0` for `j >= num_active_levels` so the
//! bit convention matches `preprocess_dense_proof_padded`'s
//! `direction_bit = false` on padded levels.

use gosh_dense_balanced_tree::{bytes_to_fr, cond_swap, DenseTreeProof, RATE, T};
use halo2_base::gates::{GateInstructions, RangeInstructions};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::{AssignedValue, Context};

/// In-circuit dense-merkle walk with direction bits bound to an external
/// position witness.
///
/// Mirrors upstream `gosh_dense_balanced_tree::dense_merkle_root_circuit_padded`
/// verbatim except for one change: at each level `j`, the direction bit is
/// **`pos_bits[j]`** — the caller-supplied bit-decomposition of the position
/// witness — instead of a fresh unconstrained witness loaded from
/// `level.direction_bit` and merely `assert_bit`-checked. Semantics are
/// identical when the caller passes bits that match the preprocessed
/// `direction_bit`s.
///
/// Preconditions the caller MUST enforce:
/// * `pos_bits.len() == proof.levels.len()`.
/// * Each `pos_bits[j] ∈ {0, 1}` (satisfied automatically when produced by
///   `gate.num_to_bits`).
/// * `sum(pos_bits[j] · 2^j) == pos_witness` for whichever `pos_witness` the
///   caller is binding (satisfied by `gate.num_to_bits`).
/// * For every `j ≥ num_active_levels`, `pos_bits[j] == 0`. This aligns the
///   bound direction bit with the preprocessor's `direction_bit = false`
///   convention on padded levels, so the chunk-decomposition constraints
///   inside the walk hold uniformly across active/inactive levels.
pub fn dense_merkle_root_padded_bound(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    proof: &DenseTreeProof,
    leaf_fr: AssignedValue<Fr>,
    num_active_levels: AssignedValue<Fr>,
    pos_bits: &[AssignedValue<Fr>],
) -> AssignedValue<Fr> {
    assert_eq!(
        pos_bits.len(),
        proof.levels.len(),
        "pos_bits length must match proof.levels",
    );
    let gate = range.gate();

    let pow_248 = ctx.load_constant(Fr::from_raw([0u64, 0u64, 0u64, 1u64 << 56]));
    let pow_240 = ctx.load_constant(Fr::from_raw([0u64, 0u64, 0u64, 1u64 << 48]));
    let two56 = ctx.load_constant(Fr::from(256u64));

    let mut cur = leaf_fr;

    for (j, level) in proof.levels.iter().enumerate() {
        // active = (j < num_active_levels)
        let j_const = ctx.load_constant(Fr::from(j as u64));
        let active = range.is_less_than(ctx, j_const, num_active_levels, 4);

        let sibling_fr = ctx.load_witness(bytes_to_fr(&level.sibling));

        // Direction bit is the bound `pos_bits[j]`, NOT a free witness.
        // The caller enforces `pos_bits[j] == 0` for `j >= num_active_levels`,
        // so on padded levels this matches the preprocessor's
        // `direction_bit = false` convention.
        let bit = pos_bits[j];

        let (left, right) = cond_swap(ctx, gate, cur, sibling_fr, bit);

        let c0 = ctx.load_witness(level.chunk0);
        let c1 = ctx.load_witness(level.chunk1);
        let c2 = ctx.load_witness(level.chunk2);
        let left_hi = ctx.load_witness(Fr::from(level.left_hi as u64));

        let lhs = gate.mul_add(ctx, left_hi, pow_248, c0);
        ctx.constrain_equal(&lhs, &left);

        let c2_shifted = gate.mul(ctx, c2, pow_240);
        let right_low = gate.sub(ctx, right, c2_shifted);

        let rhs = gate.mul_add(ctx, right_low, two56, left_hi);
        ctx.constrain_equal(&rhs, &c1);

        range.range_check(ctx, c0, 248);
        range.range_check(ctx, right_low, 240);
        range.range_check(ctx, left_hi, 8);
        range.range_check(ctx, c2, 16);

        let computed = hasher.hash_fix_len_array(ctx, gate, &[c0, c1, c2]);

        cur = gate.select(ctx, computed, cur, active);
    }

    cur
}
