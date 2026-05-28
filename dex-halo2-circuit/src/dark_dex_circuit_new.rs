use gosh_sha256_chip::Sha256Chip;
use halo2_base::halo2_proofs::halo2curves::ff::Field as _;
use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem, Error},
    },
};

use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        flex_gate::MultiPhaseThreadBreakPoints,
        GateInstructions, RangeInstructions,
    },
    poseidon::hasher::{
        spec::OptimizedPoseidonSpec,
        PoseidonHasher,
    },
    AssignedValue, QuantumCell,
};

use std::cell::RefCell;

use crate::boc_helper::*;
use crate::poseidon::*;
use gosh_dense_balanced_tree::{
    bytes_to_fr, compute_root_native, dense_merkle_root_circuit,
    dense_merkle_root_circuit_padded, fr_to_bytes, poseidon_hash_native,
    preprocess_dense_proof, preprocess_dense_proof_padded,
    verify_chain_of_dense_proofs, DenseChainLink, MAX_CHAIN_LEN,
};
use halo2_base::Context;

pub const MAX_EVENTS_TREE_DEPTH: usize = 8;

const SHA256_HASH_LEN: usize = 32;
const EVENT_BOC_DATA_BYTES_OFFSET: usize = 6;
const EVENT_SK_U_COMMIT_FIELD_LEN: usize = 32;
const EVENT_VOUCHER_NOMINAL_FIELD_LEN: usize = 32;
const EVENT_TOKEN_TYPE_FIELD_LEN: usize = 4;

const EVENT_SK_U_COMMIT_START: usize = EVENT_BOC_DATA_BYTES_OFFSET;
const EVENT_SK_U_COMMIT_END: usize = EVENT_SK_U_COMMIT_START + EVENT_SK_U_COMMIT_FIELD_LEN;
const EVENT_VOUCHER_NOMINAL_START: usize = EVENT_SK_U_COMMIT_END;
const EVENT_VOUCHER_NOMINAL_END: usize =
    EVENT_VOUCHER_NOMINAL_START + EVENT_VOUCHER_NOMINAL_FIELD_LEN;
const EVENT_TOKEN_TYPE_START: usize = EVENT_VOUCHER_NOMINAL_END;
const EVENT_TOKEN_TYPE_END: usize = EVENT_TOKEN_TYPE_START + EVENT_TOKEN_TYPE_FIELD_LEN;

// ---------------------------------------------------------------------------
// Poseidon-hash-of-96-bytes helpers (3 × 32-byte inputs → 4 Fr chunks)
// ---------------------------------------------------------------------------

/// Split 96 bytes at 31-byte boundaries into 4 LE Fr elements.
///
/// Chunk layout (matching `hash_bytes_flat` convention):
///   c0 = Fr(buf[0..31])   — 248 bits
///   c1 = Fr(buf[31..62])  — 248 bits
///   c2 = Fr(buf[62..93])  — 248 bits
///   c3 = Fr(buf[93..96])  — 24 bits
fn chunk_96_bytes_to_fr(buf: &[u8; 96]) -> (Fr, Fr, Fr, Fr) {
    let mut b0 = [0u8; 32];
    b0[..31].copy_from_slice(&buf[0..31]);
    let c0 = bytes_to_fr(&b0);

    let mut b1 = [0u8; 32];
    b1[..31].copy_from_slice(&buf[31..62]);
    let c1 = bytes_to_fr(&b1);

    let mut b2 = [0u8; 32];
    b2[..31].copy_from_slice(&buf[62..93]);
    let c2 = bytes_to_fr(&b2);

    let mut b3 = [0u8; 32];
    b3[..3].copy_from_slice(&buf[93..96]);
    let c3 = bytes_to_fr(&b3);

    (c0, c1, c2, c3)
}

/// Native (off-circuit): Poseidon hash of 3 × 32-byte inputs chunked at 31-byte boundaries.
///
/// Returns `fr_to_bytes(Poseidon(c0, c1, c2, c3))`.
pub(crate) fn poseidon_hash_96_native(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(a);
    buf[32..64].copy_from_slice(b);
    buf[64..96].copy_from_slice(c);
    let (c0, c1, c2, c3) = chunk_96_bytes_to_fr(&buf);
    let hash = poseidon_hash_native(&[c0, c1, c2, c3]);
    fr_to_bytes(hash)
}

/// In-circuit: Poseidon hash of 3 × 32-byte inputs with algebraic linking.
///
/// Given assigned Fr values `a_fr, b_fr, c_fr` (LE packing of 32-byte inputs)
/// and the corresponding native bytes, loads 6 intermediate witnesses,
/// constrains the 31-byte chunking decomposition, and returns the Poseidon hash.
///
/// ## Algebraic linking (a = buf[0..32], b = buf[32..64], c = buf[64..96]):
///   c0 + hi_a · 2^248 = a_fr       (hi_a = a[31], 1 byte)
///   c1 = hi_a + 256 · low_b        (low_b = b[0..30], 30 bytes)
///   low_b + hi_b · 2^240 = b_fr    (hi_b = b[30..32], 2 bytes)
///   c2 = hi_b + 2^16 · low_c       (low_c = c[0..29], 29 bytes)
///   low_c + c3 · 2^232 = c_fr      (c3 = c[29..32], 3 bytes)
fn poseidon_hash_96_circuit(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    a_fr: AssignedValue<Fr>,
    b_fr: AssignedValue<Fr>,
    c_fr: AssignedValue<Fr>,
    a_bytes: &[u8; 32],
    b_bytes: &[u8; 32],
    c_bytes: &[u8; 32],
) -> AssignedValue<Fr> {
    let gate = range.gate();

    // --- Off-circuit: compute chunks and intermediates ---
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(a_bytes);
    buf[32..64].copy_from_slice(b_bytes);
    buf[64..96].copy_from_slice(c_bytes);
    let (c0_val, _c1_val, _c2_val, c3_val) = chunk_96_bytes_to_fr(&buf);

    let hi_a_val = Fr::from(a_bytes[31] as u64);

    let mut low_b_buf = [0u8; 32];
    low_b_buf[..30].copy_from_slice(&b_bytes[..30]);
    let low_b_val = bytes_to_fr(&low_b_buf);

    let hi_b_val = Fr::from(b_bytes[30] as u64 + (b_bytes[31] as u64) * 256);

    let mut low_c_buf = [0u8; 32];
    low_c_buf[..29].copy_from_slice(&c_bytes[..29]);
    let low_c_val = bytes_to_fr(&low_c_buf);

    // --- Load 6 witnesses ---
    let c0 = ctx.load_witness(c0_val);
    let hi_a = ctx.load_witness(hi_a_val);
    let low_b = ctx.load_witness(low_b_val);
    let hi_b = ctx.load_witness(hi_b_val);
    let low_c = ctx.load_witness(low_c_val);
    let c3 = ctx.load_witness(c3_val);

    // --- 5 linking constraints ---
    // 1. c0 + hi_a * 2^248 = a_fr
    let pow_248 = QuantumCell::Constant(Fr::from(2u64).pow([248]));
    let sum_a = gate.mul_add(ctx, hi_a, pow_248, c0);
    ctx.constrain_equal(&sum_a, &a_fr);

    // 2. c1 = hi_a + 256 * low_b  (derived, not a witness)
    let c256 = QuantumCell::Constant(Fr::from(256u64));
    let c1 = gate.mul_add(ctx, low_b, c256, hi_a);

    // 3. low_b + hi_b * 2^240 = b_fr
    let pow_240 = QuantumCell::Constant(Fr::from(2u64).pow([240]));
    let sum_b = gate.mul_add(ctx, hi_b, pow_240, low_b);
    ctx.constrain_equal(&sum_b, &b_fr);

    // 4. c2 = hi_b + 2^16 * low_c  (derived, not a witness)
    let pow_16 = QuantumCell::Constant(Fr::from(1u64 << 16));
    let c2 = gate.mul_add(ctx, low_c, pow_16, hi_b);

    // 5. low_c + c3 * 2^232 = c_fr
    let pow_232 = QuantumCell::Constant(Fr::from(2u64).pow([232]));
    let sum_c = gate.mul_add(ctx, c3, pow_232, low_c);
    ctx.constrain_equal(&sum_c, &c_fr);

    // --- 6 range checks ---
    range.range_check(ctx, c0, 248);    // 31 bytes
    range.range_check(ctx, hi_a, 8);    // 1 byte
    range.range_check(ctx, low_b, 240); // 30 bytes
    range.range_check(ctx, hi_b, 16);   // 2 bytes
    range.range_check(ctx, low_c, 232); // 29 bytes
    range.range_check(ctx, c3, 24);     // 3 bytes

    // --- Poseidon hash ---
    hasher.hash_fix_len_array(ctx, gate, &[c0, c1, c2, c3])
}

/// Extract `voucher_nominal` and `token_type` from the child cell of an event BOC,
/// using big-endian byte-to-Fr conversion (matching the in-circuit extraction).
pub fn extract_event_public_fields(entries: &[BocFlattenData; 2]) -> (Fr, Fr) {
    let child_data = &entries[1].cell_repr_data;
    let voucher_bytes = &child_data[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END];
    let token_bytes = &child_data[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END];

    let mut voucher_nominal = Fr::from(0u64);
    for &b in voucher_bytes {
        voucher_nominal = voucher_nominal * Fr::from(256u64) + Fr::from(b as u64);
    }

    let mut token_type = Fr::from(0u64);
    for &b in token_bytes {
        token_type = token_type * Fr::from(256u64) + Fr::from(b as u64);
    }

    (voucher_nominal, token_type)
}

#[derive(Clone, Debug)]
pub struct DarkDexCircuitNewConfig {
    base_circuit_config: BaseConfig<Fr>,
}

pub struct DarkDexCircuitNew {
    pub sk_u: Fr,
    /// Public witness exposed as instance 4: ephemeral_pubkey the prover
    /// commits to as the future PN owner. Binding this in-circuit closes
    /// the deploy-time frontrun on RootPN.deployPrivateNote — an attacker
    /// who steals a pending proof cannot substitute their own pubkey
    /// without re-running the prover.
    pub ephemeral_pubkey: Fr,
    /// Private witness: serialized cells tree entries (root + one child).
    pub entries: [BocFlattenData; 2],
    /// Private witness: events-tree Merkle proof siblings (bottom-up).
    pub merkle_proof_siblings: Vec<[u8; 32]>,
    /// Private witness: leaf position in the events tree.
    pub merkle_proof_position: usize,
    /// Private witness: dApp ID (32 bytes) for ext_message_leaf computation.
    pub account_dapp_id: [u8; 32],
    /// Private witness: account ID (32 bytes) for ext_message_leaf computation.
    pub account_id: [u8; 32],
    /// Private witness: block ID (32 bytes) for block_leaf computation.
    pub block_id: [u8; 32],
    /// Private witness: envelope hash (32 bytes) for block_leaf computation.
    pub envelope_hash_bytes: [u8; 32],
    /// Private witness: block-tree Merkle proof siblings (bottom-up).
    pub block_merkle_proof_siblings: Vec<[u8; 32]>,
    /// Private witness: leaf position in the block (history window) tree.
    pub block_merkle_proof_position: usize,
    /// Private witness: chain of dense balanced tree proofs (length = MAX_CHAIN_LEN).
    pub dense_chain: Vec<DenseChainLink>,
    /// Number of active chain steps (0..=MAX_CHAIN_LEN).
    pub num_active_chain_steps: usize,
    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl DarkDexCircuitNew {
    pub fn new(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        merkle_proof_siblings: Vec<[u8; 32]>,
        merkle_proof_position: usize,
        account_dapp_id: [u8; 32],
        account_id: [u8; 32],
        block_id: [u8; 32],
        envelope_hash_bytes: [u8; 32],
        block_merkle_proof_siblings: Vec<[u8; 32]>,
        block_merkle_proof_position: usize,
        dense_chain: Vec<DenseChainLink>,
        num_active_chain_steps: usize,
        base_circuit_params: BaseCircuitParams,
    ) -> Self {
        assert!(
            merkle_proof_siblings.len() <= MAX_EVENTS_TREE_DEPTH,
            "events tree depth {} exceeds MAX_EVENTS_TREE_DEPTH {}",
            merkle_proof_siblings.len(),
            MAX_EVENTS_TREE_DEPTH,
        );
        assert_eq!(dense_chain.len(), MAX_CHAIN_LEN);
        assert!(num_active_chain_steps <= MAX_CHAIN_LEN);
        let base_circuit_builder = RefCell::new(
            BaseCircuitBuilder::<Fr>::new(false).use_params(base_circuit_params.clone()),
        );
        Self {
            sk_u,
            ephemeral_pubkey,
            entries,
            merkle_proof_siblings,
            merkle_proof_position,
            account_dapp_id,
            account_id,
            block_id,
            envelope_hash_bytes,
            block_merkle_proof_siblings,
            block_merkle_proof_position,
            dense_chain,
            num_active_chain_steps,
            base_circuit_params,
            base_circuit_builder,
        }
    }

    pub fn new_for_proving(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        merkle_proof_siblings: Vec<[u8; 32]>,
        merkle_proof_position: usize,
        account_dapp_id: [u8; 32],
        account_id: [u8; 32],
        block_id: [u8; 32],
        envelope_hash_bytes: [u8; 32],
        block_merkle_proof_siblings: Vec<[u8; 32]>,
        block_merkle_proof_position: usize,
        dense_chain: Vec<DenseChainLink>,
        num_active_chain_steps: usize,
        base_circuit_params: BaseCircuitParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        assert!(
            merkle_proof_siblings.len() <= MAX_EVENTS_TREE_DEPTH,
            "events tree depth {} exceeds MAX_EVENTS_TREE_DEPTH {}",
            merkle_proof_siblings.len(),
            MAX_EVENTS_TREE_DEPTH,
        );
        assert_eq!(dense_chain.len(), MAX_CHAIN_LEN);
        assert!(num_active_chain_steps <= MAX_CHAIN_LEN);
        let base_circuit_builder = RefCell::new(BaseCircuitBuilder::<Fr>::prover(
            base_circuit_params.clone(),
            break_points,
        ));
        Self {
            sk_u,
            ephemeral_pubkey,
            entries,
            merkle_proof_siblings,
            merkle_proof_position,
            account_dapp_id,
            account_id,
            block_id,
            envelope_hash_bytes,
            block_merkle_proof_siblings,
            block_merkle_proof_position,
            dense_chain,
            num_active_chain_steps,
            base_circuit_params,
            base_circuit_builder,
        }
    }
}

impl Circuit<Fr> for DarkDexCircuitNew {
    type Config = DarkDexCircuitNewConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn params(&self) -> Self::Params {
        self.base_circuit_params.clone()
    }

    fn without_witnesses(&self) -> Self {
        // Preserve cell_repr_data lengths so that SHA-256 produces the same
        // number of blocks and byte indexing works.
        let dummy_entries = [
            BocFlattenData {
                repr_hash: [0u8; 32],
                refs_count: self.entries[0].refs_count,
                childs_repr_hashes_offset: self.entries[0].childs_repr_hashes_offset.clone(),
                cell_repr_data: vec![0u8; self.entries[0].cell_repr_data.len()],
            },
            BocFlattenData {
                repr_hash: [0u8; 32],
                refs_count: self.entries[1].refs_count,
                childs_repr_hashes_offset: self.entries[1].childs_repr_hashes_offset.clone(),
                cell_repr_data: vec![0u8; self.entries[1].cell_repr_data.len()],
            },
        ];
        let dummy_chain = self.dense_chain.iter().map(|link| {
            DenseChainLink::inactive([0u8; 32], link.siblings.len())
        }).collect();
        Self::new(
            Fr::zero(),
            Fr::zero(),  // ephemeral_pubkey witness (0 for keygen/dummy)
            dummy_entries,
            vec![[0u8; 32]; MAX_EVENTS_TREE_DEPTH],
            0,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            self.block_merkle_proof_siblings.iter().map(|_| [0u8; 32]).collect(),
            0,
            dummy_chain,
            0,
            self.base_circuit_params.clone(),
        )
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::configure_with_params(meta, Default::default())
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        let base_circuit_config = BaseCircuitBuilder::<Fr>::configure_with_params(meta, params);
        DarkDexCircuitNewConfig { base_circuit_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Reset the base circuit builder so that repeated synthesize calls
        // (keygen_vk + keygen_pk) don't accumulate gates.
        {
            let old = self.base_circuit_builder.borrow();
            let mut fresh = if old.witness_gen_only() {
                BaseCircuitBuilder::<Fr>::prover(
                    self.base_circuit_params.clone(),
                    old.break_points(),
                )
            } else {
                BaseCircuitBuilder::<Fr>::new(false).use_params(self.base_circuit_params.clone())
            };
            while fresh.assigned_instances.len() < self.base_circuit_params.num_instance_columns {
                fresh.assigned_instances.push(vec![]);
            }
            drop(old);
            *self.base_circuit_builder.borrow_mut() = fresh;
        }

        // ---------------------------------------------------------------
        // Everything runs inside the base circuit — no separate SHA-256
        // region, no cross-region bridging.
        // ---------------------------------------------------------------
        {
            let mut builder = self.base_circuit_builder.borrow_mut();
            let range = builder.range_chip();

            let (final_hasher_result, final_root, voucher_nominal, token_type) = {
                let gate = range.gate();
                let ctx = builder.pool(0).main();
                let sha256_chip = Sha256Chip::new(&range);

                // === Assign preimage bytes as witnesses ===
                let root_input_bytes: Vec<AssignedValue<Fr>> = self.entries[0]
                    .cell_repr_data
                    .iter()
                    .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                    .collect();
                let child_input_bytes: Vec<AssignedValue<Fr>> = self.entries[1]
                    .cell_repr_data
                    .iter()
                    .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                    .collect();

                // === SHA-256 hash computation ===
                // digest_bytes range-checks all input bytes to 8 bits
                // and returns 32 big-endian output bytes.
                let root_hash_bytes = sha256_chip.digest_bytes(ctx, &root_input_bytes);
                let child_hash_bytes = sha256_chip.digest_bytes(ctx, &child_input_bytes);

                // === Child hash connectivity check ===
                // Root preimage embeds the child's repr_hash at a known byte offset.
                // Constrain those embedded bytes == child's computed SHA-256 output.
                let root_child_hash_byte_offset: usize =
                    self.entries[0].childs_repr_hashes_offset.as_ref().unwrap()[0] as usize;
                for i in 0..SHA256_HASH_LEN {
                    ctx.constrain_equal(
                        &root_input_bytes[root_child_hash_byte_offset + i],
                        &child_hash_bytes[i],
                    );
                }

                // === Field extraction from child preimage bytes ===
                // Bytes are already assigned and range-checked by digest_bytes.

                // sk_u_commit (bytes 6..38, LE Fr representation)
                let sk_u_commit_bytes =
                    &child_input_bytes[EVENT_SK_U_COMMIT_START..EVENT_SK_U_COMMIT_END];
                let le_powers_32: Vec<QuantumCell<Fr>> = (0..EVENT_SK_U_COMMIT_FIELD_LEN)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();
                let sk_u_commit_cells: Vec<QuantumCell<Fr>> = sk_u_commit_bytes
                    .iter()
                    .map(|b| QuantumCell::Existing(*b))
                    .collect();
                let sk_u_commit = gate.inner_product(ctx, sk_u_commit_cells, le_powers_32);

                // voucher_nominal (bytes 38..70, BE)
                let voucher_bytes =
                    &child_input_bytes[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END];
                let be_powers_32: Vec<QuantumCell<Fr>> = (0..EVENT_VOUCHER_NOMINAL_FIELD_LEN)
                    .map(|i| {
                        QuantumCell::Constant(
                            Fr::from(256u64).pow([(EVENT_VOUCHER_NOMINAL_FIELD_LEN - 1 - i) as u64]),
                        )
                    })
                    .collect();
                let voucher_cells: Vec<QuantumCell<Fr>> = voucher_bytes
                    .iter()
                    .map(|b| QuantumCell::Existing(*b))
                    .collect();
                let voucher_nominal = gate.inner_product(ctx, voucher_cells, be_powers_32);

                // token_type (bytes 70..74, BE)
                let token_bytes =
                    &child_input_bytes[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END];
                let be_powers_4: Vec<QuantumCell<Fr>> = (0..EVENT_TOKEN_TYPE_FIELD_LEN)
                    .map(|i| {
                        QuantumCell::Constant(
                            Fr::from(256u64).pow([(EVENT_TOKEN_TYPE_FIELD_LEN - 1 - i) as u64]),
                        )
                    })
                    .collect();
                let token_cells: Vec<QuantumCell<Fr>> = token_bytes
                    .iter()
                    .map(|b| QuantumCell::Existing(*b))
                    .collect();
                let token_type = gate.inner_product(ctx, token_cells, be_powers_4);

                // === d1 descriptor checks ===
                // Input bytes are already range-checked to [0,255] by digest_bytes.
                let root_d1 = root_input_bytes[0];
                let child_d1 = child_input_bytes[0];

                // Root d1: refs_count (lower 3 bits) == 1.
                {
                    let root_d1_val =
                        self.entries[0].cell_repr_data.get(0).copied().unwrap_or(0);
                    let bits: Vec<AssignedValue<Fr>> = (0..8u32)
                        .map(|i| {
                            ctx.load_witness(Fr::from(((root_d1_val >> i) & 1) as u64))
                        })
                        .collect();
                    for &bit in &bits {
                        gate.assert_bit(ctx, bit);
                    }
                    let powers: Vec<_> =
                        (0..8u32).map(|i| QuantumCell::Constant(Fr::from(1u64 << i))).collect();
                    let reconstructed = gate.inner_product(ctx, bits.clone(), powers);
                    ctx.constrain_equal(&root_d1, &reconstructed);
                    let const_one = ctx.load_constant(Fr::one());
                    let const_zero = ctx.load_constant(Fr::zero());
                    ctx.constrain_equal(&bits[0], &const_one);
                    ctx.constrain_equal(&bits[1], &const_zero);
                    ctx.constrain_equal(&bits[2], &const_zero);
                }

                // Child d1: refs_count (lower 3 bits) == 0.
                {
                    let child_d1_val =
                        self.entries[1].cell_repr_data.get(0).copied().unwrap_or(0);
                    let bits: Vec<AssignedValue<Fr>> = (0..8u32)
                        .map(|i| {
                            ctx.load_witness(Fr::from(((child_d1_val >> i) & 1) as u64))
                        })
                        .collect();
                    for &bit in &bits {
                        gate.assert_bit(ctx, bit);
                    }
                    let powers: Vec<_> =
                        (0..8u32).map(|i| QuantumCell::Constant(Fr::from(1u64 << i))).collect();
                    let reconstructed = gate.inner_product(ctx, bits.clone(), powers);
                    ctx.constrain_equal(&child_d1, &reconstructed);
                    let const_zero = ctx.load_constant(Fr::zero());
                    ctx.constrain_equal(&bits[0], &const_zero);
                    ctx.constrain_equal(&bits[1], &const_zero);
                    ctx.constrain_equal(&bits[2], &const_zero);
                }

                // === Poseidon commitment ===
                let values = [self.sk_u, Fr::zero()];
                let inputs = ctx.assign_witnesses(values.clone());
                let sk_u_assigned = inputs[0].clone();

                let spec = OptimizedPoseidonSpec::<Fr, T, RATE>::new::<R_F, R_P, 0>();
                let mut hasher = PoseidonHasher::<Fr, T, RATE>::new(spec);
                hasher.initialize_consts(ctx, gate);
                let hasher_result = hasher.hash_fix_len_array(ctx, gate, &inputs);

                ctx.constrain_equal(&sk_u_commit, &hasher_result);

                let inputs = [voucher_nominal, token_type, sk_u_assigned, sk_u_commit];
                let final_hasher_result = hasher.hash_fix_len_array(ctx, gate, &inputs);

                // === a. Pack SHA-256 output to repr_hash_fr ===
                // root_hash_bytes are 32 BE bytes from Sha256Chip.
                // Pack into repr_hash_fr using LE byte-order weights (same encoding
                // as bytes_to_fr in the dense tree module).
                let powers: Vec<QuantumCell<Fr>> = (0..32)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();
                let byte_cells: Vec<QuantumCell<Fr>> = root_hash_bytes
                    .iter()
                    .map(|b| QuantumCell::Existing(*b))
                    .collect();
                let repr_hash_fr = gate.inner_product(ctx, byte_cells, powers);

                // === b. Compute ext_message_leaf in-circuit ===
                let dapp_fr = ctx.load_witness(bytes_to_fr(&self.account_dapp_id));
                let acc_fr = ctx.load_witness(bytes_to_fr(&self.account_id));
                let ext_msg_leaf_fr = poseidon_hash_96_circuit(
                    ctx, &range, &hasher,
                    dapp_fr, acc_fr, repr_hash_fr,
                    &self.account_dapp_id, &self.account_id, &self.entries[0].repr_hash,
                );

                // === c. Prove ext_msg_leaf → ext_out_messages_root ===
                let ext_msg_leaf_native = poseidon_hash_96_native(
                    &self.account_dapp_id, &self.account_id, &self.entries[0].repr_hash,
                );
                // Unpadded proof for native root computation
                let events_proof_native = preprocess_dense_proof(
                    ext_msg_leaf_native,
                    &self.merkle_proof_siblings,
                    self.merkle_proof_position,
                );
                // Padded proof for in-circuit verification (always MAX_EVENTS_TREE_DEPTH levels)
                let events_proof_padded = preprocess_dense_proof_padded(
                    ext_msg_leaf_native,
                    &self.merkle_proof_siblings,
                    self.merkle_proof_position,
                    MAX_EVENTS_TREE_DEPTH,
                );
                // Load & range-check num_events_levels in [0, MAX_EVENTS_TREE_DEPTH]
                let num_events_levels = ctx.load_witness(
                    Fr::from(self.merkle_proof_siblings.len() as u64),
                );
                range.range_check(ctx, num_events_levels, 4);
                let max_ev_const = ctx.load_constant(
                    Fr::from(MAX_EVENTS_TREE_DEPTH as u64),
                );
                let ev_diff = gate.sub(ctx, max_ev_const, num_events_levels);
                range.range_check(ctx, ev_diff, 4);

                let ext_out_root = dense_merkle_root_circuit_padded(
                    ctx, &range, &hasher, &events_proof_padded,
                    ext_msg_leaf_fr, num_events_levels,
                );

                // === d. Compute block_leaf in-circuit ===
                let block_id_fr = ctx.load_witness(bytes_to_fr(&self.block_id));
                let envelope_hash_fr = ctx.load_witness(bytes_to_fr(&self.envelope_hash_bytes));
                // When the events proof has 0 levels, the padded circuit returns
                // the leaf unchanged. The native computation must match.
                let ext_out_root_bytes = if self.merkle_proof_siblings.is_empty() {
                    ext_msg_leaf_native
                } else {
                    fr_to_bytes(compute_root_native(&events_proof_native))
                };
                let block_leaf_fr = poseidon_hash_96_circuit(
                    ctx, &range, &hasher,
                    block_id_fr, envelope_hash_fr, ext_out_root,
                    &self.block_id, &self.envelope_hash_bytes, &ext_out_root_bytes,
                );

                // === e. Prove block_leaf → history window root (root_1) ===
                let block_leaf_native = poseidon_hash_96_native(
                    &self.block_id, &self.envelope_hash_bytes, &ext_out_root_bytes,
                );
                let block_proof = preprocess_dense_proof(
                    block_leaf_native,
                    &self.block_merkle_proof_siblings,
                    self.block_merkle_proof_position,
                );
                let root_1 = dense_merkle_root_circuit(
                    ctx, &range, &hasher, &block_proof, block_leaf_fr,
                );

                // === f. Optional chain of dense proofs ===
                // Constrain num_active_chain_steps in [0, MAX_CHAIN_LEN].
                let num_active = ctx.load_witness(Fr::from(self.num_active_chain_steps as u64));
                range.range_check(ctx, num_active, 4);
                let max_chain_const = ctx.load_constant(Fr::from(MAX_CHAIN_LEN as u64));
                let max_minus_na = gate.sub(ctx, max_chain_const, num_active);
                range.range_check(ctx, max_minus_na, 4);

                let final_root = verify_chain_of_dense_proofs(
                    ctx, &range, &hasher, root_1, &self.dense_chain, num_active,
                );

                (final_hasher_result, final_root, voucher_nominal, token_type)
            };

            // Instance 4: ephemeral_pubkey, witnessed by the prover and
            // exposed publicly. Binds the proof to a specific PN owner so
            // an attacker cannot substitute their own pubkey at deploy
            // time without re-running the prover (which they can't —
            // they don't have sk_u).
            let eph = {
                let ctx = builder.pool(0).main();
                ctx.load_witness(self.ephemeral_pubkey)
            };
            builder.assigned_instances[0].push(final_hasher_result);
            builder.assigned_instances[0].push(final_root);
            builder.assigned_instances[0].push(voucher_nominal);
            builder.assigned_instances[0].push(token_type);
            builder.assigned_instances[0].push(eph);
        }

        // Synthesize base circuit builder to materialize virtual constraints.
        let builder = self.base_circuit_builder.borrow();
        builder.synthesize(config.base_circuit_config, layouter)?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use dense_balanced_tree::PoseidonHasher as DensePoseidonHasher;
    use halo2_base::halo2_proofs::dev::MockProver;

    #[test]
    fn test_dark_dex_circuit_for_all_collected_events_mock_prover() {
        use crate::event_data_helper::read_event_data_from_file;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let events = read_event_data_from_file("vouchers.txt");
        assert!(!events.is_empty(), "vouchers.txt must contain at least one entry");

        let params = base_circuit_params();
        let all_vouchers: Vec<VoucherFields> = events
            .iter()
            .map(|ev| {
                let (entries, repr_hash) = parse_voucher_boc(&ev.event_boc);
                extract_voucher_fields(ev.sk_u, entries, repr_hash)
            })
            .collect();
        println!("Parsed {} vouchers", all_vouchers.len());

        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(42);

        for (idx, v) in all_vouchers.iter().enumerate() {
            println!("\n========== Voucher {} ==========", idx);

            let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);
            println!("Events proof depth: {}", tw.events_siblings.len());
            println!("Block proof depth: {}", tw.block_siblings.len());

            let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
            let final_root_fr = bytes_to_fr(&final_root_bytes);

            let ephemeral_pubkey = Fr::from(0xDEADu64);
            let circuit = DarkDexCircuitNew::new(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings,
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings,
                tw.block_pos,
                dense_chain,
                1,
                params.clone(),
            );

            println!("Running MockProver...");
            let prover = MockProver::<Fr>::run(
                K,
                &circuit,
                vec![vec![v.expected_poseidon_hash, final_root_fr, v.voucher_nominal_val, v.token_type_val, ephemeral_pubkey]],
            )
            .unwrap();
            prover.assert_satisfied();
            println!("Voucher {} passed", idx);
        }
        println!(
            "\nAll {} vouchers passed with two-level tree proofs",
            all_vouchers.len()
        );
    }

   
    #[test]
    fn test_dark_dex_circuit_merkle_chain_variable_length() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let v = load_first_voucher();

        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(77);

        let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);

        let params = base_circuit_params();

        for t in 0..=MAX_CHAIN_LEN {
            println!("\n========== Chain T={} ==========", t);

            let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, t, 130);
            let final_root_fr = bytes_to_fr(&final_root_bytes);

            let ephemeral_pubkey = Fr::from(0xDEADu64);
            let circuit = DarkDexCircuitNew::new(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings.clone(),
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings.clone(),
                tw.block_pos,
                dense_chain,
                t,
                params.clone(),
            );

            println!("Running MockProver for T={}...", t);
            let prover = MockProver::<Fr>::run(
                K,
                &circuit,
                vec![vec![v.expected_poseidon_hash, final_root_fr, v.voucher_nominal_val, v.token_type_val, ephemeral_pubkey]],
            )
            .unwrap();
            prover.assert_satisfied();
            println!("T={} passed!", t);
        }
        println!("\nAll chain lengths T=0..{} passed!", MAX_CHAIN_LEN);
    }


    #[test]
    fn test_dark_dex_circuit_real_proof_for_fixed_k() { //now k = 19
        use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
        use halo2_base::utils::fs::gen_srs;
        use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        use std::time::Instant;

        let v = load_first_voucher();

        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(99);

        let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);

        let params = base_circuit_params();

        // Generate SRS params once.
        let srs = gen_srs(K);

        // Keygen once with T=1 (circuit shape is the same for all chain lengths
        // since verify_chain_of_dense_proofs always processes MAX_CHAIN_LEN links).
        let (keygen_chain, _) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
        let ephemeral_pubkey = Fr::from(0xDEADu64);
        let keygen_circuit = DarkDexCircuitNew::new(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            tw.events_siblings.clone(),
            tw.events_pos,
            tw.account_dapp_id,
            tw.account_id,
            tw.block_id,
            tw.envelope_hash_bytes,
            tw.block_siblings.clone(),
            tw.block_pos,
            keygen_chain,
            1,
            params.clone(),
        );

        let start = Instant::now();
        let vk = keygen_vk(&srs, &keygen_circuit).expect("keygen_vk should not fail");
        println!("keygen_vk time: {:?}", start.elapsed());

        let start = Instant::now();
        let pk = keygen_pk(&srs, vk, &keygen_circuit).expect("keygen_pk should not fail");
        println!("keygen_pk time: {:?}", start.elapsed());

        let break_points = keygen_circuit.base_circuit_builder.borrow().break_points();

        // Test chain lengths: 0, 1, 2, 5, MAX_CHAIN_LEN.
        let chain_lengths = [0, 1, 2, 5, MAX_CHAIN_LEN];

        struct ProofResult {
            chain_len: usize,
            prove_ms: u128,
            verify_ms: u128,
            proof_size: usize,
        }
        let mut results: Vec<ProofResult> = Vec::new();

        for &chain_len in &chain_lengths {
            println!("\n========== Real proof: chain_len={} ==========", chain_len);

            let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, chain_len, 130);
            let final_root_fr = bytes_to_fr(&final_root_bytes);

            let prover_circuit = DarkDexCircuitNew::new_for_proving(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings.clone(),
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings.clone(),
                tw.block_pos,
                dense_chain,
                chain_len,
                params.clone(),
                break_points.clone(),
            );

            let start = Instant::now();
            let instance_fr = vec![v.expected_poseidon_hash, final_root_fr, v.voucher_nominal_val, v.token_type_val, ephemeral_pubkey];
            let proof_bytes =
                gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instance_fr]);
            let prove_ms = start.elapsed().as_millis();
            println!("  proof generation time: {}ms", prove_ms);
            println!("  proof size: {} bytes", proof_bytes.len());

            let start = Instant::now();
            check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instance_fr], true);
            let verify_ms = start.elapsed().as_millis();
            println!("  proof verification time: {}ms", verify_ms);
            println!("  chain_len={} passed!", chain_len);

            results.push(ProofResult {
                chain_len,
                prove_ms,
                verify_ms,
                proof_size: proof_bytes.len(),
            });
        }

        // Print summary table.
        println!("\n╔════════════╤═══════════╤═══════════╤════════════╗");
        println!("║ chain_len  │  prove    │  verify   │ proof_size ║");
        println!("╠════════════╪═══════════╪═══════════╪════════════╣");
        for r in &results {
            println!(
                "║    {:>2}      │  {:>6}ms │  {:>6}ms │  {:>6}B   ║",
                r.chain_len, r.prove_ms, r.verify_ms, r.proof_size,
            );
        }
        println!("╚════════════╧═══════════╧═══════════╧════════════╝");
        println!("\nAll chain lengths passed!");
    }

    /// Export W=128 VK + proofs + instances for embedding in tvm-sdk.
    ///
    /// Usage:
    ///   TVM_SDK_EXPORT_DIR=/path/to/tvm-sdk/tvm_vm/halo2_test_data \
    ///   cargo test --release test_export_tvm_sdk_data_w128 -- --nocapture
    ///
    /// Writes:
    ///   {TVM_SDK_EXPORT_DIR}/dark_dex_w128_vk.bin           (VK serialized with RawBytesUnchecked)
    ///   {TVM_SDK_EXPORT_DIR}/dark_dex_w128_L{N}_proof.bin   (N ∈ {0,1,2})
    ///   {TVM_SDK_EXPORT_DIR}/dark_dex_w128_L{N}_instances.bin  (5 × 32 bytes LE Fr)
    ///
    /// VK byte format matches `gosh_zk_snark_halo2_utils::io::read_vk` (SerdeFormat::RawBytesUnchecked).
    /// Synthesizes a W=128 tree: 128 events leaves (depth 7), 130 block leaves (depth 8),
    /// 130 leaves per dense chain tree (depth 8) — matches the canonical W=128 layout
    /// used by `test_dark_dex_circuit_real_proof_for_fixed_k`.
    #[test]
    fn test_export_tvm_sdk_data_w128() {
        use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
        use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
        use halo2_base::halo2_proofs::SerdeFormat;
        use halo2_base::utils::fs::gen_srs;
        use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        use std::time::Instant;

        let out_dir = match std::env::var("TVM_SDK_EXPORT_DIR") {
            Ok(p) => std::path::PathBuf::from(p),
            Err(_) => {
                println!("TVM_SDK_EXPORT_DIR not set — skipping.");
                return;
            }
        };
        assert!(
            out_dir.is_dir(),
            "TVM_SDK_EXPORT_DIR is not a directory: {}",
            out_dir.display()
        );

        let v = load_first_voucher();

        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(99);

        // W=128 layout: 128 events leaves (depth 7) + 130 block leaves (depth 8).
        let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);

        let params = base_circuit_params();
        let ephemeral_pubkey = Fr::from(0xDEADu64);

        println!("PARAMS_DIR = {:?}", std::env::var("PARAMS_DIR"));
        println!("Loading SRS (K={})...", K);
        let srs = gen_srs(K);

        // Keygen against a 1-step chain circuit; circuit shape is the same for all chain
        // lengths since verify_chain_of_dense_proofs always processes MAX_CHAIN_LEN links.
        let (keygen_chain, _) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
        let keygen_circuit = DarkDexCircuitNew::new(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            tw.events_siblings.clone(),
            tw.events_pos,
            tw.account_dapp_id,
            tw.account_id,
            tw.block_id,
            tw.envelope_hash_bytes,
            tw.block_siblings.clone(),
            tw.block_pos,
            keygen_chain,
            1,
            params.clone(),
        );

        let start = Instant::now();
        let vk = keygen_vk(&srs, &keygen_circuit).expect("keygen_vk failed");
        println!("keygen_vk time: {:?}", start.elapsed());

        // Serialize VK with the same format tvm-sdk's read_vk uses.
        let mut vk_bytes: Vec<u8> = Vec::new();
        vk.write(&mut vk_bytes, SerdeFormat::RawBytesUnchecked)
            .expect("vk.write failed");
        let vk_path = out_dir.join("dark_dex_w128_vk.bin");
        std::fs::write(&vk_path, &vk_bytes).expect("write vk");
        println!("Wrote VK: {} ({} B)", vk_path.display(), vk_bytes.len());

        let start = Instant::now();
        let pk = keygen_pk(&srs, vk, &keygen_circuit).expect("keygen_pk failed");
        println!("keygen_pk time: {:?}", start.elapsed());

        let break_points = keygen_circuit.base_circuit_builder.borrow().break_points();

        for chain_len in [0usize, 1, 2] {
            let (dense_chain, final_root_bytes) =
                build_dense_chain(tw.blocks_root_level_0, chain_len, 130);
            let final_root_fr = bytes_to_fr(&final_root_bytes);

            let prover_circuit = DarkDexCircuitNew::new_for_proving(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings.clone(),
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings.clone(),
                tw.block_pos,
                dense_chain,
                chain_len,
                params.clone(),
                break_points.clone(),
            );

            let instance_fr = vec![
                v.expected_poseidon_hash,
                final_root_fr,
                v.voucher_nominal_val,
                v.token_type_val,
                ephemeral_pubkey,
            ];
            assert_eq!(instance_fr.len(), 5);

            println!("\n[L{}] proving...", chain_len);
            let start = Instant::now();
            let proof_bytes = gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instance_fr]);
            println!(
                "[L{}] proof = {} bytes in {}ms; sanity-verifying...",
                chain_len,
                proof_bytes.len(),
                start.elapsed().as_millis()
            );
            check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instance_fr], true);

            // 5 Fr × 32 bytes LE = 160 B; tvm-sdk decodes via Fr::from_bytes_le (byte-exact symmetric).
            let mut instances_bytes: Vec<u8> = Vec::with_capacity(5 * 32);
            for fr in &instance_fr {
                instances_bytes.extend_from_slice(fr.to_repr().as_ref());
            }
            assert_eq!(instances_bytes.len(), 160);

            let proof_path = out_dir.join(format!("dark_dex_w128_L{}_proof.bin", chain_len));
            let instances_path = out_dir.join(format!("dark_dex_w128_L{}_instances.bin", chain_len));
            std::fs::write(&proof_path, &proof_bytes).expect("write proof");
            std::fs::write(&instances_path, &instances_bytes).expect("write instances");
            println!(
                "[L{}] wrote {} ({} B) and {} ({} B)",
                chain_len,
                proof_path.display(),
                proof_bytes.len(),
                instances_path.display(),
                instances_bytes.len()
            );
        }

        println!(
            "\nDone — wrote VK + 3 (proof,instances) pairs to {}",
            out_dir.display()
        );
    }

    #[test]
    fn test_k_sweep_benchmark() {
        use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
        use halo2_base::utils::fs::gen_srs;
        use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        use std::time::Instant;

        let v = load_first_voucher();

        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(55);

        let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);

        let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
        let final_root_fr = bytes_to_fr(&final_root_bytes);
        let ephemeral_pubkey = Fr::from(0xDEADu64);

        // ── Step 1: Measure cell counts using K=19 (known-good params) ──
        println!("\n=== Step 1: Measuring circuit cell usage with K={} ===\n", K);
        let (total_advice, total_lookup, total_fixed);
        {
            let params = base_circuit_params();
            let measure_circuit = DarkDexCircuitNew::new(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings.clone(),
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings.clone(),
                tw.block_pos,
                dense_chain.clone(),
                1,
                params,
            );
            let srs_measure = gen_srs(K);
            let _ = keygen_vk(&srs_measure, &measure_circuit).expect("keygen_vk for measurement failed");

            let stats = measure_circuit.base_circuit_builder.borrow().statistics();
            total_advice = stats.gate.total_advice_per_phase[0];
            total_lookup = stats.total_lookup_advice_per_phase[0];
            total_fixed = stats.gate.total_fixed;
            println!("Total advice cells: {}", total_advice);
            println!("Total lookup advice cells: {}", total_lookup);
            println!("Total fixed (constants): {}", total_fixed);
        }

        // ── Step 2: Sweep K = 14..=20 ──
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

        for k_val in 14u32..=20 {
            println!("────────────────────────────────────────────");
            println!("  K = {} (2^{} = {} rows)", k_val, k_val, 1u64 << k_val);
            println!("────────────────────────────────────────────");

            let usable_rows = (1usize << k_val) - 12;
            let lookup_bits = (k_val - 1) as usize;

            let num_advice = ((total_advice as f64 / usable_rows as f64) * 1.05).ceil() as usize;
            let num_advice = num_advice.max(1);
            let num_lookup_advice = ((total_lookup as f64 / usable_rows as f64) * 1.05).ceil() as usize;
            let num_lookup_advice = num_lookup_advice.max(1);
            let num_fixed = ((total_fixed as f64 / usable_rows as f64) * 1.05).ceil() as usize;
            let num_fixed = num_fixed.max(1);

            let total_columns = num_advice + num_lookup_advice + num_fixed + 1;

            println!("  Usable rows: {}", usable_rows);
            println!("  Config: num_advice={}, num_lookup_advice={}, num_fixed={}, lookup_bits={}",
                     num_advice, num_lookup_advice, num_fixed, lookup_bits);
            println!("  Total polynomial columns: {}", total_columns);

            let params = BaseCircuitParams {
                k: k_val as usize,
                num_advice_per_phase: vec![num_advice],
                num_fixed,
                num_lookup_advice_per_phase: vec![num_lookup_advice],
                lookup_bits: Some(lookup_bits),
                num_instance_columns: 1,
            };

            let start = Instant::now();
            let srs = gen_srs(k_val);
            println!("  SRS gen:   {}ms", start.elapsed().as_millis());

            // Keygen
            let keygen_circuit = DarkDexCircuitNew::new(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings.clone(),
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings.clone(),
                tw.block_pos,
                dense_chain.clone(),
                1,
                params.clone(),
            );

            let start = Instant::now();
            let vk = keygen_vk(&srs, &keygen_circuit).expect("keygen_vk failed");
            let keygen_vk_ms = start.elapsed().as_millis();
            println!("  keygen_vk: {}ms", keygen_vk_ms);

            let start = Instant::now();
            let pk = keygen_pk(&srs, vk, &keygen_circuit).expect("keygen_pk failed");
            let keygen_pk_ms = start.elapsed().as_millis();
            println!("  keygen_pk: {}ms", keygen_pk_ms);

            let break_points = keygen_circuit.base_circuit_builder.borrow().break_points();

            // Prove
            let prover_circuit = DarkDexCircuitNew::new_for_proving(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings.clone(),
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings.clone(),
                tw.block_pos,
                dense_chain.clone(),
                1,
                params,
                break_points,
            );

            let start = Instant::now();
            let instance_fr = vec![v.expected_poseidon_hash, final_root_fr, v.voucher_nominal_val, v.token_type_val, ephemeral_pubkey];
            let proof_bytes =
                gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instance_fr]);
            let prove_ms = start.elapsed().as_millis();
            println!("  prove:     {}ms", prove_ms);
            println!("  proof size: {} bytes", proof_bytes.len());

            // Verify (run 5 times and take median for stability)
            let mut verify_times = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                check_proof_with_instances(&srs, pk.get_vk(), &proof_bytes, &[&instance_fr], true);
                verify_times.push(start.elapsed().as_millis());
            }
            verify_times.sort();
            let verify_ms = verify_times[2]; // median
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

        // ── Print summary table ──
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

    #[test]
    fn test_dark_dex_circuit_variable_events_depth() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let v = load_first_voucher();

        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(314);

        let params = base_circuit_params();

        // Test events trees of various sizes (depths 1–8), block tree always 130 leaves.
        let events_leaf_counts = [2, 4, 16, 64, 128, 256];

        for &num_events_leaves in &events_leaf_counts {
            let depth = ceil_log2(num_events_leaves);
            println!(
                "\n========== Events leaves={}, depth={} ==========",
                num_events_leaves, depth
            );

            let tw = build_two_level_tree(
                &v.repr_hash, &mut rng, &dense_hasher, num_events_leaves, 130,
            );
            println!("Events proof depth: {}", tw.events_siblings.len());
            println!("Block proof depth: {}", tw.block_siblings.len());

            let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
            let final_root_fr = bytes_to_fr(&final_root_bytes);

            let ephemeral_pubkey = Fr::from(0xDEADu64);
            let circuit = DarkDexCircuitNew::new(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                tw.events_siblings,
                tw.events_pos,
                tw.account_dapp_id,
                tw.account_id,
                tw.block_id,
                tw.envelope_hash_bytes,
                tw.block_siblings,
                tw.block_pos,
                dense_chain,
                1,
                params.clone(),
            );

            println!("Running MockProver...");
            let prover = MockProver::<Fr>::run(
                K,
                &circuit,
                vec![vec![v.expected_poseidon_hash, final_root_fr, v.voucher_nominal_val, v.token_type_val, ephemeral_pubkey]],
            )
            .unwrap();
            prover.assert_satisfied();
            println!(
                "Events leaves={}, depth={} passed!",
                num_events_leaves, depth
            );
        }
        println!(
            "\nAll variable-depth events tree tests passed!"
        );
    }
}
