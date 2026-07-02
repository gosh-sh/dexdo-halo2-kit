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

use crate::block_id_tree::assert_depth4_l8_opening_circuit;
use crate::boc_helper::*;
use crate::salt::{compute_salt_native, domain_tag_hop_salt_fr};
use gosh_dense_balanced_tree::{
    bytes_to_fr, compute_root_native, dense_merkle_root_circuit,
    dense_merkle_root_circuit_padded, fr_to_bytes, poseidon_hash_native,
    preprocess_dense_proof, preprocess_dense_proof_padded,
    verify_chain_of_dense_proofs, DenseChainLink, MAX_CHAIN_LEN, R_F, R_P, RATE, T,
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

/// Byte-flat Poseidon over `a ‖ b ‖ c` (96 bytes total).
///
/// Takes byte cells directly (with per-byte `range_check 8`), so each chunk
/// is uniquely determined by the witness. No `chunks_int ≡ Fr (mod p)`
/// malleability: the integer formed by `a_bytes ‖ b_bytes ‖ c_bytes` is
/// fully pinned by the per-byte range checks, and every chunk is < 2^248 < p
/// so equals its integer value in Fp.
///
/// Chunk layout (matching `hash_bytes_flat` / `chunk_96_bytes_to_fr`):
///   c0 = LE(buf[0..31])   c1 = LE(buf[31..62])
///   c2 = LE(buf[62..93])  c3 = LE(buf[93..96])
fn poseidon_hash_96_circuit_bytes(
    ctx: &mut Context<Fr>,
    range: &impl RangeInstructions<Fr>,
    hasher: &PoseidonHasher<Fr, T, RATE>,
    a_bytes: &[AssignedValue<Fr>; 32],
    b_bytes: &[AssignedValue<Fr>; 32],
    c_bytes: &[AssignedValue<Fr>; 32],
) -> AssignedValue<Fr> {
    let gate = range.gate();

    // Per-byte range checks pin each cell to [0, 256).
    for cells in [a_bytes, b_bytes, c_bytes] {
        for &cell in cells {
            range.range_check(ctx, cell, 8);
        }
    }

    // Powers of 256 LE, up to 30 (longest contiguous byte slice in any chunk).
    let powers_le_31: Vec<QuantumCell<Fr>> = (0..31)
        .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
        .collect();

    // c0 = LE(a[0..31])
    let c0 = {
        let cells: Vec<QuantumCell<Fr>> =
            a_bytes[0..31].iter().map(|c| QuantumCell::Existing(*c)).collect();
        gate.inner_product(ctx, cells, powers_le_31[..31].iter().cloned())
    };

    // c1 = a[31] + 256 · LE(b[0..30])
    let c1 = {
        let lo30 = {
            let cells: Vec<QuantumCell<Fr>> =
                b_bytes[0..30].iter().map(|c| QuantumCell::Existing(*c)).collect();
            gate.inner_product(ctx, cells, powers_le_31[..30].iter().cloned())
        };
        gate.mul_add(
            ctx,
            QuantumCell::Existing(lo30),
            QuantumCell::Constant(Fr::from(256u64)),
            QuantumCell::Existing(a_bytes[31]),
        )
    };

    // c2 = LE(b[30..32]) + 2^16 · LE(c[0..29])
    let c2 = {
        let hi_b = {
            let cells: Vec<QuantumCell<Fr>> =
                b_bytes[30..32].iter().map(|c| QuantumCell::Existing(*c)).collect();
            gate.inner_product(ctx, cells, powers_le_31[..2].iter().cloned())
        };
        let lo29 = {
            let cells: Vec<QuantumCell<Fr>> =
                c_bytes[0..29].iter().map(|c| QuantumCell::Existing(*c)).collect();
            gate.inner_product(ctx, cells, powers_le_31[..29].iter().cloned())
        };
        gate.mul_add(
            ctx,
            QuantumCell::Existing(lo29),
            QuantumCell::Constant(Fr::from(1u64 << 16)),
            QuantumCell::Existing(hi_b),
        )
    };

    // c3 = LE(c[29..32])
    let c3: AssignedValue<Fr> = {
        let cells: Vec<QuantumCell<Fr>> =
            c_bytes[29..32].iter().map(|c| QuantumCell::Existing(*c)).collect();
        gate.inner_product(ctx, cells, powers_le_31[..3].iter().cloned())
    };

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

/// DexFinalProof circuit per `MULTITHREAD_CIRCUIT_SPEC.md` §7.7.
///
/// Structure: two disjoint sub-circuits sharing salt + sk_u:
///   • X-side (SHA family, 6 SHA compressions): BOC reconstruction (2×) +
///     field extraction + Poseidon `ext_msg_leaf` + padded Poseidon
///     dense-Merkle to `x_l8_tracked_ext_out_messages_root` + depth-4 SHA
///     block_id opening (4×) binding `x_l8` into `x_block_id`. Exposes
///     `salted_X_start` (Poseidon on `x_block_id`).
///   • Y-side (Poseidon family): opaque byte-cell witnesses for
///     `y_block_id`, `y_envelope_hash`, `y_tracked_ext_out_messages_root` →
///     `block_leaf_Y = Poseidon96(...)` → depth-8 Poseidon dense-Merkle →
///     dense-chain → `finalLayerHistoricalHashRoot`. Exposes `salted_Y_end`.
///
/// Publics (8): `[depositIdentifierHash, finalLayerHistoricalHashRoot,
/// voucherNominalFr, tokenTypeFr, ephemeralPubkey, salted_X_start,
/// salted_Y_end, salt_commitment]`.
///
/// X and Y may be the same (t=0 uniform: producer thread = anchor thread)
/// or distinct (t≠0 cross-thread: event fires in thread t, anchor is
/// thread 0). The circuit is agnostic — X and Y are independent witness
/// bundles.
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

    // === X-side (event-emitting block) =====================================
    /// Private witness: dApp ID (32 bytes) for X-side `ext_message_leaf`.
    pub x_account_dapp_id: [u8; 32],
    /// Private witness: account ID (32 bytes) for X-side `ext_message_leaf`.
    pub x_account_id: [u8; 32],
    /// Private witness: X-side ext-out messages tree Merkle proof siblings.
    pub x_ext_out_merkle_proof_siblings: Vec<[u8; 32]>,
    /// Private witness: X-side ext-out messages tree leaf position.
    pub x_ext_out_merkle_proof_position: usize,
    /// Private witness: X-side block ID (32 bytes) — constrained via
    /// depth-4 SHA opening against `x_l8_tracked_ext_out_messages_root`.
    pub x_block_id: [u8; 32],
    /// Private witness: opaque left-half sibling (SHA-root of leaves
    /// 0..=7) in the depth-4 SHA block_id tree.
    pub x_block_id_h07_sibling: [u8; 32],

    // === Y-side (anchor block on thread 0) =================================
    /// Private witness: Y-side block ID (32 bytes) for Y-side `block_leaf`.
    pub y_block_id: [u8; 32],
    /// Private witness: Y-side envelope hash (unconstrained content).
    pub y_envelope_hash: [u8; 32],
    /// Private witness: Y-side `tracked_ext_out_messages_root` (unconstrained
    /// content; anchored upstream by the multi-hop stream, not by V2).
    pub y_tracked_ext_out_messages_root: [u8; 32],
    /// Private witness: Y-side history-window tree Merkle proof siblings.
    pub y_block_merkle_proof_siblings: Vec<[u8; 32]>,
    /// Private witness: Y-side history-window tree leaf position.
    pub y_block_merkle_proof_position: usize,
    /// Private witness: Y-side chain of dense balanced tree proofs.
    pub y_dense_chain: Vec<DenseChainLink>,
    /// Number of active chain steps on the Y-side (0..=MAX_CHAIN_LEN).
    pub y_num_active_chain_steps: usize,

    pub base_circuit_params: BaseCircuitParams,
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
}

impl DarkDexCircuitNew {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        // === X-side ===
        x_account_dapp_id: [u8; 32],
        x_account_id: [u8; 32],
        x_ext_out_merkle_proof_siblings: Vec<[u8; 32]>,
        x_ext_out_merkle_proof_position: usize,
        x_block_id: [u8; 32],
        x_block_id_h07_sibling: [u8; 32],
        // === Y-side ===
        y_block_id: [u8; 32],
        y_envelope_hash: [u8; 32],
        y_tracked_ext_out_messages_root: [u8; 32],
        y_block_merkle_proof_siblings: Vec<[u8; 32]>,
        y_block_merkle_proof_position: usize,
        y_dense_chain: Vec<DenseChainLink>,
        y_num_active_chain_steps: usize,
        base_circuit_params: BaseCircuitParams,
    ) -> Self {
        assert!(
            x_ext_out_merkle_proof_siblings.len() <= MAX_EVENTS_TREE_DEPTH,
            "X ext-out tree depth {} exceeds MAX_EVENTS_TREE_DEPTH {}",
            x_ext_out_merkle_proof_siblings.len(),
            MAX_EVENTS_TREE_DEPTH,
        );
        assert_eq!(y_dense_chain.len(), MAX_CHAIN_LEN);
        assert!(y_num_active_chain_steps <= MAX_CHAIN_LEN);
        let base_circuit_builder = RefCell::new(
            BaseCircuitBuilder::<Fr>::new(false).use_params(base_circuit_params.clone()),
        );
        Self {
            sk_u,
            ephemeral_pubkey,
            entries,
            x_account_dapp_id,
            x_account_id,
            x_ext_out_merkle_proof_siblings,
            x_ext_out_merkle_proof_position,
            x_block_id,
            x_block_id_h07_sibling,
            y_block_id,
            y_envelope_hash,
            y_tracked_ext_out_messages_root,
            y_block_merkle_proof_siblings,
            y_block_merkle_proof_position,
            y_dense_chain,
            y_num_active_chain_steps,
            base_circuit_params,
            base_circuit_builder,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_proving(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        // === X-side ===
        x_account_dapp_id: [u8; 32],
        x_account_id: [u8; 32],
        x_ext_out_merkle_proof_siblings: Vec<[u8; 32]>,
        x_ext_out_merkle_proof_position: usize,
        x_block_id: [u8; 32],
        x_block_id_h07_sibling: [u8; 32],
        // === Y-side ===
        y_block_id: [u8; 32],
        y_envelope_hash: [u8; 32],
        y_tracked_ext_out_messages_root: [u8; 32],
        y_block_merkle_proof_siblings: Vec<[u8; 32]>,
        y_block_merkle_proof_position: usize,
        y_dense_chain: Vec<DenseChainLink>,
        y_num_active_chain_steps: usize,
        base_circuit_params: BaseCircuitParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        assert!(
            x_ext_out_merkle_proof_siblings.len() <= MAX_EVENTS_TREE_DEPTH,
            "X ext-out tree depth {} exceeds MAX_EVENTS_TREE_DEPTH {}",
            x_ext_out_merkle_proof_siblings.len(),
            MAX_EVENTS_TREE_DEPTH,
        );
        assert_eq!(y_dense_chain.len(), MAX_CHAIN_LEN);
        assert!(y_num_active_chain_steps <= MAX_CHAIN_LEN);
        let base_circuit_builder = RefCell::new(BaseCircuitBuilder::<Fr>::prover(
            base_circuit_params.clone(),
            break_points,
        ));
        Self {
            sk_u,
            ephemeral_pubkey,
            entries,
            x_account_dapp_id,
            x_account_id,
            x_ext_out_merkle_proof_siblings,
            x_ext_out_merkle_proof_position,
            x_block_id,
            x_block_id_h07_sibling,
            y_block_id,
            y_envelope_hash,
            y_tracked_ext_out_messages_root,
            y_block_merkle_proof_siblings,
            y_block_merkle_proof_position,
            y_dense_chain,
            y_num_active_chain_steps,
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
        let dummy_chain = self.y_dense_chain.iter().map(|link| {
            DenseChainLink::inactive([0u8; 32], link.siblings.len())
        }).collect();
        Self::new(
            Fr::zero(),
            Fr::zero(),  // ephemeral_pubkey witness (0 for keygen/dummy)
            dummy_entries,
            // X-side dummies (preserve x_ext_out proof depth for layout stability)
            [0u8; 32],
            [0u8; 32],
            self.x_ext_out_merkle_proof_siblings.iter().map(|_| [0u8; 32]).collect(),
            0,
            [0u8; 32],
            [0u8; 32],
            // Y-side dummies (preserve y_block_merkle proof depth for layout stability)
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            self.y_block_merkle_proof_siblings.iter().map(|_| [0u8; 32]).collect(),
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

            let (
                final_hasher_result,
                final_root,
                voucher_nominal,
                token_type,
                salted_x_start,
                salted_y_end,
                salt_commitment,
            ) = {
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

                // === salt and salt_commitment ===
                // salt = Poseidon([DOMAIN_TAG_HOP_SALT_FR, sk_u])
                // salt_commitment = Poseidon([salt])
                //
                // The DexFinalProof's salt_commitment public input must equal
                // every MultiHopProof's salt_commitment in the same bundle —
                // RootPN.sol enforces this on-chain.
                let domain_tag_fr_const = ctx.load_constant(domain_tag_hop_salt_fr());
                let salt_assigned = hasher.hash_fix_len_array(
                    ctx, gate, &[domain_tag_fr_const, sk_u_assigned],
                );
                let salt_commitment = hasher.hash_fix_len_array(
                    ctx, gate, &[salt_assigned],
                );

                // ================================================================
                // ==================== X-SIDE (SHA family) =======================
                // Compute x_ext_msg_leaf → x_l8_tracked_ext_out_messages_root,
                // constrain V<p canonicality on x_l8 bytes, run depth-4 SHA
                // block_id opening binding x_l8 into x_block_id, expose
                // salted_x_start on x_block_id.
                // ================================================================

                // === X.a Compute ext_message_leaf in-circuit ===
                let x_dapp_id_bytes: [AssignedValue<Fr>; 32] = self
                    .x_account_dapp_id
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                let x_account_id_bytes: [AssignedValue<Fr>; 32] = self
                    .x_account_id
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                let root_hash_bytes_array: [AssignedValue<Fr>; 32] = root_hash_bytes
                    .clone()
                    .try_into()
                    .expect("root_hash_bytes is exactly 32 cells");
                let x_ext_msg_leaf_fr = poseidon_hash_96_circuit_bytes(
                    ctx, &range, &hasher,
                    &x_dapp_id_bytes, &x_account_id_bytes, &root_hash_bytes_array,
                );

                // === X.b Prove x_ext_msg_leaf → x_l8_tracked_ext_out_messages_root ===
                let x_ext_msg_leaf_native = poseidon_hash_96_native(
                    &self.x_account_dapp_id, &self.x_account_id, &self.entries[0].repr_hash,
                );
                // Unpadded proof for native root computation
                let x_events_proof_native = preprocess_dense_proof(
                    x_ext_msg_leaf_native,
                    &self.x_ext_out_merkle_proof_siblings,
                    self.x_ext_out_merkle_proof_position,
                );
                // Padded proof for in-circuit verification (always MAX_EVENTS_TREE_DEPTH levels)
                let x_events_proof_padded = preprocess_dense_proof_padded(
                    x_ext_msg_leaf_native,
                    &self.x_ext_out_merkle_proof_siblings,
                    self.x_ext_out_merkle_proof_position,
                    MAX_EVENTS_TREE_DEPTH,
                );
                // Load & range-check num_events_levels in [0, MAX_EVENTS_TREE_DEPTH]
                let x_num_events_levels = ctx.load_witness(
                    Fr::from(self.x_ext_out_merkle_proof_siblings.len() as u64),
                );
                range.range_check(ctx, x_num_events_levels, 4);
                let max_ev_const = ctx.load_constant(
                    Fr::from(MAX_EVENTS_TREE_DEPTH as u64),
                );
                let ev_diff = gate.sub(ctx, max_ev_const, x_num_events_levels);
                range.range_check(ctx, ev_diff, 4);

                let x_l8_ext_out_root = dense_merkle_root_circuit_padded(
                    ctx, &range, &hasher, &x_events_proof_padded,
                    x_ext_msg_leaf_fr, x_num_events_levels,
                );

                // Reusable LE powers of 256 up to 31 (matches `inner_product`
                // weights for a 32-byte LE integer decomposition).
                let powers_le_32: Vec<QuantumCell<Fr>> = (0..32)
                    .map(|i| QuantumCell::Constant(Fr::from(256u64).pow([i as u64])))
                    .collect();

                // === Salt decomposition (shared by salted_X_start and salted_Y_end) ===
                //
                // Match `compute_salted_block_id_native(salt, block_id)` in
                // `salt.rs`: chunk the 64-byte stream `fr_to_bytes(salt) ‖
                // block_id` at 31-byte boundaries (top byte zero ⇒ Fr-safe).
                //   chunk0 = LE(salt[0..31])                         (31 B)
                //   chunk1 = salt_hi + 256 · LE(block_id[0..30])     (31 B)
                //   chunk2 = LE(block_id[30..32])                    (2 B)
                //   salted = Poseidon([c0, c1, c2])
                //
                // Decompose `salt_assigned` once into salt_chunk0 + salt_hi · 2^248
                // (matches the pattern in `multi_hop_proof.rs` so the on-chain
                // RootPN salt-equality check holds across DexFinalProof and
                // every MultiHopProof in the bundle).
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
                    let pow_248 = QuantumCell::Constant(Fr::from_raw([
                        0u64,
                        0u64,
                        0u64,
                        1u64 << 56,
                    ]));
                    let reconstructed = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(salt_hi),
                        pow_248,
                        QuantumCell::Existing(salt_chunk0),
                    );
                    ctx.constrain_equal(&reconstructed, &salt_assigned);
                }

                // === X.c V<p canonical byte decomposition of x_l8 ===
                //
                // `x_l8_ext_out_root` is the algebraic Fr output of
                // `dense_merkle_root_circuit_padded` (a Poseidon image, so
                // < p). To feed it as bytes into the SHA depth-4 opening
                // we need 32 byte cells with a CANONICAL decomposition:
                // `V = sum bytes_i · 256^i` and `V < p`.
                let x_l8_bytes_native = if self.x_ext_out_merkle_proof_siblings.is_empty() {
                    x_ext_msg_leaf_native
                } else {
                    fr_to_bytes(compute_root_native(&x_events_proof_native))
                };
                let x_l8_bytes_cells: [AssignedValue<Fr>; 32] = {
                    let v: Vec<AssignedValue<Fr>> = x_l8_bytes_native
                        .iter()
                        .map(|&b| ctx.load_witness(Fr::from(b as u64)))
                        .collect();
                    v.try_into()
                        .expect("x_l8_bytes_native is exactly 32 bytes")
                };
                for &c in &x_l8_bytes_cells {
                    range.range_check(ctx, c, 8);
                }
                // Linking equation (mod p): sum_i byte_i · 256^i == x_l8_ext_out_root.
                {
                    let cells: Vec<QuantumCell<Fr>> = x_l8_bytes_cells
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    let sum = gate.inner_product(ctx, cells, powers_le_32.clone());
                    ctx.constrain_equal(&sum, &x_l8_ext_out_root);
                }
                // Canonical-form check: V < p, with V = V_lo + V_hi · 2^128.
                {
                    let p_lo = Fr::from_raw([
                        0x43e1_f593_f000_0001,
                        0x2833_e848_79b9_7091,
                        0,
                        0,
                    ]);
                    let p_hi = Fr::from_raw([
                        0xb850_45b6_8181_585d,
                        0x3064_4e72_e131_a029,
                        0,
                        0,
                    ]);
                    let lo_cells: Vec<QuantumCell<Fr>> = x_l8_bytes_cells
                        [0..16]
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    let hi_cells: Vec<QuantumCell<Fr>> = x_l8_bytes_cells
                        [16..32]
                        .iter()
                        .map(|c| QuantumCell::Existing(*c))
                        .collect();
                    let v_lo = gate.inner_product(
                        ctx,
                        lo_cells,
                        powers_le_32[0..16].iter().cloned(),
                    );
                    let v_hi = gate.inner_product(
                        ctx,
                        hi_cells,
                        powers_le_32[0..16].iter().cloned(),
                    );
                    let hi_less = range.is_less_than(
                        ctx,
                        QuantumCell::Existing(v_hi),
                        QuantumCell::Constant(p_hi),
                        128,
                    );
                    let hi_eq = gate.is_equal(
                        ctx,
                        QuantumCell::Existing(v_hi),
                        QuantumCell::Constant(p_hi),
                    );
                    let lo_less = range.is_less_than(
                        ctx,
                        QuantumCell::Existing(v_lo),
                        QuantumCell::Constant(p_lo),
                        128,
                    );
                    let tail = gate.and(ctx, hi_eq, lo_less);
                    let valid = gate.or(ctx, hi_less, tail);
                    let one = ctx.load_constant(Fr::one());
                    ctx.constrain_equal(&valid, &one);
                }

                // === X.d Depth-4 SHA opening binding x_l8 into x_block_id ===
                //
                // 4 additional SHA compressions verify that x_block_id is the
                // depth-4 SHA-tree root of 16 leaves where only leaf 8 = x_l8
                // carries content (leaves 9..=15 are zero, leaves 0..=7 are
                // aggregated into `x_block_id_h07_sibling`).
                let x_block_id_bytes: [AssignedValue<Fr>; 32] = self
                    .x_block_id
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                for &c in &x_block_id_bytes {
                    range.range_check(ctx, c, 8);
                }
                let x_h07_sibling_bytes: [AssignedValue<Fr>; 32] = self
                    .x_block_id_h07_sibling
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                // (assert_depth4_l8_opening_circuit re-range-checks h07 defensively)
                assert_depth4_l8_opening_circuit(
                    ctx,
                    &range,
                    &sha256_chip,
                    &x_l8_bytes_cells,
                    &x_h07_sibling_bytes,
                    &x_block_id_bytes,
                );

                // === X.e salted_X_start = byte-flat Poseidon on x_block_id ===
                let salted_x_start = {
                    let block_id_lo30 = {
                        let cells: Vec<QuantumCell<Fr>> = x_block_id_bytes[0..30]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(
                            ctx,
                            cells,
                            powers_le_32[0..30].iter().cloned(),
                        )
                    };
                    let chunk1 = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(block_id_lo30),
                        QuantumCell::Constant(Fr::from(256u64)),
                        QuantumCell::Existing(salt_hi),
                    );
                    let chunk2 = {
                        let cells: Vec<QuantumCell<Fr>> = x_block_id_bytes[30..32]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(
                            ctx,
                            cells,
                            powers_le_32[0..2].iter().cloned(),
                        )
                    };
                    hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[salt_chunk0, chunk1, chunk2],
                    )
                };

                // ================================================================
                // ==================== Y-SIDE (Poseidon family) ==================
                // Opaque byte-cell witnesses for y_block_id, y_envelope_hash,
                // y_tracked_ext_out_messages_root → block_leaf_Y → depth-8
                // Poseidon dense-Merkle → chain → final_root. Expose salted_Y_end.
                // ================================================================

                let y_block_id_bytes: [AssignedValue<Fr>; 32] = self
                    .y_block_id
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                for &c in &y_block_id_bytes {
                    range.range_check(ctx, c, 8);
                }
                let y_envelope_hash_bytes_cells: [AssignedValue<Fr>; 32] = self
                    .y_envelope_hash
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                for &c in &y_envelope_hash_bytes_cells {
                    range.range_check(ctx, c, 8);
                }
                let y_tracked_ext_out_root_bytes_cells: [AssignedValue<Fr>; 32] = self
                    .y_tracked_ext_out_messages_root
                    .map(|b| ctx.load_witness(Fr::from(b as u64)));
                for &c in &y_tracked_ext_out_root_bytes_cells {
                    range.range_check(ctx, c, 8);
                }

                // === Y.a block_leaf(Y) = Poseidon96(y_block_id, y_envelope_hash,
                //                                   y_tracked_ext_out_messages_root) ===
                let block_leaf_fr = poseidon_hash_96_circuit_bytes(
                    ctx, &range, &hasher,
                    &y_block_id_bytes,
                    &y_envelope_hash_bytes_cells,
                    &y_tracked_ext_out_root_bytes_cells,
                );

                // === Y.b Prove block_leaf → history window root (root_1) ===
                let block_leaf_native = poseidon_hash_96_native(
                    &self.y_block_id,
                    &self.y_envelope_hash,
                    &self.y_tracked_ext_out_messages_root,
                );
                let block_proof = preprocess_dense_proof(
                    block_leaf_native,
                    &self.y_block_merkle_proof_siblings,
                    self.y_block_merkle_proof_position,
                );
                let root_1 = dense_merkle_root_circuit(
                    ctx, &range, &hasher, &block_proof, block_leaf_fr,
                );

                // === Y.c Optional chain of dense proofs ===
                let num_active = ctx.load_witness(
                    Fr::from(self.y_num_active_chain_steps as u64),
                );
                range.range_check(ctx, num_active, 4);
                let max_chain_const = ctx.load_constant(Fr::from(MAX_CHAIN_LEN as u64));
                let max_minus_na = gate.sub(ctx, max_chain_const, num_active);
                range.range_check(ctx, max_minus_na, 4);

                let final_root = verify_chain_of_dense_proofs(
                    ctx, &range, &hasher, root_1, &self.y_dense_chain, num_active,
                );

                // === Y.d salted_Y_end = byte-flat Poseidon on y_block_id ===
                let salted_y_end = {
                    let block_id_lo30 = {
                        let cells: Vec<QuantumCell<Fr>> = y_block_id_bytes[0..30]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(
                            ctx,
                            cells,
                            powers_le_32[0..30].iter().cloned(),
                        )
                    };
                    let chunk1 = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(block_id_lo30),
                        QuantumCell::Constant(Fr::from(256u64)),
                        QuantumCell::Existing(salt_hi),
                    );
                    let chunk2 = {
                        let cells: Vec<QuantumCell<Fr>> = y_block_id_bytes[30..32]
                            .iter()
                            .map(|c| QuantumCell::Existing(*c))
                            .collect();
                        gate.inner_product(
                            ctx,
                            cells,
                            powers_le_32[0..2].iter().cloned(),
                        )
                    };
                    hasher.hash_fix_len_array(
                        ctx,
                        gate,
                        &[salt_chunk0, chunk1, chunk2],
                    )
                };

                (
                    final_hasher_result,
                    final_root,
                    voucher_nominal,
                    token_type,
                    salted_x_start,
                    salted_y_end,
                    salt_commitment,
                )
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
            // §7.3 V2 publics: salted_X_start (event-side, X block_id under
            // the same salt) and salted_Y_end (anchor-side, Y block_id under
            // the same salt). These bind the DexFinalProof to the bundle's
            // MultiHopProof chain endpoints.
            builder.assigned_instances[0].push(salted_x_start);
            builder.assigned_instances[0].push(salted_y_end);
            builder.assigned_instances[0].push(salt_commitment);
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
    use crate::salt::{
        compute_salt_commitment_native, compute_salt_native, compute_salted_block_id_native,
    };
    use crate::test_helpers::*;
    use dense_balanced_tree::PoseidonHasher as DensePoseidonHasher;
    use halo2_base::halo2_proofs::dev::MockProver;

    // -------------------------------------------------------------------
    // V2 test helpers: build a `DarkDexCircuitNew` (V2 §7.7 semantics)
    // from a `TwoLevelWitnesses` under the uniform t=0 (X==Y) assumption.
    // In the uniform case:
    //   * X-side and Y-side block_id agree (== `tw.block_id` == v2_x_block_id).
    //   * y_tracked_ext_out_messages_root == v2_x_l8 (== events tree root).
    //   * salted_X_start == salted_Y_end (both use the same block_id under
    //     the same salt).
    // Cross-thread tests use `build_v2_cross_thread_witness` directly and
    // do NOT go through these helpers.
    // -------------------------------------------------------------------
    #[cfg(test)]
    fn make_v2_circuit(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        tw: &TwoLevelWitnesses,
        dense_chain: Vec<DenseChainLink>,
        chain_len: usize,
        params: BaseCircuitParams,
    ) -> DarkDexCircuitNew {
        DarkDexCircuitNew::new(
            sk_u,
            ephemeral_pubkey,
            entries,
            tw.account_dapp_id,
            tw.account_id,
            tw.events_siblings.clone(),
            tw.events_pos,
            tw.block_id,
            tw.v2_x_block_id_h07_sibling,
            tw.block_id,
            tw.envelope_hash_bytes,
            tw.v2_x_l8,
            tw.block_siblings.clone(),
            tw.block_pos,
            dense_chain,
            chain_len,
            params,
        )
    }

    #[cfg(test)]
    fn make_v2_prover_circuit(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        tw: &TwoLevelWitnesses,
        dense_chain: Vec<DenseChainLink>,
        chain_len: usize,
        params: BaseCircuitParams,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> DarkDexCircuitNew {
        DarkDexCircuitNew::new_for_proving(
            sk_u,
            ephemeral_pubkey,
            entries,
            tw.account_dapp_id,
            tw.account_id,
            tw.events_siblings.clone(),
            tw.events_pos,
            tw.block_id,
            tw.v2_x_block_id_h07_sibling,
            tw.block_id,
            tw.envelope_hash_bytes,
            tw.v2_x_l8,
            tw.block_siblings.clone(),
            tw.block_pos,
            dense_chain,
            chain_len,
            params,
            break_points,
        )
    }

    /// Build the 8-instance §7.3 publics vector for a uniform-t=0
    /// DexFinalProof: `[depositIdentifierHash, finalLayerHistoricalHashRoot,
    /// voucherNominalFr, tokenTypeFr, ephemeralPubkey, salted_X_start,
    /// salted_Y_end, salt_commitment]`. In the uniform case
    /// `salted_X_start == salted_Y_end`.
    #[cfg(test)]
    fn make_v2_instances(
        v: &VoucherFields,
        final_root_fr: Fr,
        ephemeral_pubkey: Fr,
        tw: &TwoLevelWitnesses,
    ) -> Vec<Fr> {
        let salt = compute_salt_native(v.sk_u);
        let salt_commitment = compute_salt_commitment_native(salt);
        let salted = compute_salted_block_id_native(salt, &tw.block_id);
        vec![
            v.expected_poseidon_hash,
            final_root_fr,
            v.voucher_nominal_val,
            v.token_type_val,
            ephemeral_pubkey,
            salted, // salted_X_start
            salted, // salted_Y_end (== salted_X_start under t=0)
            salt_commitment,
        ]
    }

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
            let circuit = make_v2_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
                dense_chain,
                1,
                params.clone(),
            );

            let instances = make_v2_instances(v, final_root_fr, ephemeral_pubkey, &tw);

            println!("Running MockProver...");
            let prover = MockProver::<Fr>::run(K, &circuit, vec![instances])
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
            let circuit = make_v2_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
                dense_chain,
                t,
                params.clone(),
            );

            let instances = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);

            println!("Running MockProver for T={}...", t);
            let prover = MockProver::<Fr>::run(K, &circuit, vec![instances])
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
        let keygen_circuit = make_v2_circuit(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            &tw,
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

            let prover_circuit = make_v2_prover_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
                dense_chain,
                chain_len,
                params.clone(),
                break_points.clone(),
            );

            let start = Instant::now();
            let instance_fr = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);
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
        let keygen_circuit = make_v2_circuit(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            &tw,
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

            let prover_circuit = make_v2_prover_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
                dense_chain,
                chain_len,
                params.clone(),
                break_points.clone(),
            );

            let instance_fr = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);
            // §7.3 V2: 8 Fr publics.
            assert_eq!(instance_fr.len(), 8);

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

            // 8 Fr × 32 bytes LE = 256 B (was 224 B before splitting the
            // salted endpoints); tvm-sdk decodes via Fr::from_bytes_le
            // (byte-exact symmetric).
            let mut instances_bytes: Vec<u8> = Vec::with_capacity(8 * 32);
            for fr in &instance_fr {
                instances_bytes.extend_from_slice(fr.to_repr().as_ref());
            }
            assert_eq!(instances_bytes.len(), 256);

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
            let measure_circuit = make_v2_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
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
            let keygen_circuit = make_v2_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
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
            let prover_circuit = make_v2_prover_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
                dense_chain.clone(),
                1,
                params,
                break_points,
            );

            let start = Instant::now();
            let instance_fr = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);
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
            let circuit = make_v2_circuit(
                v.sk_u,
                ephemeral_pubkey,
                v.entries.clone(),
                &tw,
                dense_chain,
                1,
                params.clone(),
            );

            let instances = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);

            println!("Running MockProver...");
            let prover = MockProver::<Fr>::run(K, &circuit, vec![instances])
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

    // -------------------------------------------------------------------
    // V2 cross-thread (X ≠ Y) positive test
    // -------------------------------------------------------------------

    /// Build a V2 DarkDexCircuitNew from a cross-thread (X ≠ Y) witness.
    /// X-side leaf-8 opens a distinct depth-4 SHA tree from the Y-side
    /// block anchor; the two block_ids differ.
    #[cfg(test)]
    fn make_v2_circuit_cross_thread(
        sk_u: Fr,
        ephemeral_pubkey: Fr,
        entries: [BocFlattenData; 2],
        ctw: &V2CrossThreadWitness,
        dense_chain: Vec<DenseChainLink>,
        chain_len: usize,
        params: BaseCircuitParams,
    ) -> DarkDexCircuitNew {
        DarkDexCircuitNew::new(
            sk_u,
            ephemeral_pubkey,
            entries,
            ctw.x_account_dapp_id,
            ctw.x_account_id,
            ctw.x_ext_out_siblings.clone(),
            ctw.x_ext_out_pos,
            ctw.x_block_id,
            ctw.x_block_id_h07_sibling,
            ctw.y_block_id,
            ctw.y_envelope_hash,
            ctw.y_tracked_ext_out_root,
            ctw.y_block_siblings.clone(),
            ctw.y_block_pos,
            dense_chain,
            chain_len,
            params,
        )
    }

    #[test]
    fn test_dark_dex_circuit_new_cross_thread() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let v = load_first_voucher();
        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(2026);

        let ctw = build_v2_cross_thread_witness(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);
        assert_ne!(
            ctw.x_block_id, ctw.y_block_id,
            "cross-thread witness must have distinct X/Y block_ids"
        );

        let (dense_chain, final_root_bytes) = build_dense_chain(ctw.y_blocks_root_level_0, 1, 130);
        let final_root_fr = bytes_to_fr(&final_root_bytes);

        let params = base_circuit_params();
        let ephemeral_pubkey = Fr::from(0xBEEFu64);

        let circuit = make_v2_circuit_cross_thread(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            &ctw,
            dense_chain,
            1,
            params,
        );

        // Build 8-instance publics with the CROSS-THREAD X/Y block ids
        // (they differ, so salted_X_start ≠ salted_Y_end).
        let salt = compute_salt_native(v.sk_u);
        let salt_commitment = compute_salt_commitment_native(salt);
        let salted_x_start = compute_salted_block_id_native(salt, &ctw.x_block_id);
        let salted_y_end = compute_salted_block_id_native(salt, &ctw.y_block_id);
        assert_ne!(salted_x_start, salted_y_end);
        let instances = vec![
            v.expected_poseidon_hash,
            final_root_fr,
            v.voucher_nominal_val,
            v.token_type_val,
            ephemeral_pubkey,
            salted_x_start,
            salted_y_end,
            salt_commitment,
        ];

        println!("Cross-thread MockProver...");
        let prover = MockProver::<Fr>::run(K, &circuit, vec![instances])
            .unwrap();
        prover.assert_satisfied();
        println!("Cross-thread V2 test passed");
    }

    // -------------------------------------------------------------------
    // V2 negative tests: each mutates one witness / public input and
    // expects MockProver::verify() to fail.
    // -------------------------------------------------------------------

    #[test]
    fn test_dark_dex_circuit_new_bad_h07_sibling() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let v = load_first_voucher();
        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(11);

        let mut tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);
        // Corrupt the h07 sibling AFTER v2_x_block_id was already
        // derived from the original one; the depth-4 SHA opening will
        // now yield a root ≠ x_block_id, so the assert_depth4 gadget
        // must fail.
        tw.v2_x_block_id_h07_sibling[0] ^= 0x01;

        let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
        let final_root_fr = bytes_to_fr(&final_root_bytes);

        let params = base_circuit_params();
        let ephemeral_pubkey = Fr::from(0xDEADu64);
        let circuit = make_v2_circuit(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            &tw,
            dense_chain,
            1,
            params,
        );

        let instances = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);
        let prover = MockProver::<Fr>::run(K, &circuit, vec![instances]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected verify() to fail with corrupted h07 sibling"
        );
    }

    #[test]
    fn test_dark_dex_circuit_new_bad_ephemeral_pubkey() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let v = load_first_voucher();
        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(22);
        let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);

        let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
        let final_root_fr = bytes_to_fr(&final_root_bytes);

        let params = base_circuit_params();
        // Prover witnesses one pubkey…
        let prover_eph = Fr::from(0xDEADu64);
        let circuit = make_v2_circuit(
            v.sk_u,
            prover_eph,
            v.entries.clone(),
            &tw,
            dense_chain,
            1,
            params,
        );

        // …but the public instance claims a DIFFERENT pubkey.
        let mut instances = make_v2_instances(&v, final_root_fr, prover_eph, &tw);
        instances[4] = Fr::from(0xBEEFu64); // ephemeral_pubkey slot

        let prover = MockProver::<Fr>::run(K, &circuit, vec![instances]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected verify() to fail with mismatched ephemeral_pubkey public"
        );
    }

    #[test]
    fn test_dark_dex_circuit_new_bad_salted_x_start() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let v = load_first_voucher();
        let dense_hasher = DensePoseidonHasher::new();
        let mut rng = StdRng::seed_from_u64(33);
        let tw = build_two_level_tree(&v.repr_hash, &mut rng, &dense_hasher, 128, 130);

        let (dense_chain, final_root_bytes) = build_dense_chain(tw.blocks_root_level_0, 1, 130);
        let final_root_fr = bytes_to_fr(&final_root_bytes);

        let params = base_circuit_params();
        let ephemeral_pubkey = Fr::from(0xDEADu64);
        let circuit = make_v2_circuit(
            v.sk_u,
            ephemeral_pubkey,
            v.entries.clone(),
            &tw,
            dense_chain,
            1,
            params,
        );

        // Corrupt the salted_X_start public (index 5).
        let mut instances = make_v2_instances(&v, final_root_fr, ephemeral_pubkey, &tw);
        instances[5] = instances[5] + Fr::from(1u64);

        let prover = MockProver::<Fr>::run(K, &circuit, vec![instances]).unwrap();
        assert!(
            prover.verify().is_err(),
            "expected verify() to fail with corrupted salted_X_start public"
        );
    }
}
