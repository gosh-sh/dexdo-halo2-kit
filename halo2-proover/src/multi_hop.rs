//! MultiHopProver — halo2 KZG prover for one bundle-slot MultiHopProof snark.
//!
//! Consumes a [`MultiHopSnarkWitnessJson`] plus the bundle-shared `sk_u` and
//! emits a proof + the three public instances (`salted_start_block_id`,
//! `salted_end_block_id`, `salt_commitment`) that the on-chain bundle
//! verifier consumes.
//!
//! ## Keygen sharing
//!
//! All `N_BUNDLE` snarks in a bundle share the same circuit topology, so a
//! single `MultiHopProver` reuses one PK across every snark it produces.
//! The bundle orchestrator (`bundle.rs`) constructs one `MultiHopProver`
//! and calls `generate_proof` `N_BUNDLE` times.
//!
//! Circuit parameters mirror `gosh_dark_dex_halo2_new_circuit::bin::gen_hermez_kzg_and_multi_hop_keys`
//! (K=17, 200 advice cols, lookup_bits=16) — the same shape the on-chain
//! `MULTI_HOP_VK_BYTES` was generated against.

use gosh_dark_dex_halo2_new_circuit::multi_hop_proof::{
    MultiHopProofCircuit, MultiHopWitness, MULTI_HOP_PUBLIC_LEN,
};
use gosh_dark_dex_halo2_new_circuit::multi_hop_witness::{
    BLOCK_MERKLE_DEPTH, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH,
};
use gosh_dark_dex_halo2_new_circuit::salt::{compute_salt_commitment_native, compute_salt_native};
use gosh_dark_dex_halo2_new_circuit::kzg_source::load_srs;
use dex_witness_export::bundle_witness::{HopWitnessJson, MultiHopSnarkWitnessJson};

use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};

use serde::{Deserialize, Serialize};

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use crate::ProverError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MULTI_HOP_K: u32 = 17;

const MULTI_HOP_PK_CACHE_FILE: &str = "multi_hop_pk_cache.bin";
const MULTI_HOP_BP_CACHE_FILE: &str = "multi_hop_break_points_cache.bin";
const MULTI_HOP_VK_CACHE_FILE: &str = "multi_hop_vk_cache.bin";

// ---------------------------------------------------------------------------
// Public output type
// ---------------------------------------------------------------------------

/// One MultiHopProof snark's output — proof bytes + the three public
/// instances the on-chain bundle verifier consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiHopProofOutput {
    /// Raw proof bytes, hex-encoded.
    pub proof: String,
    /// `MULTI_HOP_PUBLIC_LEN * 32` LE bytes of the public instances,
    /// concatenated in the order `[salted_start, salted_end, salt_commitment]`
    /// per `gosh_dark_dex_halo2_new_circuit::bundle_verifier::multihop_offset`.
    pub pub_inputs_hex: String,
    /// `Fr::to_repr()` LE hex of `salted_start_block_id`.
    pub salted_start_block_id: String,
    /// `Fr::to_repr()` LE hex of `salted_end_block_id`.
    pub salted_end_block_id: String,
    /// `Fr::to_repr()` LE hex of `salt_commitment`.
    pub salt_commitment: String,
    /// Which slot of the bundle this snark occupies (`0..N_BUNDLE`).
    pub bundle_index: u32,
}

// ---------------------------------------------------------------------------
// Circuit params
// ---------------------------------------------------------------------------

/// `BaseCircuitParams` for the MultiHop snark. Byte-identical to
/// `gosh_dark_dex_halo2_new_circuit::bin::gen_hermez_kzg_and_multi_hop_keys::multi_hop_circuit_params`.
fn multi_hop_base_circuit_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: MULTI_HOP_K as usize,
        num_advice_per_phase: vec![200],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![14],
        lookup_bits: Some(16),
        num_instance_columns: 1,
    }
}

// ---------------------------------------------------------------------------
// Hex → witness conversion
// ---------------------------------------------------------------------------

fn hex_to_32(hex_str: &str) -> Result<[u8; 32], ProverError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ProverError::Fixture(format!("invalid hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| ProverError::Fixture(format!("expected 32 bytes, got {}", v.len())))
}

fn hex_to_fr(hex_str: &str) -> Result<Fr, ProverError> {
    let bytes = hex_to_32(hex_str)?;
    Option::from(Fr::from_repr(bytes))
        .ok_or_else(|| ProverError::Fixture("hex value is not a valid Fr element".into()))
}

fn hop_from_json(h: &HopWitnessJson) -> Result<MultiHopWitness, ProverError> {
    let ref_block_id = hex_to_32(&h.ref_block_id_hex)?;
    let block_id = hex_to_32(&h.block_id_hex)?;
    let l7 = hex_to_32(&h.l7_hex)?;

    let mut block_merkle_leaf_proof_l7 = [[0u8; 32]; BLOCK_MERKLE_DEPTH];
    for (i, s) in h.block_merkle_leaf_proof_l7_hex.iter().enumerate() {
        block_merkle_leaf_proof_l7[i] = hex_to_32(s)?;
    }

    let mut proof_block_ref_inner_path = [[0u8; 32]; MAX_PROOF_BLOCK_REFS_DEPTH];
    for (i, s) in h.proof_block_ref_inner_path_hex.iter().enumerate() {
        proof_block_ref_inner_path[i] = hex_to_32(s)?;
    }

    let salted_start_block_id = hex_to_fr(&h.salted_start_block_id_hex)?;
    let salted_end_block_id = hex_to_fr(&h.salted_end_block_id_hex)?;

    Ok(MultiHopWitness {
        is_active: h.is_active,
        ref_block_id,
        block_id,
        l7,
        block_merkle_leaf_proof_l7,
        ref_index: h.ref_index,
        refs_tree_depth: h.refs_tree_depth,
        proof_block_ref_inner_path,
        salted_start_block_id,
        salted_end_block_id,
    })
}

fn hops_from_json(
    hops: &[HopWitnessJson; H_HOPS_PER_PROOF],
) -> Result<[MultiHopWitness; H_HOPS_PER_PROOF], ProverError> {
    // Convert into a Vec first (`?` inside `array::from_fn` is awkward), then
    // fall back to a fixed-size array via TryInto.
    let mut out = Vec::with_capacity(H_HOPS_PER_PROOF);
    for h in hops {
        out.push(hop_from_json(h)?);
    }
    out.try_into()
        .map_err(|_| ProverError::Fixture("hop array length mismatch".into()))
}

// ---------------------------------------------------------------------------
// PK / break-points cache (mirrors the pattern in lib.rs)
// ---------------------------------------------------------------------------

fn save_pk(pk: &ProvingKey<G1Affine>, path: &Path) -> Result<(), ProverError> {
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    pk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
        .map_err(|e| ProverError::Io(std::io::Error::other(format!("PK write failed: {e}"))))?;
    Ok(())
}

fn load_pk(
    path: &Path,
    circuit_params: BaseCircuitParams,
) -> Result<ProvingKey<G1Affine>, ProverError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    ProvingKey::read::<_, MultiHopProofCircuit>(
        &mut reader,
        SerdeFormat::RawBytesUnchecked,
        circuit_params,
    )
    .map_err(|e| ProverError::Io(std::io::Error::other(format!("PK read failed: {e}"))))
}

fn save_break_points(
    break_points: &MultiPhaseThreadBreakPoints,
    path: &Path,
) -> Result<(), ProverError> {
    let serialized = serde_json::to_string(break_points).map_err(|e| {
        ProverError::Io(std::io::Error::other(format!(
            "break_points serialize: {e}"
        )))
    })?;
    fs::write(path, serialized)?;
    Ok(())
}

fn load_break_points(path: &Path) -> Result<MultiPhaseThreadBreakPoints, ProverError> {
    let data = fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|e| {
        ProverError::Io(std::io::Error::other(format!(
            "break_points deserialize: {e}"
        )))
    })
}

// ---------------------------------------------------------------------------
// Prover (stateful, holds SRS + PK in memory)
// ---------------------------------------------------------------------------

/// Stateful MultiHopProof prover. Holds the Hermez KZG SRS at K=17 plus a
/// cached PK and break-points, so `N_BUNDLE` calls in a row only pay
/// keygen once.
pub struct MultiHopProver {
    srs: ParamsKZG<Bn256>,
    pk: Option<ProvingKey<G1Affine>>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    cache_dir: Option<PathBuf>,
}

impl MultiHopProver {
    /// Create a new prover, loading the Hermez KZG SRS at [`MULTI_HOP_K`].
    ///
    /// If `cache_dir` is provided and contains cached PK/break_points files,
    /// they are loaded immediately. Otherwise PK is generated on the first
    /// call to [`Self::generate_proof`].
    pub fn new(cache_dir: Option<&Path>) -> Result<Self, ProverError> {
        eprintln!("Loading Hermez SRS (K={MULTI_HOP_K}) for MultiHopProof...");
        let srs = load_srs(MULTI_HOP_K);

        let cache_dir = cache_dir.map(PathBuf::from);
        let (pk, break_points) = match &cache_dir {
            Some(dir) => {
                let pk_path = dir.join(MULTI_HOP_PK_CACHE_FILE);
                let bp_path = dir.join(MULTI_HOP_BP_CACHE_FILE);
                if pk_path.exists() && bp_path.exists() {
                    eprintln!("Loading cached MultiHop PK and break_points...");
                    let pk = load_pk(&pk_path, multi_hop_base_circuit_params())?;
                    let bp = load_break_points(&bp_path)?;
                    (Some(pk), Some(bp))
                } else {
                    (None, None)
                }
            }
            None => (None, None),
        };

        Ok(Self {
            srs,
            pk,
            break_points,
            cache_dir,
        })
    }

    /// Generate one MultiHopProof snark proof.
    ///
    /// * `snark` — the per-slot witness (bundle_index, hops, salt_commitment).
    /// * `sk_u_hex` — the bundle-shared voucher secret (LE Fr hex, matches the
    ///   top-level `BundleWitnessJson.sk_u_hex`). The prover recomputes
    ///   `salt = Poseidon(DOMAIN_TAG_HOP_SALT_FR, sk_u)` and
    ///   `salt_commitment = Poseidon([salt])` locally and cross-checks it
    ///   against `snark.salt_commitment_hex` before proving.
    ///
    /// On first call (if PK is not cached) performs keygen and caches the
    /// result. Subsequent calls reuse the in-memory PK.
    pub fn generate_proof(
        &mut self,
        snark: &MultiHopSnarkWitnessJson,
        sk_u_hex: &str,
    ) -> Result<MultiHopProofOutput, ProverError> {
        let sk_u = hex_to_fr(sk_u_hex)?;

        // Cross-check the JSON salt_commitment against the native derivation.
        let expected_salt = compute_salt_native(sk_u);
        let expected_salt_commitment = compute_salt_commitment_native(expected_salt);
        let json_salt_commitment = hex_to_fr(&snark.salt_commitment_hex)?;
        if json_salt_commitment != expected_salt_commitment {
            return Err(ProverError::Fixture(format!(
                "snark[{}].salt_commitment does not match Poseidon(salt) derived from sk_u",
                snark.bundle_index
            )));
        }

        let hops = hops_from_json(&snark.hops)?;
        let params = multi_hop_base_circuit_params();

        // Public instances follow `bundle_verifier::multihop_offset`:
        //   [0] = hops[0].salted_start_block_id
        //   [1] = hops[H_HOPS_PER_PROOF-1].salted_end_block_id
        //   [2] = salt_commitment
        let salted_start = hops[0].salted_start_block_id;
        let salted_end = hops[H_HOPS_PER_PROOF - 1].salted_end_block_id;
        let instances = vec![salted_start, salted_end, expected_salt_commitment];
        debug_assert_eq!(instances.len(), MULTI_HOP_PUBLIC_LEN);

        // Keygen if needed
        if self.pk.is_none() {
            eprintln!("No cached MultiHop PK, running keygen...");
            let keygen_circuit =
                MultiHopProofCircuit::new(sk_u, hops.clone(), snark.bundle_index, params.clone());

            let vk = keygen_vk(&self.srs, &keygen_circuit)
                .map_err(|e| ProverError::Keygen(format!("keygen_vk: {e}")))?;

            // Save VK if cache dir available
            if let Some(dir) = &self.cache_dir {
                let vk_path = dir.join(MULTI_HOP_VK_CACHE_FILE);
                let file = fs::File::create(&vk_path)?;
                let mut writer = BufWriter::new(file);
                vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
                    .map_err(|e| ProverError::Keygen(format!("VK write: {e}")))?;
            }

            let pk = keygen_pk(&self.srs, vk, &keygen_circuit)
                .map_err(|e| ProverError::Keygen(format!("keygen_pk: {e}")))?;

            let bp = keygen_circuit.base_circuit_builder.borrow().break_points();

            if let Some(dir) = &self.cache_dir {
                save_pk(&pk, &dir.join(MULTI_HOP_PK_CACHE_FILE))?;
                save_break_points(&bp, &dir.join(MULTI_HOP_BP_CACHE_FILE))?;
            }

            self.pk = Some(pk);
            self.break_points = Some(bp);
        }

        let pk = self.pk.as_ref().unwrap();
        let break_points = self.break_points.as_ref().unwrap().clone();

        let prover_circuit = MultiHopProofCircuit::new_for_proving(
            sk_u,
            hops,
            snark.bundle_index,
            params,
            break_points,
        );

        eprintln!(
            "Generating MultiHopProof snark [{}]...",
            snark.bundle_index
        );
        let proof_bytes = gen_proof_with_instances(&self.srs, pk, prover_circuit, &[&instances]);
        eprintln!("  Proof: {} bytes", proof_bytes.len());

        let mut pub_inputs_bytes = Vec::with_capacity(MULTI_HOP_PUBLIC_LEN * 32);
        for inst in instances.iter() {
            let repr: [u8; 32] = inst.to_repr();
            pub_inputs_bytes.extend_from_slice(&repr);
        }

        Ok(MultiHopProofOutput {
            proof: hex::encode(&proof_bytes),
            pub_inputs_hex: hex::encode(&pub_inputs_bytes),
            salted_start_block_id: hex::encode(salted_start.to_repr()),
            salted_end_block_id: hex::encode(salted_end.to_repr()),
            salt_commitment: hex::encode(expected_salt_commitment.to_repr()),
            bundle_index: snark.bundle_index,
        })
    }

    /// In-process self-verify — decodes `output.proof` and runs the halo2
    /// KZG verifier against the same SRS + PK.get_vk(). Panics if the proof
    /// does not verify (mirrors `check_proof_with_instances` semantics).
    pub fn verify_proof(&self, output: &MultiHopProofOutput) -> Result<(), ProverError> {
        let pk = self
            .pk
            .as_ref()
            .ok_or_else(|| ProverError::Keygen("verify_proof called before PK is loaded".into()))?;
        let proof_bytes = hex::decode(&output.proof)
            .map_err(|e| ProverError::ProofGen(format!("proof hex decode: {e}")))?;
        let salted_start = hex_to_fr(&output.salted_start_block_id)?;
        let salted_end = hex_to_fr(&output.salted_end_block_id)?;
        let salt_commitment = hex_to_fr(&output.salt_commitment)?;
        let instances = vec![salted_start, salted_end, salt_commitment];
        check_proof_with_instances(
            &self.srs,
            pk.get_vk(),
            &proof_bytes,
            &[&instances],
            true,
        );
        Ok(())
    }
}
