use gosh_dark_dex_halo2_new_circuit::boc_helper::{serialize_cells_tree_root_first, BocFlattenData};
use gosh_dark_dex_halo2_new_circuit::dark_dex_circuit_new::DarkDexCircuitNew;
use gosh_dark_dex_halo2_new_circuit::poseidon::poseidon_hash;

use gosh_dense_balanced_tree::{
    bytes_to_fr, compute_root_native, fr_to_bytes, preprocess_dense_proof, DenseChainLink,
    MAX_CHAIN_LEN,
};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::gen_proof_with_instances;

use serde::{Deserialize, Serialize};
use tvm_block::{Deserializable, Message, Serializable};

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const K: u32 = 19;

const PK_CACHE_FILE: &str = "pk_cache.bin";
const BP_CACHE_FILE: &str = "break_points_cache.bin";
const VK_CACHE_FILE: &str = "vk_cache.bin";

const EVENT_SK_U_COMMIT_START: usize = 6;
const EVENT_SK_U_COMMIT_END: usize = 38;
const EVENT_VOUCHER_NOMINAL_START: usize = 38;
const EVENT_VOUCHER_NOMINAL_END: usize = 70;
const EVENT_TOKEN_TYPE_START: usize = 70;
const EVENT_TOKEN_TYPE_END: usize = 74;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("Fixture parsing failed: {0}")]
    Fixture(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Keygen failed: {0}")]
    Keygen(String),

    #[error("Proof generation failed: {0}")]
    ProofGen(String),
}

// ---------------------------------------------------------------------------
// Public output types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOutput {
    pub proof: String,
    pub pub_inputs_hex: String,
    pub deposit_identifier_hash: String,
    pub final_layer_historical_hash_root: String,
    pub voucher_nominal: String,
    pub token_type: String,
    pub ephemeral_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceValues {
    pub deposit_identifier_hash: String,
    pub final_layer_historical_hash_root: String,
    pub voucher_nominal: String,
    pub token_type: String,
    pub ephemeral_pubkey: String,
}

// ---------------------------------------------------------------------------
// Public fixture types (consumers can construct programmatically)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainLinkJson {
    pub active: bool,
    pub siblings_hex: Vec<String>,
    pub position: usize,
    pub leaf_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFixtureJson {
    pub description: String,
    pub sk_u_hex: String,
    pub ephemeral_pubkey_hex: String,
    pub event_boc_base64: String,
    pub events_proof_siblings_hex: Vec<String>,
    pub events_proof_position: usize,
    pub account_dapp_id_hex: String,
    pub account_id_hex: String,
    pub block_id_hex: String,
    pub envelope_hash_hex: String,
    pub block_proof_siblings_hex: Vec<String>,
    pub block_proof_position: usize,
    pub num_active_chain_steps: usize,
    pub dense_chain: Vec<ChainLinkJson>,
}

// ---------------------------------------------------------------------------
// Internal parsed representation
// ---------------------------------------------------------------------------

struct ParsedFixture {
    sk_u: Fr,
    ephemeral_pubkey: Fr,
    entries: [BocFlattenData; 2],
    events_proof_siblings: Vec<[u8; 32]>,
    events_proof_position: usize,
    account_dapp_id: [u8; 32],
    account_id: [u8; 32],
    block_id: [u8; 32],
    envelope_hash_bytes: [u8; 32],
    block_proof_siblings: Vec<[u8; 32]>,
    block_proof_position: usize,
    dense_chain: Vec<DenseChainLink>,
    num_active_chain_steps: usize,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn base_circuit_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: K as usize,
        num_advice_per_phase: vec![4],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![1],
        lookup_bits: Some(18),
        num_instance_columns: 1,
    }
}

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

fn bytes_to_fr_be(data: &[u8]) -> Fr {
    let mut val = Fr::from(0u64);
    for &byte in data {
        val = val * Fr::from(256u64) + Fr::from(byte as u64);
    }
    val
}

fn poseidon_hash_96_native(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(a);
    buf[32..64].copy_from_slice(b);
    buf[64..96].copy_from_slice(c);

    let chunk = |start: usize, len: usize| -> Fr {
        let mut b32 = [0u8; 32];
        b32[..len].copy_from_slice(&buf[start..start + len]);
        bytes_to_fr(&b32)
    };

    let c0 = chunk(0, 31);
    let c1 = chunk(31, 31);
    let c2 = chunk(62, 31);
    let c3 = chunk(93, 3);

    let hash = poseidon_hash(&[c0, c1, c2, c3]);
    fr_to_bytes(hash)
}

fn instances_to_values(instances: &[Fr]) -> InstanceValues {
    InstanceValues {
        deposit_identifier_hash: hex::encode(instances[0].to_repr()),
        final_layer_historical_hash_root: hex::encode(instances[1].to_repr()),
        voucher_nominal: hex::encode(instances[2].to_repr()),
        token_type: hex::encode(instances[3].to_repr()),
        ephemeral_pubkey: hex::encode(instances[4].to_repr()),
    }
}

// ---------------------------------------------------------------------------
// Fixture parsing
// ---------------------------------------------------------------------------

fn parse_fixture(json: &DexFixtureJson) -> Result<ParsedFixture, ProverError> {
    let sk_u = hex_to_fr(&json.sk_u_hex)?;

    let msg = Message::construct_from_base64(&json.event_boc_base64)
        .map_err(|e| ProverError::Fixture(format!("BOC parse failed: {e}")))?;
    let msg_cell = msg
        .serialize()
        .map_err(|e| ProverError::Fixture(format!("BOC serialize failed: {e}")))?;
    let serialized = serialize_cells_tree_root_first(&msg_cell)
        .map_err(|e| ProverError::Fixture(format!("BOC flatten failed: {e}")))?;
    if serialized.len() != 2 {
        return Err(ProverError::Fixture(format!(
            "expected 2 cells in BOC, got {}",
            serialized.len()
        )));
    }
    let entries: [BocFlattenData; 2] = [serialized[0].clone(), serialized[1].clone()];

    let events_proof_siblings: Vec<[u8; 32]> = json
        .events_proof_siblings_hex
        .iter()
        .map(|s| hex_to_32(s))
        .collect::<Result<_, _>>()?;

    let block_proof_siblings: Vec<[u8; 32]> = json
        .block_proof_siblings_hex
        .iter()
        .map(|s| hex_to_32(s))
        .collect::<Result<_, _>>()?;

    let account_dapp_id = hex_to_32(&json.account_dapp_id_hex)?;
    let account_id = hex_to_32(&json.account_id_hex)?;
    let block_id = hex_to_32(&json.block_id_hex)?;
    let envelope_hash_bytes = hex_to_32(&json.envelope_hash_hex)?;

    let mut dense_chain: Vec<DenseChainLink> = json
        .dense_chain
        .iter()
        .map(|link| {
            let siblings: Vec<[u8; 32]> = link
                .siblings_hex
                .iter()
                .map(|s| hex_to_32(s))
                .collect::<Result<_, _>>()?;
            Ok(DenseChainLink {
                active: link.active,
                siblings,
                position: link.position,
                leaf_native: hex_to_32(&link.leaf_hex)?,
            })
        })
        .collect::<Result<_, ProverError>>()?;

    if dense_chain.len() > MAX_CHAIN_LEN {
        return Err(ProverError::Fixture(format!(
            "dense chain too long: {} > {}",
            dense_chain.len(),
            MAX_CHAIN_LEN
        )));
    }

    // Pad chain to MAX_CHAIN_LEN
    if dense_chain.len() < MAX_CHAIN_LEN {
        let repr_hash = &entries[0].repr_hash;
        let ext_msg_leaf = poseidon_hash_96_native(&account_dapp_id, &account_id, repr_hash);
        let ext_out_root_bytes = if events_proof_siblings.is_empty() {
            ext_msg_leaf
        } else {
            let events_proof = preprocess_dense_proof(
                ext_msg_leaf,
                &events_proof_siblings,
                json.events_proof_position,
            );
            fr_to_bytes(compute_root_native(&events_proof))
        };
        let block_leaf =
            poseidon_hash_96_native(&block_id, &envelope_hash_bytes, &ext_out_root_bytes);
        let block_proof = preprocess_dense_proof(
            block_leaf,
            &block_proof_siblings,
            json.block_proof_position,
        );
        let root_1_fr = compute_root_native(&block_proof);

        let mut current = root_1_fr;
        for link in dense_chain.iter().filter(|l| l.active) {
            let proof =
                preprocess_dense_proof(link.leaf_native, &link.siblings, link.position);
            current = compute_root_native(&proof);
        }

        let padding_leaf = fr_to_bytes(current);
        let depth = if !dense_chain.is_empty() {
            dense_chain[0].siblings.len()
        } else {
            block_proof_siblings.len()
        };

        while dense_chain.len() < MAX_CHAIN_LEN {
            dense_chain.push(DenseChainLink::inactive(padding_leaf, depth));
        }
    }

    Ok(ParsedFixture {
        sk_u,
        ephemeral_pubkey: bytes_to_fr_be(&hex_to_32(&json.ephemeral_pubkey_hex)?),
        entries,
        events_proof_siblings,
        events_proof_position: json.events_proof_position,
        account_dapp_id,
        account_id,
        block_id,
        envelope_hash_bytes,
        block_proof_siblings,
        block_proof_position: json.block_proof_position,
        dense_chain,
        num_active_chain_steps: json.num_active_chain_steps,
    })
}

// ---------------------------------------------------------------------------
// Instance computation
// ---------------------------------------------------------------------------

fn compute_instances(parsed: &ParsedFixture) -> Vec<Fr> {
    let child_data = &parsed.entries[1].cell_repr_data;

    let sk_u_commit_bytes: [u8; 32] = child_data[EVENT_SK_U_COMMIT_START..EVENT_SK_U_COMMIT_END]
        .try_into()
        .unwrap();
    let sk_u_commit_val = Fr::from_repr(sk_u_commit_bytes).unwrap();
    let voucher_nominal_val =
        bytes_to_fr_be(&child_data[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END]);
    let token_type_val =
        bytes_to_fr_be(&child_data[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END]);
    let ephemeral_pubkey_val = parsed.ephemeral_pubkey;

    let poseidon_commitment =
        poseidon_hash(&[voucher_nominal_val, token_type_val, parsed.sk_u, sk_u_commit_val]);

    let block_leaf_native = {
        let repr_hash = &parsed.entries[0].repr_hash;
        let ext_msg_leaf = poseidon_hash_96_native(
            &parsed.account_dapp_id,
            &parsed.account_id,
            repr_hash,
        );

        let ext_out_root_bytes = if parsed.events_proof_siblings.is_empty() {
            ext_msg_leaf
        } else {
            let events_proof = preprocess_dense_proof(
                ext_msg_leaf,
                &parsed.events_proof_siblings,
                parsed.events_proof_position,
            );
            fr_to_bytes(compute_root_native(&events_proof))
        };

        poseidon_hash_96_native(
            &parsed.block_id,
            &parsed.envelope_hash_bytes,
            &ext_out_root_bytes,
        )
    };

    let block_proof = preprocess_dense_proof(
        block_leaf_native,
        &parsed.block_proof_siblings,
        parsed.block_proof_position,
    );
    let root_1_fr = compute_root_native(&block_proof);

    let final_root = if parsed.num_active_chain_steps == 0 {
        root_1_fr
    } else {
        let mut current = root_1_fr;
        for link in parsed
            .dense_chain
            .iter()
            .take(parsed.num_active_chain_steps)
        {
            assert!(link.active);
            let proof =
                preprocess_dense_proof(link.leaf_native, &link.siblings, link.position);
            current = compute_root_native(&proof);
        }
        current
    };

    vec![
        poseidon_commitment,
        final_root,
        voucher_nominal_val,
        token_type_val,
        ephemeral_pubkey_val,
    ]
}

// ---------------------------------------------------------------------------
// PK caching (private)
// ---------------------------------------------------------------------------

fn save_pk(pk: &ProvingKey<G1Affine>, path: &Path) -> Result<(), ProverError> {
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    pk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
        .map_err(|e| ProverError::Io(std::io::Error::other(format!("PK write failed: {e}"))))?;
    Ok(())
}

fn load_pk(path: &Path, circuit_params: BaseCircuitParams) -> Result<ProvingKey<G1Affine>, ProverError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    ProvingKey::read::<_, DarkDexCircuitNew>(
        &mut reader,
        SerdeFormat::RawBytesUnchecked,
        circuit_params,
    )
    .map_err(|e| ProverError::Io(std::io::Error::other(format!("PK read failed: {e}"))))
}

fn save_break_points(break_points: &MultiPhaseThreadBreakPoints, path: &Path) -> Result<(), ProverError> {
    let serialized = serde_json::to_string(break_points)
        .map_err(|e| ProverError::Io(std::io::Error::other(format!("break_points serialize: {e}"))))?;
    fs::write(path, serialized)?;
    Ok(())
}

fn load_break_points(path: &Path) -> Result<MultiPhaseThreadBreakPoints, ProverError> {
    let data = fs::read_to_string(path)?;
    serde_json::from_str(&data)
        .map_err(|e| ProverError::Io(std::io::Error::other(format!("break_points deserialize: {e}"))))
}

// ---------------------------------------------------------------------------
// Prover (stateful, holds SRS + PK in memory)
// ---------------------------------------------------------------------------

pub struct Prover {
    srs: halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG<
        halo2_base::halo2_proofs::halo2curves::bn256::Bn256,
    >,
    pk: Option<ProvingKey<G1Affine>>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    cache_dir: Option<PathBuf>,
}

impl Prover {
    /// Create a new prover, loading SRS via `gen_srs(19)`.
    ///
    /// If `cache_dir` is provided and contains cached PK/break_points files,
    /// they are loaded immediately. Otherwise PK is generated on the first
    /// call to `generate_proof`.
    pub fn new(cache_dir: Option<&Path>) -> Result<Self, ProverError> {
        eprintln!("Loading SRS (K={K})...");
        let srs = gen_srs(K);

        let cache_dir = cache_dir.map(PathBuf::from);
        let (pk, break_points) = match &cache_dir {
            Some(dir) => {
                let pk_path = dir.join(PK_CACHE_FILE);
                let bp_path = dir.join(BP_CACHE_FILE);
                if pk_path.exists() && bp_path.exists() {
                    eprintln!("Loading cached PK and break_points...");
                    let pk = load_pk(&pk_path, base_circuit_params())?;
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

    /// Generate a DarkDex ZK proof from a fixture JSON string.
    ///
    /// On first call (if PK is not cached), performs keygen and caches the
    /// result. Subsequent calls reuse the in-memory PK.
    pub fn generate_proof(&mut self, fixture_json: &str) -> Result<ProofOutput, ProverError> {
        let json: DexFixtureJson = serde_json::from_str(fixture_json)
            .map_err(|e| ProverError::Fixture(format!("JSON parse: {e}")))?;

        let parsed = parse_fixture(&json)?;
        let instances = compute_instances(&parsed);
        let params = base_circuit_params();

        // Keygen if needed
        if self.pk.is_none() {
            eprintln!("No cached PK, running keygen...");
            let keygen_circuit = DarkDexCircuitNew::new(
                parsed.sk_u,
                parsed.ephemeral_pubkey,
                parsed.entries.clone(),
                parsed.events_proof_siblings.clone(),
                parsed.events_proof_position,
                parsed.account_dapp_id,
                parsed.account_id,
                parsed.block_id,
                parsed.envelope_hash_bytes,
                parsed.block_proof_siblings.clone(),
                parsed.block_proof_position,
                parsed.dense_chain.clone(),
                parsed.num_active_chain_steps,
                params.clone(),
            );

            let vk = keygen_vk(&self.srs, &keygen_circuit)
                .map_err(|e| ProverError::Keygen(format!("keygen_vk: {e}")))?;

            // Save VK if cache dir available
            if let Some(dir) = &self.cache_dir {
                let vk_path = dir.join(VK_CACHE_FILE);
                let file = fs::File::create(&vk_path)?;
                let mut writer = BufWriter::new(file);
                vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
                    .map_err(|e| ProverError::Keygen(format!("VK write: {e}")))?;
            }

            let pk = keygen_pk(&self.srs, vk, &keygen_circuit)
                .map_err(|e| ProverError::Keygen(format!("keygen_pk: {e}")))?;

            let bp = keygen_circuit
                .base_circuit_builder
                .borrow()
                .break_points();

            // Cache to disk
            if let Some(dir) = &self.cache_dir {
                save_pk(&pk, &dir.join(PK_CACHE_FILE))?;
                save_break_points(&bp, &dir.join(BP_CACHE_FILE))?;
            }

            self.pk = Some(pk);
            self.break_points = Some(bp);
        }

        let pk = self.pk.as_ref().unwrap();
        let break_points = self.break_points.as_ref().unwrap().clone();

        // Build prover circuit
        let prover_circuit = DarkDexCircuitNew::new_for_proving(
            parsed.sk_u,
            parsed.ephemeral_pubkey,
            parsed.entries,
            parsed.events_proof_siblings,
            parsed.events_proof_position,
            parsed.account_dapp_id,
            parsed.account_id,
            parsed.block_id,
            parsed.envelope_hash_bytes,
            parsed.block_proof_siblings,
            parsed.block_proof_position,
            parsed.dense_chain,
            parsed.num_active_chain_steps,
            params,
            break_points,
        );

        eprintln!("Generating proof...");
        let proof_bytes = gen_proof_with_instances(&self.srs, pk, prover_circuit, &[&instances]);
        eprintln!("  Proof: {} bytes", proof_bytes.len());

        // Build output
        // 5 public instance Fr elements concatenated as LE bytes (5×32=160B)
        // for direct use by the TVM ZKHALO2VERIFY on-chain verifier
        let mut pub_inputs_bytes = Vec::with_capacity(160);
        for inst in &instances {
            pub_inputs_bytes.extend_from_slice(&inst.to_repr());
        }

        let values = instances_to_values(&instances);
        Ok(ProofOutput {
            proof: hex::encode(&proof_bytes),
            pub_inputs_hex: hex::encode(&pub_inputs_bytes),
            deposit_identifier_hash: values.deposit_identifier_hash,
            final_layer_historical_hash_root: values.final_layer_historical_hash_root,
            voucher_nominal: values.voucher_nominal,
            token_type: values.token_type,
            ephemeral_pubkey: values.ephemeral_pubkey,
        })
    }
}

// ---------------------------------------------------------------------------
// Stateless public API
// ---------------------------------------------------------------------------

/// Compute the 5 public instance values without generating a proof.
///
/// Fast (milliseconds). No SRS or PK needed.
pub fn compute_instances_from_json(fixture_json: &str) -> Result<InstanceValues, ProverError> {
    let json: DexFixtureJson = serde_json::from_str(fixture_json)
        .map_err(|e| ProverError::Fixture(format!("JSON parse: {e}")))?;
    let parsed = parse_fixture(&json)?;
    let instances = compute_instances(&parsed);
    Ok(instances_to_values(&instances))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_L1: &str = include_str!("../dex_fixture_live_L1_H277_S0.json");
    const FIXTURE_L2: &str = include_str!("../dex_fixture_live_L2_H1904_S0.json");

    #[test]
    fn test_parse_fixture_l1() {
        let json: DexFixtureJson = serde_json::from_str(FIXTURE_L1).unwrap();
        let parsed = parse_fixture(&json).unwrap();
        assert_eq!(parsed.num_active_chain_steps, 1);
        assert_eq!(parsed.dense_chain.len(), MAX_CHAIN_LEN);
    }

    #[test]
    fn test_parse_fixture_l2() {
        let json: DexFixtureJson = serde_json::from_str(FIXTURE_L2).unwrap();
        let parsed = parse_fixture(&json).unwrap();
        assert_eq!(parsed.num_active_chain_steps, 2);
        assert_eq!(parsed.dense_chain.len(), MAX_CHAIN_LEN);
    }

    #[test]
    fn test_compute_instances_l1() {
        let values = compute_instances_from_json(FIXTURE_L1).unwrap();
        assert!(!values.deposit_identifier_hash.is_empty());
        assert!(!values.final_layer_historical_hash_root.is_empty());
        assert!(!values.voucher_nominal.is_empty());
        assert!(!values.token_type.is_empty());
        assert!(!values.ephemeral_pubkey.is_empty());
    }

    #[test]
    fn test_compute_instances_deterministic() {
        let v1 = compute_instances_from_json(FIXTURE_L1).unwrap();
        let v2 = compute_instances_from_json(FIXTURE_L1).unwrap();
        assert_eq!(v1.deposit_identifier_hash, v2.deposit_identifier_hash);
        assert_eq!(
            v1.final_layer_historical_hash_root,
            v2.final_layer_historical_hash_root
        );
    }

    #[test]
    fn test_different_fixtures_different_instances() {
        let v1 = compute_instances_from_json(FIXTURE_L1).unwrap();
        let v2 = compute_instances_from_json(FIXTURE_L2).unwrap();
        assert_ne!(v1.deposit_identifier_hash, v2.deposit_identifier_hash);
    }

    #[test]
    fn test_fixture_json_roundtrip() {
        let json: DexFixtureJson = serde_json::from_str(FIXTURE_L1).unwrap();
        let serialized = serde_json::to_string(&json).unwrap();
        let _: DexFixtureJson = serde_json::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let result = compute_instances_from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_returns_error() {
        let mut json: serde_json::Value = serde_json::from_str(FIXTURE_L1).unwrap();
        json["sk_u_hex"] = serde_json::Value::String("zzzz".into());
        let result = compute_instances_from_json(&json.to_string());
        assert!(result.is_err());
    }
}
