use gosh_dark_dex_halo2_new_circuit::boc_helper::{serialize_cells_tree_root_first, BocFlattenData};
use gosh_dark_dex_halo2_new_circuit::dark_dex_circuit_new::DarkDexCircuitNew;
use gosh_dark_dex_halo2_new_circuit::keygen::W128Fixture;
use gosh_dark_dex_halo2_new_circuit::poseidon::poseidon_hash;

use gosh_dense_balanced_tree::{
    bytes_to_fr, compute_root_native, fr_to_bytes, preprocess_dense_proof, DenseChainLink,
    MAX_CHAIN_LEN,
};
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::testing::gen_proof_with_instances;

use gosh_zk_snark_halo2_utils::ptau::{
    default_ptau_cache_path, ensure_hermez_k20_ptau, read_hermez_ptau_and_verify,
    HERMEZ_K20_RAW_SRS_SHA256,
};

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
const SRS_CACHE_FILE: &str = "hermez_kzg_srs_k19.bin";

/// Default URL for the Hermez-anchored K=19 KZG SRS in halo2 canonical raw
/// format. Same material [`Prover::new_with_hermez`] produces, but
/// pre-computed and hosted on the GOSH binaries mirror so consumers skip
/// the ~1.2 GB ptau download + downsize.
pub const DEFAULT_HERMEZ_KZG_SRS_URL: &str =
    "https://binaries.gosh.sh/dexdo/hermez_kzg_bn254_19.srs";

/// Default RNG seed for the synthetic two-level tree in [`Prover::generate_proof_synthetic`].
/// Matches `TWO_LEVEL_TREE_SEED` in `dex-halo2-circuit::bin::gen_hermez_kzg_and_dark_dex_keys`.
pub const DEFAULT_SYNTH_SEED: u64 = 99;

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

/// Blocking HTTP GET → SRS bytes. Streams via `std::io::copy` to avoid the
/// buffered `Response::bytes()` path, which fails on ~64 MB bodies with
/// "error decoding response body". Follows redirects (reqwest default:
/// up to 10 hops).
fn download_srs_bytes(url: &str) -> Result<Vec<u8>, ProverError> {
    let mut resp = reqwest::blocking::get(url)
        .map_err(|e| ProverError::Io(std::io::Error::other(format!("HTTP GET failed: {e}"))))?
        .error_for_status()
        .map_err(|e| ProverError::Io(std::io::Error::other(format!("HTTP status: {e}"))))?;
    let mut buf: Vec<u8> = Vec::new();
    std::io::copy(&mut resp, &mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Prover (stateful, holds SRS + PK in memory)
// ---------------------------------------------------------------------------

pub struct Prover {
    srs: ParamsKZG<Bn256>,
    pk: Option<ProvingKey<G1Affine>>,
    vk: Option<VerifyingKey<G1Affine>>,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    cache_dir: Option<PathBuf>,
}

impl Prover {
    /// **LEGACY / INSECURE.** Create a new prover, loading SRS via `gen_srs(19)` —
    /// a self-generated, deterministic-from-seed KZG SRS whose trapdoor `s` is
    /// knowable. Proofs produced with this SRS **do NOT verify against
    /// production tvm-sdk / USDCBridge**, which are anchored to the Hermez
    /// Perpetual Powers of Tau ceremony.
    ///
    /// Kept only for backward-compat reproduction of pre-Hermez behavior.
    /// Prefer [`Prover::new_with_hermez`] for anything real.
    ///
    /// If `cache_dir` is provided and contains cached PK/break_points files,
    /// they are loaded immediately. Otherwise PK is generated on the first
    /// call to `generate_proof`.
    pub fn new(cache_dir: Option<&Path>) -> Result<Self, ProverError> {
        eprintln!("[LEGACY] Loading self-generated SRS via gen_srs(K={K}) — insecure trapdoor!");
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
            vk: None,
            break_points,
            cache_dir,
        })
    }

    /// Create a new prover from an in-memory SRS blob in halo2 canonical raw
    /// format (`[u32 k LE][g[..] raw][g_lagrange[..] raw][g2 raw][s_g2 raw]`).
    ///
    /// This is what lets a build tool feed a Hermez-derived SRS directly,
    /// bypassing the disk cache path used by `gen_srs`. `cache_dir` still
    /// applies for PK / break_points caching.
    pub fn new_with_srs_bytes(
        raw_srs: &[u8],
        cache_dir: Option<&Path>,
    ) -> Result<Self, ProverError> {
        let mut cursor: &[u8] = raw_srs;
        let srs = ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytesUnchecked)
            .map_err(|e| ProverError::Keygen(format!("SRS parse from bytes: {e}")))?;

        let cache_dir = cache_dir.map(PathBuf::from);
        let (pk, break_points) = match &cache_dir {
            Some(dir) => {
                let pk_path = dir.join(PK_CACHE_FILE);
                let bp_path = dir.join(BP_CACHE_FILE);
                if pk_path.exists() && bp_path.exists() {
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
            vk: None,
            break_points,
            cache_dir,
        })
    }

    /// Create a new prover using the **Hermez Perpetual Powers of Tau K=20**
    /// ceremony as KZG SRS, downsized to `K=19` (the DarkDex W=128 circuit
    /// degree). This is the secure path: the VK produced here matches
    /// `DARK_DEX_W128_VK_BYTES` in tvm-sdk's `zk_halo2_utils.rs` and proofs
    /// verify on-chain (`USDCBridge.sol`).
    ///
    /// Reproduces the SRS-loading flow of
    /// `dex-halo2-circuit::bin::gen_hermez_kzg_and_dark_dex_keys`:
    ///   1. Ensure `~/.cache/halo2-kzg-srs/powersOfTau28_hez_final_20.ptau`
    ///      exists (download from the Polygon zkEVM GCS mirror on cache miss).
    ///   2. `read_hermez_ptau_and_verify` — parse ptau, verify K=20 SHA-256
    ///      anchor, downsize to K=19, re-serialize as halo2 raw SRS.
    ///   3. Delegate to [`Prover::new_with_srs_bytes`].
    ///
    /// `ptau_cache` overrides the default cache location.
    pub fn new_with_hermez(cache_dir: Option<&Path>) -> Result<Self, ProverError> {
        Self::new_with_hermez_from(cache_dir, None)
    }

    /// Variant of [`Prover::new_with_hermez`] that lets the caller pin an
    /// explicit ptau cache path (useful for tests / sandboxed builds).
    pub fn new_with_hermez_from(
        cache_dir: Option<&Path>,
        ptau_cache: Option<&Path>,
    ) -> Result<Self, ProverError> {
        let ptau_path = ptau_cache
            .map(PathBuf::from)
            .unwrap_or_else(default_ptau_cache_path);
        ensure_hermez_k20_ptau(&ptau_path)
            .map_err(|e| ProverError::Keygen(format!("ptau download: {e}")))?;

        eprintln!(
            "Reading Hermez ptau, verifying K=20 SHA-256 anchor, downsizing to k={K}..."
        );
        let mut reader = fs::File::open(&ptau_path)?;
        let material = read_hermez_ptau_and_verify(&mut reader, K);
        if material.k20_sha256 != HERMEZ_K20_RAW_SRS_SHA256 {
            return Err(ProverError::Keygen(
                "Hermez K=20 raw SRS SHA-256 anchor mismatch".into(),
            ));
        }
        eprintln!("  Hermez anchor OK; raw SRS at k={K} is {} bytes", material.raw_srs.len());

        Self::new_with_srs_bytes(&material.raw_srs, cache_dir)
    }

    /// Create a new prover by downloading a pre-computed KZG SRS blob from
    /// `url` (halo2 canonical raw format, ready for
    /// `ParamsKZG::<Bn256>::read_custom(RawBytesUnchecked)`).
    ///
    /// Simpler than [`Prover::new_with_hermez`]: no ~1.2 GB ptau download,
    /// no downsize step — the file at `url` is already the K=19 raw SRS.
    ///
    /// If `url` is `None`, [`DEFAULT_HERMEZ_KZG_SRS_URL`] is used (currently
    /// a Google Drive link hosting the Hermez K=19 KZG SRS; slated to be
    /// swapped for an Andrey Shuvalov mirror).
    ///
    /// Caching behavior:
    ///   * If `cache_dir` contains `hermez_kzg_srs_k19.bin`, it is read from
    ///     disk (no HTTP).
    ///   * Otherwise the URL is fetched via blocking HTTP and, if
    ///     `cache_dir` is provided, cached at that path.
    ///   * PK / break_points caching is delegated to
    ///     [`Prover::new_with_srs_bytes`] — absent PK triggers keygen on the
    ///     first `generate_proof` call.
    pub fn new_with_srs_from_url(
        url: Option<&str>,
        cache_dir: Option<&Path>,
    ) -> Result<Self, ProverError> {
        let url = url.unwrap_or(DEFAULT_HERMEZ_KZG_SRS_URL);

        let srs_bytes = if let Some(dir) = cache_dir {
            let srs_path = dir.join(SRS_CACHE_FILE);
            if srs_path.exists() {
                eprintln!("Loading cached KZG SRS from {}", srs_path.display());
                fs::read(&srs_path)?
            } else {
                fs::create_dir_all(dir)?;
                eprintln!("KZG SRS not cached — downloading from {url}");
                let bytes = download_srs_bytes(url)?;
                fs::write(&srs_path, &bytes)?;
                eprintln!("  Wrote {} bytes to {}", bytes.len(), srs_path.display());
                bytes
            }
        } else {
            eprintln!("No cache_dir — downloading KZG SRS from {url}");
            download_srs_bytes(url)?
        };

        Self::new_with_srs_bytes(&srs_bytes, cache_dir)
    }

    /// Access the in-memory SRS.
    pub fn srs(&self) -> &ParamsKZG<Bn256> {
        &self.srs
    }

    /// Access the verifying key. Populated after the first `generate_proof`
    /// call (or `keygen`).
    pub fn verifying_key(&self) -> Option<&VerifyingKey<G1Affine>> {
        self.vk.as_ref()
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

            let pk = keygen_pk(&self.srs, vk.clone(), &keygen_circuit)
                .map_err(|e| ProverError::Keygen(format!("keygen_pk: {e}")))?;
            self.vk = Some(vk);

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
// Synthetic W=128 fixture JSON emitter
// ---------------------------------------------------------------------------

/// Dump a **synthetic** W=128 fixture in the same `DexFixtureJson` schema that
/// [`Prover::generate_proof`] consumes.
///
/// Live chain-snapshot fixtures are no longer captured — this is the
/// authoritative replacement. Derives everything in-process from
/// `vouchers.txt` (read from CWD) plus a deterministic `rng_seed` for the
/// two-level tree. Sibling counts reflect the real W=128 tree geometry
/// (`HISTORY_PROOF_WINDOW_SIZE = 128`, `BLOCK_TREE_LEAVES = 130`, tree
/// depths ⌈log₂⌉).
///
/// `chain_len ∈ 0..=MAX_CHAIN_LEN`. Only the active links are emitted into
/// `dense_chain[]`; [`Prover::generate_proof`] pads to `MAX_CHAIN_LEN`
/// transparently.
///
/// Returned string is pretty-printed JSON ready to `fs::write` and hand to a
/// third-party consumer.
pub fn dump_synthetic_fixture_json(
    chain_len: usize,
    rng_seed: u64,
) -> Result<String, ProverError> {
    use gosh_dark_dex_halo2_new_circuit::dark_dex_circuit_new::BLOCK_TREE_LEAVES;
    use gosh_dark_dex_halo2_new_circuit::event_data_helper::read_event_data_from_file;
    use gosh_dark_dex_halo2_new_circuit::keygen::build_dense_chain;

    assert!(
        chain_len <= MAX_CHAIN_LEN,
        "chain_len {chain_len} exceeds MAX_CHAIN_LEN {MAX_CHAIN_LEN}"
    );

    // Preserve event_boc_base64 by reading vouchers.txt directly —
    // `W128Fixture::synth` drops it after parsing.
    let events = read_event_data_from_file("vouchers.txt");
    if events.is_empty() {
        return Err(ProverError::Fixture("vouchers.txt is empty".into()));
    }
    let event_boc_base64 = events[0].event_boc.clone();

    let fixture = W128Fixture::synth(rng_seed);
    let (dense_chain, _final_root) =
        build_dense_chain(fixture.tw.blocks_root_level_0, chain_len, BLOCK_TREE_LEAVES);

    // `parse_fixture` decodes ephemeral_pubkey_hex via `bytes_to_fr_be` — BE
    // 32-byte integer. `W128Fixture::synth` sets `Fr::from(0xDEAD)`; encode
    // that as 30 zero bytes + `de ad`.
    let ephemeral_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[30] = 0xDE;
        b[31] = 0xAD;
        b
    };

    let dense_chain_json: Vec<ChainLinkJson> = dense_chain
        .iter()
        .take(chain_len)
        .map(|link| ChainLinkJson {
            active: link.active,
            siblings_hex: link.siblings.iter().map(|s| hex::encode(s)).collect(),
            position: link.position,
            leaf_hex: hex::encode(link.leaf_native),
        })
        .collect();

    let json = DexFixtureJson {
        description: format!(
            "Synthetic W=128 fixture (chain_len={chain_len}, seed={rng_seed}). \
             Sibling shapes match production HISTORY_PROOF_WINDOW_SIZE=128 / \
             BLOCK_TREE_LEAVES=130. See halo2-proover/README.md."
        ),
        sk_u_hex: hex::encode(fixture.voucher.sk_u.to_repr()),
        ephemeral_pubkey_hex: hex::encode(ephemeral_bytes),
        event_boc_base64,
        events_proof_siblings_hex: fixture
            .tw
            .events_siblings
            .iter()
            .map(|s| hex::encode(s))
            .collect(),
        events_proof_position: fixture.tw.events_pos,
        account_dapp_id_hex: hex::encode(fixture.tw.account_dapp_id),
        account_id_hex: hex::encode(fixture.tw.account_id),
        block_id_hex: hex::encode(fixture.tw.block_id),
        envelope_hash_hex: hex::encode(fixture.tw.envelope_hash_bytes),
        block_proof_siblings_hex: fixture
            .tw
            .block_siblings
            .iter()
            .map(|s| hex::encode(s))
            .collect(),
        block_proof_position: fixture.tw.block_pos,
        num_active_chain_steps: chain_len,
        dense_chain: dense_chain_json,
    };

    serde_json::to_string_pretty(&json)
        .map_err(|e| ProverError::Fixture(format!("serialize: {e}")))
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

/// Same as [`compute_instances_from_json`] but returns raw `Fr` elements
/// suitable for feeding into `check_proof_with_instances`.
pub fn compute_fr_instances_from_json(fixture_json: &str) -> Result<Vec<Fr>, ProverError> {
    let json: DexFixtureJson = serde_json::from_str(fixture_json)
        .map_err(|e| ProverError::Fixture(format!("JSON parse: {e}")))?;
    let parsed = parse_fixture(&json)?;
    Ok(compute_instances(&parsed))
}

/// The `BaseCircuitParams` shape used by `DarkDexCircuitNew` at K=19.
/// Mirrors `dark_dex_w128_config_params` in
/// `tvm_vm/src/executor/zk_halo2_utils.rs`.
pub fn config_params_default() -> BaseCircuitParams {
    base_circuit_params()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_L1: &str = include_str!("../dex_fixture_synth_L1.json");
    const FIXTURE_L2: &str = include_str!("../dex_fixture_synth_L2.json");

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
        // L1 and L2 synthetic fixtures share the same voucher (both derived from
        // vouchers.txt[0]), so `deposit_identifier_hash` (voucher-only) matches.
        // The chain-derived `final_layer_historical_hash_root` is what must differ.
        let v1 = compute_instances_from_json(FIXTURE_L1).unwrap();
        let v2 = compute_instances_from_json(FIXTURE_L2).unwrap();
        assert_eq!(v1.deposit_identifier_hash, v2.deposit_identifier_hash);
        assert_ne!(
            v1.final_layer_historical_hash_root,
            v2.final_layer_historical_hash_root
        );
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
