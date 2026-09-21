//! `gen_hermez_kzg_and_multi_hop_keys` — build Hermez-anchored KZG bytes +
//! full `MultiHopProofCircuit` keygen artifact set (VK, PK, break_points) at
//! the canonical K=17 / 200-advice shape.
//!
//! All four snarks in a bundle share topology (same gate layout, same
//! `H_HOPS_PER_PROOF`, `is_active` handled inside the loop body), so a single
//! VK/PK/breakpoints triple is valid for every snark_idx ∈ 0..N_BUNDLE.
//!
//! ## Flow
//!
//! Same 4-phase shape as `gen_hermez_kzg_and_dark_dex_keys`:
//!   1. Cache the Hermez ptau
//!   2. Read + verify K=20 anchor + downsize to `--k`
//!   3. Defense-in-depth A/B/C checks on `g[0]` / `g2` / `s_g2`
//!   4. Keygen + prove + verify against a `synth_chain(SEED, K_HOPS)` snark
//!
//! Emits under `<out>/`:
//!   - `kzg_bytes.rs`                         — paste-ready `KZG_G0/G2/S_G2` consts
//!   - `multi_hop_k17_vk_bytes.rs`            — paste-ready `MULTI_HOP_VK_BYTES` const
//!   - `multi_hop_k17_vk.bin`                 — binary VK (RawBytesUnchecked)
//!   - `multi_hop_k17_pk.bin`                 — binary PK (RawBytesUnchecked)
//!   - `multi_hop_k17_break_points.json`      — break_points
//!   - `multi_hop_k17_config_params.json`     — `BaseCircuitParams`
//!   - `hermez_kzg_bn254_<k>.srs`             — halo2 raw SRS at `k`
//!
//! ## Usage
//! ```bash
//! cargo run --release --bin gen_hermez_kzg_and_multi_hop_keys -- --k 17 --out ./generated_multihop
//! ```

use std::fs;
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine, G2Affine};
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};

use dex_halo2_circuit::kzg_source::{self, KzgSource};
use dex_halo2_circuit::multi_hop_proof::{MultiHopProofCircuit, MultiHopWitness};
use dex_halo2_circuit::multi_hop_witness::{H_HOPS_PER_PROOF, N_BUNDLE};
use dex_halo2_circuit::test_helpers::{split_into_bundle_snarks, synth_chain};

use gosh_zk_snark_halo2_utils::ptau::{emit_rust_const_byte_array, KzgVerifierBytes};

/// Canonical MultiHopProofCircuit `k`. Matches the bundle-suite tests
/// (test_bundle_e2e / test_bundle_negative / test_bundle_stress*).
const DEFAULT_K: u32 = 17;

/// Seed for `synth_chain(seed, K_HOPS)`. Choice is arbitrary — circuit shape
/// is chain-content-independent; the seed only affects witness values.
const SYNTH_CHAIN_SEED: u64 = 0xBEEF_5EEDu64;
/// Real hops per bundle used for the round-trip fixture. `H_HOPS_PER_PROOF`
/// == 5, so snark 0 is fully active and 1..3 fully inactive — this exercises
/// both branches (active gates + is_active-gated inactive branches) inside
/// the loop body during keygen.
const K_HOPS: usize = H_HOPS_PER_PROOF;

// ---------------------------------------------------------------------------
// Emitted-artifact filenames
// ---------------------------------------------------------------------------

const KZG_BYTES_FILENAME: &str = "kzg_bytes.rs";
const MULTI_HOP_VK_RS_FILENAME: &str = "multi_hop_k17_vk_bytes.rs";
const MULTI_HOP_VK_BIN_FILENAME: &str = "multi_hop_k17_vk.bin";
const MULTI_HOP_PK_BIN_FILENAME: &str = "multi_hop_k17_pk.bin";
const MULTI_HOP_BREAK_POINTS_FILENAME: &str = "multi_hop_k17_break_points.json";
const MULTI_HOP_CONFIG_PARAMS_FILENAME: &str = "multi_hop_k17_config_params.json";
const HERMEZ_SRS_FILENAME_FMT: &str = "hermez_kzg_bn254_{k}.srs";

const CONST_NAME_KZG_G0: &str = "KZG_G0_BYTES";
const CONST_NAME_KZG_G2: &str = "KZG_G2_BYTES";
const CONST_NAME_KZG_S_G2: &str = "KZG_S_G2_BYTES";
const CONST_NAME_MULTI_HOP_VK: &str = "MULTI_HOP_VK_BYTES";

/// `BaseCircuitParams` for the MultiHop snark — matches the bundle tests'
/// `bundle_circuit_params()` (K=17, 200 advice, lookup_bits=16).
fn multi_hop_circuit_params(k: usize) -> BaseCircuitParams {
    BaseCircuitParams {
        k,
        num_advice_per_phase: vec![200],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![14],
        lookup_bits: Some(16),
        num_instance_columns: 1,
    }
}

/// Project a single `HopWitness` into `MultiHopWitness`. Mirrors the identical
/// helper that lives inline in each `tests/test_bundle_*.rs` — inlined here to
/// keep the bin self-contained (test-side dedup is a separate cleanup).
fn hop_to_multi_hop(
    h: &dex_halo2_circuit::multi_hop_witness::HopWitness,
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

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Derive KZG verifier bytes + MultiHopProofCircuit VK from the Hermez K=20 ptau"
)]
struct Args {
    /// Target circuit `k` (must be in `1..=20`). Canonical value is 17.
    #[arg(long, default_value_t = DEFAULT_K)]
    k: u32,

    /// Output directory for generated artifacts.
    #[arg(long, default_value = "./generated_multihop")]
    out: PathBuf,

    /// Override the ptau cache path.
    #[arg(long)]
    ptau_cache: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match KzgSource::from_env() {
        KzgSource::Hermez => {}
        KzgSource::GenSrs => eprintln!(
            "WARNING: DEX_KZG_SOURCE=gen_srs — emitted keys will be INSECURE (self-generated SRS)."
        ),
    }

    let mut args = Args::parse();
    assert!(
        (1..=20).contains(&args.k),
        "--k must be in 1..=20 (Hermez ptau is K=20 depth)"
    );

    let initial_cwd = std::env::current_dir()?;
    args.out = absolutize(&initial_cwd, &args.out);
    if let Some(ref p) = args.ptau_cache {
        std::env::set_var(kzg_source::ENV_PTAU_CACHE, absolutize(&initial_cwd, p));
    }
    // MultiHop path doesn't touch vouchers.txt, so no chdir needed.

    fs::create_dir_all(&args.out)?;

    // --- 1. + 2. ---------------------------------------------------------
    eprintln!("[1+2/4] Loading Hermez-anchored SRS at k={}...", args.k);
    let srs = kzg_source::load_hermez_srs(args.k);

    // --- 3. --------------------------------------------------------------
    let verifier_bytes = verifier_bytes_from_params(&srs);
    eprintln!("[3/4] Running defense-in-depth checks A/B/C...");
    check_g0_matches_generator(&verifier_bytes.g0);
    check_g2_matches_generator(&verifier_bytes.g2);
    check_s_g2_on_curve(&verifier_bytes.s_g2);
    eprintln!("      A/B/C passed.");

    // --- 4. --------------------------------------------------------------
    eprintln!(
        "[4/4] Keygen + prove + verify on synth_chain(seed=0x{:x}, K_HOPS={})...",
        SYNTH_CHAIN_SEED, K_HOPS,
    );
    let artifacts = keygen_and_roundtrip(&srs, args.k as usize)?;

    // --- 5. --------------------------------------------------------------
    write_kzg_bytes_file(&args.out, &verifier_bytes)?;
    write_vk_bytes_file(&args.out, &artifacts.vk_bytes, args.k)?;
    write_vk_bin(&args.out, &artifacts.vk_bytes)?;
    write_pk_bin(&args.out, &artifacts.pk_bytes)?;
    write_break_points_json(&args.out, &artifacts.break_points_json)?;
    write_config_params_json(&args.out, args.k as usize)?;
    write_downsized_srs(&args.out, args.k, &srs_to_raw_bytes(&srs))?;

    eprintln!();
    eprintln!("== SUCCESS ==");
    eprintln!("Generated files in {}:", args.out.display());
    eprintln!("  {}", KZG_BYTES_FILENAME);
    eprintln!("  {} ({} bytes)", MULTI_HOP_VK_RS_FILENAME, artifacts.vk_bytes.len());
    eprintln!("  {} ({} B)", MULTI_HOP_VK_BIN_FILENAME, artifacts.vk_bytes.len());
    eprintln!("  {} ({} B)", MULTI_HOP_PK_BIN_FILENAME, artifacts.pk_bytes.len());
    eprintln!("  {} ({} B)", MULTI_HOP_BREAK_POINTS_FILENAME, artifacts.break_points_json.len());
    eprintln!("  {} (BaseCircuitParams)", MULTI_HOP_CONFIG_PARAMS_FILENAME);
    eprintln!("  {}", hermez_srs_filename(args.k));
    eprintln!();
    eprintln!("Same VK/PK/breakpoints apply to all N_BUNDLE={} snarks (shared topology).", N_BUNDLE);
    Ok(())
}

// ---------------------------------------------------------------------------
// Keygen + prove/verify round-trip
// ---------------------------------------------------------------------------

struct KeygenArtifacts {
    vk_bytes: Vec<u8>,
    pk_bytes: Vec<u8>,
    break_points_json: String,
}

fn keygen_and_roundtrip(
    srs: &ParamsKZG<Bn256>,
    k: usize,
) -> Result<KeygenArtifacts, Box<dyn std::error::Error>> {
    let chain = synth_chain(SYNTH_CHAIN_SEED, K_HOPS);
    let snarks = split_into_bundle_snarks(&chain);

    let params = multi_hop_circuit_params(k);

    // Use snark 0 (fully-active at K_HOPS=5) for keygen — same gate topology
    // as inactive snarks because the loop body is unconditional.
    let keygen_hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
        std::array::from_fn(|i| hop_to_multi_hop(&snarks[0].hops[i]));
    let keygen_circuit =
        MultiHopProofCircuit::new(chain.sk_u, keygen_hops, 0, params.clone());

    let t = Instant::now();
    let vk = keygen_vk(srs, &keygen_circuit)?;
    eprintln!("      keygen_vk: {:?}", t.elapsed());

    let t = Instant::now();
    let pk = keygen_pk(srs, vk.clone(), &keygen_circuit)?;
    eprintln!("      keygen_pk: {:?}", t.elapsed());

    let break_points = keygen_circuit
        .base_circuit_builder
        .borrow()
        .break_points();

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytesUnchecked)?;
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::RawBytesUnchecked)?;
    let break_points_json = serde_json::to_string(&break_points)?;

    // Sanity round-trip: prove + verify snark 0 (all-active).
    let snark = &snarks[0];
    let hops: [MultiHopWitness; H_HOPS_PER_PROOF] =
        std::array::from_fn(|i| hop_to_multi_hop(&snark.hops[i]));
    let first_salted = snark.hops[0].salted_start_block_id;
    let last_salted = snark.hops[H_HOPS_PER_PROOF - 1].salted_end_block_id;
    let instances = vec![first_salted, last_salted, snark.salt_commitment];
    let prover_circuit = MultiHopProofCircuit::new_for_proving(
        chain.sk_u,
        hops,
        0,
        params.clone(),
        break_points.clone(),
    );

    let t = Instant::now();
    let proof_bytes = gen_proof_with_instances(srs, &pk, prover_circuit, &[&instances]);
    eprintln!("      prove: {:?} ({} B)", t.elapsed(), proof_bytes.len());

    let t = Instant::now();
    check_proof_with_instances(srs, &vk, &proof_bytes, &[&instances], true);
    eprintln!("      verify: {:?}", t.elapsed());
    eprintln!("      OK — proof verifies against Hermez-derived SRS.");

    Ok(KeygenArtifacts {
        vk_bytes,
        pk_bytes,
        break_points_json,
    })
}

// ---------------------------------------------------------------------------
// SRS → verifier-bytes extraction (identical to sibling bin)
// ---------------------------------------------------------------------------

fn verifier_bytes_from_params(srs: &ParamsKZG<Bn256>) -> KzgVerifierBytes {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;

    let g0_point: G1Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G1::generator().to_affine();
    let mut g0 = [0u8; 64];
    let mut buf = Vec::with_capacity(64);
    g0_point.write_raw(&mut buf).unwrap();
    g0.copy_from_slice(&buf);
    let mut g2 = [0u8; 128];
    let mut buf = Vec::with_capacity(128);
    srs.g2().write_raw(&mut buf).unwrap();
    g2.copy_from_slice(&buf);
    let mut s_g2 = [0u8; 128];
    let mut buf = Vec::with_capacity(128);
    srs.s_g2().write_raw(&mut buf).unwrap();
    s_g2.copy_from_slice(&buf);
    KzgVerifierBytes { g0, g2, s_g2 }
}

fn srs_to_raw_bytes(srs: &ParamsKZG<Bn256>) -> Vec<u8> {
    let mut buf = Vec::new();
    srs.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked)
        .expect("SRS write_custom must not fail");
    buf
}

// ---------------------------------------------------------------------------
// Defense-in-depth A/B/C (identical to sibling bin)
// ---------------------------------------------------------------------------

fn check_g0_matches_generator(g0: &[u8; 64]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
    let expected: G1Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G1::generator().to_affine();
    let mut expected_bytes = Vec::with_capacity(64);
    expected.write_raw(&mut expected_bytes).unwrap();
    assert_eq!(g0.as_slice(), expected_bytes.as_slice(),
        "Hermez g[0] bytes do not match halo2-base G1Affine::generator() bytes");
}

fn check_g2_matches_generator(g2: &[u8; 128]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
    let expected: G2Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G2::generator().to_affine();
    let mut expected_bytes = Vec::with_capacity(128);
    expected.write_raw(&mut expected_bytes).unwrap();
    assert_eq!(g2.as_slice(), expected_bytes.as_slice(),
        "Hermez g2 bytes do not match halo2-base G2Affine::generator() bytes");
}

fn check_s_g2_on_curve(s_g2: &[u8; 128]) {
    use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
    let mut cursor = Cursor::new(&s_g2[..]);
    let mut buf = Vec::with_capacity(128);
    cursor.read_to_end(&mut buf).unwrap();
    let point = G2Affine::from_raw_bytes(&buf)
        .expect("s_g2 bytes did not decode as an on-curve G2Affine");
    let inf: G2Affine = G2Affine::default();
    assert_ne!(format!("{:?}", point), format!("{:?}", inf),
        "s_g2 unexpectedly decoded to identity");
}

// ---------------------------------------------------------------------------
// File emission
// ---------------------------------------------------------------------------

fn write_kzg_bytes_file(out: &Path, v: &KzgVerifierBytes) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("// Generated by dex-halo2-circuit::gen_hermez_kzg_and_multi_hop_keys.\n");
    s.push_str("// Anchored in Hermez Perpetual Powers of Tau K=20 ceremony.\n\n");
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_KZG_G0,
        "`g[0]` (64 B uncompressed BN254 G1Affine).",
        &v.g0,
    ));
    s.push('\n');
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_KZG_G2,
        "`g2` (128 B uncompressed BN254 G2Affine).",
        &v.g2,
    ));
    s.push('\n');
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_KZG_S_G2,
        "`[s]·G2` (128 B). Ceremony-specific.",
        &v.s_g2,
    ));
    let path = out.join(KZG_BYTES_FILENAME);
    fs::write(&path, s)?;
    eprintln!("      Wrote {}", path.display());
    Ok(())
}

fn write_vk_bytes_file(out: &Path, vk_bytes: &[u8], k: u32) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("// Generated by dex-halo2-circuit::gen_hermez_kzg_and_multi_hop_keys.\n");
    s.push_str(&format!(
        "// Verifying key for MultiHopProofCircuit at k={}, generated against the\n",
        k
    ));
    s.push_str("// Hermez-anchored KZG SRS above. Instance vector: 3 elements\n");
    s.push_str("// [first_salted_start_block_id, last_salted_end_block_id, salt_commitment].\n");
    s.push_str("// Shared across all N_BUNDLE snarks.\n\n");
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_MULTI_HOP_VK,
        "VerifyingKey<G1Affine> serialized with SerdeFormat::RawBytesUnchecked.",
        vk_bytes,
    ));
    let path = out.join(MULTI_HOP_VK_RS_FILENAME);
    fs::write(&path, s)?;
    eprintln!("      Wrote {} ({} VK bytes)", path.display(), vk_bytes.len());
    Ok(())
}

fn write_vk_bin(out: &Path, vk_bytes: &[u8]) -> std::io::Result<()> {
    let path = out.join(MULTI_HOP_VK_BIN_FILENAME);
    fs::write(&path, vk_bytes)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), vk_bytes.len());
    Ok(())
}

fn write_pk_bin(out: &Path, pk_bytes: &[u8]) -> std::io::Result<()> {
    let path = out.join(MULTI_HOP_PK_BIN_FILENAME);
    let file = fs::File::create(&path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(pk_bytes)?;
    writer.flush()?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), pk_bytes.len());
    Ok(())
}

fn write_break_points_json(out: &Path, json: &str) -> std::io::Result<()> {
    let path = out.join(MULTI_HOP_BREAK_POINTS_FILENAME);
    fs::write(&path, json)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), json.len());
    Ok(())
}

fn write_config_params_json(out: &Path, k: usize) -> std::io::Result<()> {
    let params = multi_hop_circuit_params(k);
    let json = serde_json::to_string_pretty(&params).unwrap();
    let path = out.join(MULTI_HOP_CONFIG_PARAMS_FILENAME);
    fs::write(&path, json)?;
    eprintln!("      Wrote {}", path.display());
    Ok(())
}

fn write_downsized_srs(out: &Path, k: u32, raw: &[u8]) -> std::io::Result<()> {
    let path = out.join(hermez_srs_filename(k));
    let mut f = fs::File::create(&path)?;
    f.write_all(raw)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), raw.len());
    Ok(())
}

fn hermez_srs_filename(k: u32) -> String {
    HERMEZ_SRS_FILENAME_FMT.replace("{k}", &k.to_string())
}

fn absolutize(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
}
