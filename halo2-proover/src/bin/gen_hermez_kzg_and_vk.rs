//! `gen_hermez_kzg_and_vk` — build Hermez-anchored KZG bytes + circuit VK.
//!
//! Purpose: replace the self-generated KZG SRS constants in
//! `tvm_vm/src/executor/zk_halo2_utils.rs` (`KZG_G0_BYTES`, `KZG_G2_BYTES`,
//! `KZG_S_G2_BYTES`, `DARK_DEX_VK_BYTES`) with material anchored in the
//! community-audited Hermez Perpetual Powers of Tau ceremony.
//!
//! Flow (mirrors `bridge/scripts/bootstrap_hermez_srs.sh` but everything
//! happens in-process — no shell binary):
//!
//! 1. Ensure `~/.cache/halo2-kzg-srs/powersOfTau28_hez_final_20.ptau` is
//!    present (download from the Polygon zkEVM GCS mirror if not, size
//!    check only — the SHA-256 anchor on the derived raw SRS is what
//!    matters for trust).
//! 2. `gosh_zk_snark_halo2_utils::ptau::read_hermez_ptau_and_verify(reader,
//!    desired_k)` — parses ptau, materializes the K=20 raw SRS, hashes it
//!    and asserts the SHA-256 matches the Hermez anchor, extracts the
//!    k-invariant `g[0] / g2 / s_g2` verifier points, then downsizes to
//!    `desired_k` and re-serializes.
//! 3. Four defense-in-depth checks against the concern that
//!    `halo2_kzg_srs`'s halo2curves (PSE 0.3.1) differs from halo2-base's
//!    halo2curves (bytes still cross correctly, but we sanity-check them):
//!      A. `g[0]` bytes equal halo2-base's `G1Affine::generator()` bytes
//!         (BN254 curve constant).
//!      B. `g2` bytes equal halo2-base's `G2Affine::generator()` bytes.
//!      C. `s_g2` bytes decode as an on-curve `G2Affine` via the checked
//!         `from_raw_bytes` path (subgroup / on-curve check).
//!      D. Full prove + verify round-trip on a real fixture succeeds.
//!    Check D is the strongest — it exercises the full stack against the
//!    reconstructed SRS.
//! 4. Emit paste-ready Rust `const` snippets under `<out>/`:
//!      - `kzg_bytes.rs`
//!      - `dark_dex_w128_vk_bytes.rs`
//!      - `dark_dex_w128_config_params.json`
//!    plus `hermez_kzg_bn254_<k>.srs` (halo2 canonical raw SRS at requested `k`)
//!    for downstream prover use.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use halo2_base::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::testing::check_proof_with_instances;

use gosh_zk_snark_halo2_utils::ptau::{
    emit_rust_const_byte_array, read_hermez_ptau_and_verify, HERMEZ_K20_PTAU_SIZE,
    HERMEZ_K20_PTAU_URL, HERMEZ_K20_RAW_SRS_SHA256,
};

use halo2_proover::{compute_fr_instances_from_json, config_params_default, Prover};

const FIXTURE_L1_H277: &str = include_str!("../../dex_fixture_live_L1_H277_S0.json");

/// Cache filename for the downloaded ptau.
const PTAU_FILENAME: &str = "powersOfTau28_hez_final_20.ptau";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Derive KZG verifier bytes + DarkDex VK from the Hermez K=20 ptau"
)]
struct Args {
    /// Target circuit `k` (must be in `1..=20`). `DarkDexCircuitNew` needs
    /// `k=19`; use anything smaller for tests.
    #[arg(long)]
    k: u32,

    /// Output directory for the generated Rust const snippets, VK blob and
    /// downsized SRS.
    #[arg(long, default_value = "./generated")]
    out: PathBuf,

    /// Override the ptau cache path.
    #[arg(long)]
    ptau_cache: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    assert!(
        (1..=20).contains(&args.k),
        "--k must be in 1..=20 (Hermez ptau is K=20 depth)"
    );

    fs::create_dir_all(&args.out)?;

    // --- 1. ptau cache ---------------------------------------------------
    let ptau_path = args.ptau_cache.clone().unwrap_or_else(default_ptau_cache);
    ensure_ptau_present(&ptau_path)?;

    // --- 2. read + verify anchor + downsize -----------------------------
    eprintln!("[2/4] Reading ptau, verifying K=20 SHA-256 anchor, downsizing to k={}...", args.k);
    let t0 = Instant::now();
    let mut reader = fs::File::open(&ptau_path)?;
    let material = read_hermez_ptau_and_verify(&mut reader, args.k);
    eprintln!(
        "      OK — K=20 SHA-256 matches ({}); raw SRS at k={} is {} bytes; took {:.1}s",
        hex_lower(&material.k20_sha256),
        args.k,
        material.raw_srs.len(),
        t0.elapsed().as_secs_f64(),
    );
    assert_eq!(material.k20_sha256, HERMEZ_K20_RAW_SRS_SHA256);

    // --- 3. cross-halo2curves defense-in-depth checks -------------------
    eprintln!("[3/4] Running defense-in-depth checks...");
    check_g0_matches_generator(&material.verifier_bytes.g0);
    check_g2_matches_generator(&material.verifier_bytes.g2);
    check_s_g2_on_curve(&material.verifier_bytes.s_g2);
    eprintln!("      A/B/C passed (generator equality + s_g2 on-curve).");

    // --- 4. full prove+verify round-trip --------------------------------
    eprintln!("[4/4] Full round-trip: keygen + prove + verify on live fixture (k={})...", args.k);
    let t0 = Instant::now();
    let mut prover = Prover::new_with_srs_bytes(&material.raw_srs, None)?;
    let proof_out = prover.generate_proof(FIXTURE_L1_H277)?;
    let vk = prover
        .verifying_key()
        .expect("VK should be populated after generate_proof");
    let instances = compute_fr_instances_from_json(FIXTURE_L1_H277)?;
    let proof_bytes = hex::decode(&proof_out.proof)?;
    check_proof_with_instances(prover.srs(), vk, &proof_bytes, &[&instances], true);
    eprintln!(
        "      OK — proof verifies against Hermez-derived SRS; took {:.1}s",
        t0.elapsed().as_secs_f64(),
    );

    // --- 5. serialize VK and emit const snippets ------------------------
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytesUnchecked)?;

    write_kzg_bytes_file(&args.out, &material.verifier_bytes)?;
    write_vk_bytes_file(&args.out, &vk_bytes)?;
    write_config_params_json(&args.out)?;
    write_downsized_srs(&args.out, args.k, &material.raw_srs)?;

    eprintln!();
    eprintln!("== SUCCESS ==");
    eprintln!("Generated files in {}:", args.out.display());
    eprintln!("  kzg_bytes.rs                       ({} bytes of KZG_G0/G2/S_G2 consts)", 64 + 128 + 128);
    eprintln!("  dark_dex_w128_vk_bytes.rs          (DARK_DEX_VK_BYTES: [u8; {}])", vk_bytes.len());
    eprintln!("  dark_dex_w128_config_params.json   (BaseCircuitParams at k={})", args.k);
    eprintln!("  hermez_kzg_bn254_{}.srs            (halo2 raw SRS at k={}, {} bytes)", args.k, args.k, material.raw_srs.len());
    eprintln!();
    eprintln!("Paste kzg_bytes.rs and dark_dex_w128_vk_bytes.rs contents into");
    eprintln!("tvm_vm/src/executor/zk_halo2_utils.rs to replace the self-generated");
    eprintln!("KZG constants with Hermez-anchored ones.");

    Ok(())
}

// ---------------------------------------------------------------------------
// Step helpers
// ---------------------------------------------------------------------------

fn default_ptau_cache() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home).join(".cache/halo2-kzg-srs").join(PTAU_FILENAME)
}

fn ensure_ptau_present(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() == HERMEZ_K20_PTAU_SIZE {
            eprintln!("[1/4] Ptau cached at {} ({} bytes) — OK", path.display(), meta.len());
            return Ok(());
        }
        eprintln!(
            "[1/4] Ptau at {} has wrong size ({} vs expected {}) — re-downloading",
            path.display(),
            meta.len(),
            HERMEZ_K20_PTAU_SIZE
        );
    } else {
        eprintln!("[1/4] Ptau not cached — downloading from {}", HERMEZ_K20_PTAU_URL);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut resp = reqwest::blocking::get(HERMEZ_K20_PTAU_URL)?.error_for_status()?;
    let mut file = fs::File::create(path)?;
    let bytes = std::io::copy(&mut resp, &mut file)?;
    eprintln!("      Downloaded {} bytes to {}", bytes, path.display());
    let meta = fs::metadata(path)?;
    assert_eq!(
        meta.len(),
        HERMEZ_K20_PTAU_SIZE,
        "Downloaded ptau size mismatch: expected {} got {}",
        HERMEZ_K20_PTAU_SIZE,
        meta.len(),
    );
    Ok(())
}

/// Check A: `g[0]` bytes equal halo2-base's `G1Affine::generator()` bytes.
///
/// BN254 `g[0]` is a curve constant across every well-formed BN254 KZG SRS.
/// If this check passes, the halo2_kzg_srs → halo2-base bytes-boundary
/// preserves G1 identity encoding.
fn check_g0_matches_generator(g0: &[u8; 64]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    let expected: G1Affine = halo2_base::halo2_proofs::halo2curves::bn256::G1::generator().to_affine();
    let mut expected_bytes = Vec::with_capacity(64);
    expected.write_raw(&mut expected_bytes).unwrap();
    assert_eq!(
        expected_bytes.len(),
        64,
        "unexpected G1Affine raw length {}",
        expected_bytes.len()
    );
    assert_eq!(
        g0.as_slice(),
        expected_bytes.as_slice(),
        "Hermez g[0] bytes do not match halo2-base G1Affine::generator() bytes"
    );
}

/// Check B: `g2` bytes equal halo2-base's `G2Affine::generator()` bytes.
fn check_g2_matches_generator(g2: &[u8; 128]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    let expected: G2Affine = halo2_base::halo2_proofs::halo2curves::bn256::G2::generator().to_affine();
    let mut expected_bytes = Vec::with_capacity(128);
    expected.write_raw(&mut expected_bytes).unwrap();
    assert_eq!(
        expected_bytes.len(),
        128,
        "unexpected G2Affine raw length {}",
        expected_bytes.len()
    );
    assert_eq!(
        g2.as_slice(),
        expected_bytes.as_slice(),
        "Hermez g2 bytes do not match halo2-base G2Affine::generator() bytes"
    );
}

/// Check C: `s_g2` bytes decode as an on-curve `G2Affine` under halo2-base's
/// halo2curves. This uses the checked `from_raw_bytes` (not `_unchecked`),
/// which validates the point lies on the curve.
fn check_s_g2_on_curve(s_g2: &[u8; 128]) {
    let mut cursor = Cursor::new(&s_g2[..]);
    let mut buf = Vec::with_capacity(128);
    cursor.read_to_end(&mut buf).unwrap();
    let point = G2Affine::from_raw_bytes(&buf)
        .expect("s_g2 bytes did not decode as an on-curve G2Affine");
    // Sanity: not the identity.
    let inf: G2Affine = G2Affine::default();
    assert_ne!(
        format!("{:?}", point),
        format!("{:?}", inf),
        "s_g2 unexpectedly decoded to identity"
    );
}

// ---------------------------------------------------------------------------
// File emission
// ---------------------------------------------------------------------------

fn write_kzg_bytes_file(
    out: &Path,
    v: &gosh_zk_snark_halo2_utils::ptau::KzgVerifierBytes,
) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("// Generated by dexdo-halo2-kit::halo2-proover::gen_hermez_kzg_and_vk.\n");
    s.push_str("// Anchored in the Hermez Perpetual Powers of Tau ceremony\n");
    s.push_str("// (powersOfTau28_hez_final_20.ptau, K=20 raw SRS SHA-256\n");
    s.push_str("// 80394564e2598883dbb5d7d61630287f34e29cdd806d7ef74f68acc6bffeb608).\n");
    s.push_str("// Paste into tvm_vm/src/executor/zk_halo2_utils.rs.\n\n");
    s.push_str(&emit_rust_const_byte_array(
        "KZG_G0_BYTES",
        "`g[0]` (64-byte uncompressed BN254 G1Affine). Curve constant.",
        &v.g0,
    ));
    s.push('\n');
    s.push_str(&emit_rust_const_byte_array(
        "KZG_G2_BYTES",
        "`g2` (128-byte uncompressed BN254 G2Affine). Curve constant.",
        &v.g2,
    ));
    s.push('\n');
    s.push_str(&emit_rust_const_byte_array(
        "KZG_S_G2_BYTES",
        "`[s]·G2` (128-byte uncompressed BN254 G2Affine). Ceremony-specific:\nencodes the Hermez trapdoor `s`. Verification only succeeds against\nproofs generated from the matching Hermez K=20 raw SRS.",
        &v.s_g2,
    ));
    let path = out.join("kzg_bytes.rs");
    fs::write(&path, s)?;
    eprintln!("      Wrote {}", path.display());
    Ok(())
}

fn write_vk_bytes_file(out: &Path, vk_bytes: &[u8]) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("// Generated by dexdo-halo2-kit::halo2-proover::gen_hermez_kzg_and_vk.\n");
    s.push_str("// Verifying key for DarkDexCircuit (dark_dex_w128) at k=19 with the\n");
    s.push_str("// BaseCircuitParams in dark_dex_w128_config_params.json, generated\n");
    s.push_str("// against the Hermez-anchored KZG SRS above.\n");
    s.push_str("// Paste into tvm_vm/src/executor/zk_halo2_utils.rs.\n\n");
    s.push_str(&emit_rust_const_byte_array(
        "DARK_DEX_VK_BYTES",
        "VerifyingKey<G1Affine> serialized with SerdeFormat::RawBytesUnchecked.",
        vk_bytes,
    ));
    let path = out.join("dark_dex_w128_vk_bytes.rs");
    fs::write(&path, s)?;
    eprintln!("      Wrote {} ({} VK bytes)", path.display(), vk_bytes.len());
    Ok(())
}

fn write_config_params_json(out: &Path) -> std::io::Result<()> {
    let params = config_params_default();
    let json = serde_json::to_string_pretty(&params).unwrap();
    let path = out.join("dark_dex_w128_config_params.json");
    fs::write(&path, json)?;
    eprintln!("      Wrote {}", path.display());
    Ok(())
}

fn write_downsized_srs(out: &Path, k: u32, raw: &[u8]) -> std::io::Result<()> {
    let path = out.join(format!("hermez_kzg_bn254_{k}.srs"));
    let mut f = fs::File::create(&path)?;
    f.write_all(raw)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), raw.len());
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
