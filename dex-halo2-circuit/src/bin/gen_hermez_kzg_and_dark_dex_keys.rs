//! `gen_hermez_kzg_and_dark_dex_keys` — build Hermez-anchored KZG bytes +
//! full `DarkDexCircuitNew` keygen artifact set (VK, PK, break_points) at the
//! canonical **W=128** circuit shape.
//!
//! Fixture-synthesis is done in-process against real live-voucher data
//! (`vouchers.txt` in CWD). All the machinery is in `crate::keygen` and is
//! shared with the tests, so a change in circuit shape flows through one place.
//!
//! ## Flow
//!
//! 1. Ensure `~/.cache/halo2-kzg-srs/powersOfTau28_hez_final_20.ptau` is
//!    present (download from the Polygon zkEVM GCS mirror if not).
//! 2. `gosh_zk_snark_halo2_utils::ptau::read_hermez_ptau_and_verify(reader,
//!    desired_k)` — parses ptau, materializes the K=20 raw SRS, hashes it and
//!    asserts the SHA-256 matches the Hermez anchor, extracts the k-invariant
//!    `g[0] / g2 / s_g2` verifier points, downsizes to `desired_k` and
//!    re-serializes.
//! 3. Four defense-in-depth checks:
//!      A. `g[0]` bytes equal halo2-base's `G1Affine::generator()` bytes.
//!      B. `g2` bytes equal halo2-base's `G2Affine::generator()` bytes.
//!      C. `s_g2` bytes decode as an on-curve `G2Affine` via the checked
//!         `from_raw_bytes` path.
//!      D. Full prove+verify round-trip on the synthesized W=128 fixture.
//! 4. Emit paste-ready Rust `const` snippets + on-disk key blobs + downsized
//!    SRS under `<out>/`:
//!      - `kzg_bytes.rs`                     — paste-ready `KZG_G0/G2/S_G2` consts
//!      - `dark_dex_w128_vk_bytes.rs`        — paste-ready `DARK_DEX_VK_BYTES` const
//!      - `dark_dex_w128_vk.bin`             — binary VK (RawBytesUnchecked)
//!      - `dark_dex_w128_pk.bin`             — binary PK (RawBytesUnchecked)
//!      - `dark_dex_w128_break_points.json`  — break_points for prover-circuit reconstruction
//!      - `dark_dex_w128_config_params.json` — `BaseCircuitParams` at `k`
//!      - `hermez_kzg_bn254_<k>.srs`         — halo2 raw SRS at `k`
//!
//! With `--gen-instances`, additionally emits a self-contained
//! `dex_instances_for_sdk_tests/` subfolder mirroring the layout produced by
//! the legacy `gen_legacy_gen_srs_dark_dex_keys` bin (kept only for backward-
//! compat reproduction of the pre-Hermez blobs — do NOT ship its output),
//! ready for hand-copy into tvm-sdk unit-test data:
//!      - `dark_dex_w128_vk.bin`                 — same VK bytes as the top-level file
//!      - `dark_dex_w128_L{0,1,2}_proof.bin`     — proof at each chain_len
//!      - `dark_dex_w128_L{0,1,2}_instances.bin` — 5 × 32-byte LE Fr instances
//! Each SDK proof is sanity-verified before being written.
//!
//! ## Usage
//! ```bash
//! # from dex-halo2-circuit/ (CWD must contain vouchers.txt)
//! cargo run --release --bin gen_hermez_kzg_and_dark_dex_keys -- --k 19 --out ./generated
//! # ...or, additionally emit SDK proof/instances subfolder:
//! cargo run --release --bin gen_hermez_kzg_and_dark_dex_keys -- --k 19 --out ./generated --gen-instances
//! ```

use std::fs;
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};

use dex_halo2_circuit::keygen::{base_circuit_params, W128Fixture, K};
use gosh_dense_balanced_tree::MAX_CHAIN_LEN;

use gosh_zk_snark_halo2_utils::ptau::{
    emit_rust_const_byte_array, read_hermez_ptau_and_verify, HERMEZ_K20_PTAU_SIZE,
    HERMEZ_K20_PTAU_URL, HERMEZ_K20_RAW_SRS_SHA256,
};

/// Cache filename for the downloaded ptau.
const PTAU_FILENAME: &str = "powersOfTau28_hez_final_20.ptau";

/// RNG seed for the synthesized two-level tree. 
const TWO_LEVEL_TREE_SEED: u64 = 99;

// ---------------------------------------------------------------------------
// Emitted-artifact filenames
// ---------------------------------------------------------------------------
// Centralized so downstream consumers (tvm-sdk paste path, standalone prover)
// can grep for these single sources of truth. Keep in sync with the top-of-file
// doc list.

/// Paste-ready `KZG_G0_BYTES / KZG_G2_BYTES / KZG_S_G2_BYTES` const snippets.
const KZG_BYTES_FILENAME: &str = "kzg_bytes.rs";
/// Paste-ready `DARK_DEX_VK_BYTES` const snippet.
const DARK_DEX_VK_RS_FILENAME: &str = "dark_dex_w128_vk_bytes.rs";
/// Binary VK blob (RawBytesUnchecked). Same bytes as the paste-ready `.rs`;
/// emitted separately so a prover can load it via `VerifyingKey::read` without
/// pulling in a Rust compile step.
const DARK_DEX_VK_BIN_FILENAME: &str = "dark_dex_w128_vk.bin";
/// Binary PK blob (RawBytesUnchecked).
const DARK_DEX_PK_BIN_FILENAME: &str = "dark_dex_w128_pk.bin";
/// `MultiPhaseThreadBreakPoints` serialized as JSON.
const DARK_DEX_BREAK_POINTS_FILENAME: &str = "dark_dex_w128_break_points.json";
/// `BaseCircuitParams` serialized as JSON.
const DARK_DEX_CONFIG_PARAMS_FILENAME: &str = "dark_dex_w128_config_params.json";
/// Format-template for the downsized halo2 raw SRS: substitute `k` for `{k}`.
const HERMEZ_SRS_FILENAME_FMT: &str = "hermez_kzg_bn254_{k}.srs";

// Rust `const` names embedded inside the paste-ready `.rs` snippets. These are
// what tvm-sdk imports, so renames must land here first.
const CONST_NAME_KZG_G0: &str = "KZG_G0_BYTES";
const CONST_NAME_KZG_G2: &str = "KZG_G2_BYTES";
const CONST_NAME_KZG_S_G2: &str = "KZG_S_G2_BYTES";
const CONST_NAME_DARK_DEX_VK: &str = "DARK_DEX_VK_BYTES";

// ---------------------------------------------------------------------------
// --gen-instances (SDK unit-test data) constants
// ---------------------------------------------------------------------------

/// Subfolder for the self-contained tvm-sdk test data (VK + proofs + instances).
/// User hand-copies this into tvm-sdk's `halo2_test_data/` after generation.
const SDK_INSTANCES_SUBDIR: &str = "dex_instances_for_sdk_tests";

/// Chain lengths whose proofs are exported to the SDK subfolder. Matches the
/// enumeration in the sibling `gen_legacy_gen_srs_dark_dex_keys` bin: L0 (no
/// dense chain), L1 (single link — same shape as keygen), L2 (two links), and
/// `MAX_CHAIN_LEN` (upper-bound stress: every link active, exercises the full
/// padding-free path).
const SDK_TEST_CHAIN_LENS: [usize; 4] = [0, 1, 2, MAX_CHAIN_LEN];

/// Proof filename template for a given chain_len.
fn sdk_proof_filename(chain_len: usize) -> String {
    format!("dark_dex_w128_L{}_proof.bin", chain_len)
}

/// Instances filename template for a given chain_len (5 × 32-byte LE Fr).
fn sdk_instances_filename(chain_len: usize) -> String {
    format!("dark_dex_w128_L{}_instances.bin", chain_len)
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Derive KZG verifier bytes + DarkDexCircuitNew (W=128) VK from the Hermez K=20 ptau"
)]
struct Args {
    /// Target circuit `k` (must be in `1..=20`). W=128 `DarkDexCircuitNew` needs
    /// `k=19`; anything smaller only makes sense for probing the downsize path.
    #[arg(long, default_value_t = K)]
    k: u32,

    /// Output directory for the generated Rust const snippets, VK blob and
    /// downsized SRS.
    #[arg(long, default_value = "./generated")]
    out: PathBuf,

    /// Override the ptau cache path.
    #[arg(long)]
    ptau_cache: Option<PathBuf>,

    /// Additionally emit `<out>/dex_instances_for_sdk_tests/` with VK +
    /// (proof, instances) pairs at chain_len ∈ {0, 1, 2, MAX_CHAIN_LEN}. Layout
    /// mirrors the sibling `gen_legacy_gen_srs_dark_dex_keys` bin; intended for
    /// hand-copy into tvm-sdk unit-test data. Adds four extra proves (~seconds
    /// to minutes each at k=19).
    #[arg(long, default_value_t = false)]
    gen_instances: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = Args::parse();
    assert!(
        (1..=20).contains(&args.k),
        "--k must be in 1..=20 (Hermez ptau is K=20 depth)"
    );

    // --- CWD-independence -----------------------------------------------
    // `load_first_voucher()` (called during [4/4] round-trip) reads
    // "vouchers.txt" relative to CWD. Rather than force the user to `cd
    // dex-halo2-circuit/` before launch, we resolve all user-supplied paths
    // against the *initial* CWD first, then chdir to CARGO_MANIFEST_DIR so
    // the relative "vouchers.txt" read succeeds regardless of launch dir.
    // We also preflight-check vouchers.txt existence BEFORE the 640s ptau
    // parse so a missing file fails fast, not 10+ minutes in.
    let initial_cwd = std::env::current_dir()?;
    args.out = absolutize(&initial_cwd, &args.out);
    if let Some(ref p) = args.ptau_cache {
        args.ptau_cache = Some(absolutize(&initial_cwd, p));
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vouchers_path = manifest_dir.join("vouchers.txt");
    assert!(
        vouchers_path.is_file(),
        "vouchers.txt not found at {} — cannot run [4/4] round-trip",
        vouchers_path.display(),
    );
    std::env::set_current_dir(&manifest_dir)?;

    fs::create_dir_all(&args.out)?;

    // --- 1. ptau cache ---------------------------------------------------
    let ptau_path = args.ptau_cache.clone().unwrap_or_else(default_ptau_cache);
    ensure_ptau_present(&ptau_path)?;

    // --- 2. read + verify anchor + downsize -----------------------------
    eprintln!(
        "[2/4] Reading ptau, verifying K=20 SHA-256 anchor, downsizing to k={}...",
        args.k
    );
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

    // --- 3. cross-halo2curves defense-in-depth A/B/C --------------------
    eprintln!("[3/4] Running defense-in-depth checks A/B/C...");
    check_g0_matches_generator(&material.verifier_bytes.g0);
    check_g2_matches_generator(&material.verifier_bytes.g2);
    check_s_g2_on_curve(&material.verifier_bytes.s_g2);
    eprintln!("      A/B/C passed (generator equality + s_g2 on-curve).");

    // --- 4. full prove+verify round-trip on a synthesized W=128 fixture -
    eprintln!(
        "[4/4] Full round-trip: keygen + prove + verify on synthesized W=128 fixture (k={})...",
        args.k
    );
    let artifacts = keygen_and_roundtrip(&material.raw_srs)?;

    // --- 5. serialize keys and emit const snippets ----------------------
    write_kzg_bytes_file(&args.out, &material.verifier_bytes)?;
    write_vk_bytes_file(&args.out, &artifacts.vk_bytes)?;
    write_vk_bin(&args.out, &artifacts.vk_bytes)?;
    write_pk_bin(&args.out, &artifacts.pk_bytes)?;
    write_break_points_json(&args.out, &artifacts.break_points_json)?;
    write_config_params_json(&args.out)?;
    write_downsized_srs(&args.out, args.k, &material.raw_srs)?;

    if args.gen_instances {
        eprintln!(
            "[+] --gen-instances: emitting SDK proof/instances subfolder at chain_len ∈ {:?}...",
            SDK_TEST_CHAIN_LENS
        );
        write_prover_instances_for_sdk(&args.out, &artifacts)?;
    }

    eprintln!();
    eprintln!("== SUCCESS ==");
    eprintln!("Generated files in {}:", args.out.display());
    eprintln!(
        "  {:<34} ({} bytes of {}/{}/{} consts)",
        KZG_BYTES_FILENAME,
        64 + 128 + 128,
        CONST_NAME_KZG_G0,
        CONST_NAME_KZG_G2,
        CONST_NAME_KZG_S_G2,
    );
    eprintln!(
        "  {:<34} ({}: [u8; {}])",
        DARK_DEX_VK_RS_FILENAME,
        CONST_NAME_DARK_DEX_VK,
        artifacts.vk_bytes.len(),
    );
    eprintln!(
        "  {:<34} ({} B, RawBytesUnchecked)",
        DARK_DEX_VK_BIN_FILENAME,
        artifacts.vk_bytes.len(),
    );
    eprintln!(
        "  {:<34} ({} B, RawBytesUnchecked)",
        DARK_DEX_PK_BIN_FILENAME,
        artifacts.pk_bytes.len(),
    );
    eprintln!(
        "  {:<34} ({} B)",
        DARK_DEX_BREAK_POINTS_FILENAME,
        artifacts.break_points_json.len(),
    );
    eprintln!(
        "  {:<34} (BaseCircuitParams at k={})",
        DARK_DEX_CONFIG_PARAMS_FILENAME, args.k,
    );
    eprintln!(
        "  {:<34} (halo2 raw SRS at k={}, {} bytes)",
        hermez_srs_filename(args.k),
        args.k,
        material.raw_srs.len(),
    );
    if args.gen_instances {
        eprintln!(
            "  {:<34}/ (VK + proof/instances at chain_len ∈ {:?})",
            SDK_INSTANCES_SUBDIR, SDK_TEST_CHAIN_LENS,
        );
    }
    eprintln!();
    eprintln!(
        "Paste {} and {} contents into",
        KZG_BYTES_FILENAME, DARK_DEX_VK_RS_FILENAME,
    );
    eprintln!("tvm_vm/src/executor/zk_halo2_utils.rs to replace the self-generated");
    eprintln!("KZG constants with Hermez-anchored ones.");
    eprintln!("The .bin/.json artifacts let a prover reconstruct the same circuit");
    eprintln!("without re-running keygen (load PK + break_points; SRS from .srs).");
    if args.gen_instances {
        eprintln!(
            "Hand-copy {}/ into tvm-sdk's halo2_test_data/ for unit tests.",
            SDK_INSTANCES_SUBDIR,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Keygen + prove/verify round-trip on the Hermez-derived SRS
// ---------------------------------------------------------------------------

/// Everything the roundtrip step produces that a downstream prover / verifier
/// (or embedding in tvm-sdk) needs. Holds both in-memory objects (so an optional
/// `--gen-instances` pass can generate more proofs without re-running keygen)
/// and pre-serialized byte blobs (for on-disk emission).
struct KeygenArtifacts {
    /// KZG SRS parsed from the Hermez-derived raw bytes.
    srs: ParamsKZG<Bn256>,
    /// VK — kept in-memory to sanity-verify any additional SDK proofs.
    vk: VerifyingKey<G1Affine>,
    /// PK — kept in-memory to avoid re-running keygen for SDK proof generation.
    pk: ProvingKey<G1Affine>,
    /// Break points for prover-circuit reconstruction. Same shape as keygen circuit.
    break_points: MultiPhaseThreadBreakPoints,
    /// The synthesized W=128 fixture. Reused to build prover circuits at
    /// different chain lengths for the SDK export loop.
    fixture: W128Fixture,
    /// VK serialized with `SerdeFormat::RawBytesUnchecked`.
    vk_bytes: Vec<u8>,
    /// PK serialized with `SerdeFormat::RawBytesUnchecked`. Substantially larger
    /// than VK (tens–hundreds of MB at k=19), only useful as an on-disk blob.
    pk_bytes: Vec<u8>,
    /// `MultiPhaseThreadBreakPoints` serialized as JSON. Required alongside PK
    /// + `BaseCircuitParams` to reconstruct a prover circuit of matching shape
    /// without re-running keygen.
    break_points_json: String,
}

/// Run the full W=128 keygen → prove → verify roundtrip against the given raw
/// Hermez-derived SRS. Returns the serialized VK/PK bytes + break_points JSON.
///
/// Uses `chain_len = 1` — same choice as `test_dark_dex_circuit_real_proof_for_fixed_k`.
/// The circuit shape is chain-length-independent, so the emitted keys are valid
/// for all `chain_len ∈ 0..=MAX_CHAIN_LEN`.
fn keygen_and_roundtrip(raw_srs: &[u8]) -> Result<KeygenArtifacts, Box<dyn std::error::Error>> {
    let t0 = Instant::now();

    // Parse the SRS from raw bytes (bypasses the disk cache path used by gen_srs).
    let mut cursor: &[u8] = raw_srs;
    let srs = ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytesUnchecked)?;
    eprintln!("      SRS parsed from bytes ({} B) in {:?}", raw_srs.len(), t0.elapsed());

    // Synthesize the canonical W=128 fixture from vouchers.txt.
    let fixture = W128Fixture::synth(TWO_LEVEL_TREE_SEED);

    // Keygen.
    let t = Instant::now();
    let keygen_circuit = fixture.build_keygen_circuit();
    let vk = keygen_vk(&srs, &keygen_circuit)?;
    eprintln!("      keygen_vk: {:?}", t.elapsed());

    let t = Instant::now();
    let pk = keygen_pk(&srs, vk.clone(), &keygen_circuit)?;
    eprintln!("      keygen_pk: {:?}", t.elapsed());

    let break_points = keygen_circuit.base_circuit_builder.borrow().break_points();

    // Serialize VK / PK / break_points.
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytesUnchecked)?;

    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::RawBytesUnchecked)?;

    let break_points_json = serde_json::to_string(&break_points)?;

    // Prove + verify with chain_len=1 (matches keygen shape). Sanity check that
    // the emitted VK / PK / break_points are internally consistent against the
    // Hermez-derived SRS. Always runs, independent of `--gen-instances`.
    let (prover_circuit, instances, _final_root) =
        fixture.build_prover_circuit(1, break_points.clone());

    let t = Instant::now();
    let proof_bytes = gen_proof_with_instances(&srs, &pk, prover_circuit, &[&instances]);
    eprintln!("      prove: {:?} ({} B)", t.elapsed(), proof_bytes.len());

    let t = Instant::now();
    check_proof_with_instances(&srs, &vk, &proof_bytes, &[&instances], true);
    eprintln!("      verify: {:?}", t.elapsed());
    eprintln!(
        "      OK — proof verifies against Hermez-derived SRS; total {:?}",
        t0.elapsed()
    );

    Ok(KeygenArtifacts {
        srs,
        vk,
        pk,
        break_points,
        fixture,
        vk_bytes,
        pk_bytes,
        break_points_json,
    })
}

// ---------------------------------------------------------------------------
// ptau helpers
// ---------------------------------------------------------------------------

fn default_ptau_cache() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    PathBuf::from(home)
        .join(".cache/halo2-kzg-srs")
        .join(PTAU_FILENAME)
}

fn ensure_ptau_present(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() == HERMEZ_K20_PTAU_SIZE {
            eprintln!(
                "[1/4] Ptau cached at {} ({} bytes) — OK",
                path.display(),
                meta.len()
            );
            return Ok(());
        }
        eprintln!(
            "[1/4] Ptau at {} has wrong size ({} vs expected {}) — re-downloading",
            path.display(),
            meta.len(),
            HERMEZ_K20_PTAU_SIZE
        );
    } else {
        eprintln!(
            "[1/4] Ptau not cached — downloading from {}",
            HERMEZ_K20_PTAU_URL
        );
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

// ---------------------------------------------------------------------------
// Defense-in-depth checks A/B/C
// ---------------------------------------------------------------------------

/// Check A: `g[0]` bytes equal halo2-base's `G1Affine::generator()` bytes.
///
/// BN254 `g[0]` is a curve constant across every well-formed BN254 KZG SRS.
/// If this check passes, the halo2_kzg_srs → halo2-base bytes-boundary
/// preserves G1 identity encoding.
fn check_g0_matches_generator(g0: &[u8; 64]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    let expected: G1Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G1::generator().to_affine();
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
    let expected: G2Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G2::generator().to_affine();
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
    s.push_str("// Generated by dex-halo2-circuit::gen_hermez_kzg_and_dark_dex_keys.\n");
    s.push_str("// Anchored in the Hermez Perpetual Powers of Tau ceremony\n");
    s.push_str("// (powersOfTau28_hez_final_20.ptau, K=20 raw SRS SHA-256\n");
    s.push_str("// 80394564e2598883dbb5d7d61630287f34e29cdd806d7ef74f68acc6bffeb608).\n");
    s.push_str("// Paste into tvm_vm/src/executor/zk_halo2_utils.rs.\n\n");
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_KZG_G0,
        "`g[0]` (64-byte uncompressed BN254 G1Affine). Curve constant.",
        &v.g0,
    ));
    s.push('\n');
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_KZG_G2,
        "`g2` (128-byte uncompressed BN254 G2Affine). Curve constant.",
        &v.g2,
    ));
    s.push('\n');
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_KZG_S_G2,
        "`[s]·G2` (128-byte uncompressed BN254 G2Affine). Ceremony-specific:\nencodes the Hermez trapdoor `s`. Verification only succeeds against\nproofs generated from the matching Hermez K=20 raw SRS.",
        &v.s_g2,
    ));
    let path = out.join(KZG_BYTES_FILENAME);
    fs::write(&path, s)?;
    eprintln!("      Wrote {}", path.display());
    Ok(())
}

fn write_vk_bytes_file(out: &Path, vk_bytes: &[u8]) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("// Generated by dex-halo2-circuit::gen_hermez_kzg_and_dark_dex_keys.\n");
    s.push_str("// Verifying key for DarkDexCircuitNew (dark_dex_w128) at k=19 with the\n");
    s.push_str(&format!(
        "// BaseCircuitParams in {}, generated\n",
        DARK_DEX_CONFIG_PARAMS_FILENAME,
    ));
    s.push_str("// against the Hermez-anchored KZG SRS above.\n");
    s.push_str("// Paste into tvm_vm/src/executor/zk_halo2_utils.rs.\n\n");
    s.push_str(&emit_rust_const_byte_array(
        CONST_NAME_DARK_DEX_VK,
        "VerifyingKey<G1Affine> serialized with SerdeFormat::RawBytesUnchecked.",
        vk_bytes,
    ));
    let path = out.join(DARK_DEX_VK_RS_FILENAME);
    fs::write(&path, s)?;
    eprintln!("      Wrote {} ({} VK bytes)", path.display(), vk_bytes.len());
    Ok(())
}

/// Write the binary VK blob. Same bytes that get embedded into the paste-ready
/// `.rs`; sharing `vk_bytes` from `KeygenArtifacts` guarantees the two artifacts
/// stay in lockstep without recomputing the serialization.
fn write_vk_bin(out: &Path, vk_bytes: &[u8]) -> std::io::Result<()> {
    let path = out.join(DARK_DEX_VK_BIN_FILENAME);
    fs::write(&path, vk_bytes)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), vk_bytes.len());
    Ok(())
}

/// Write the binary PK blob. Uses `BufWriter` because PK at k=19 is large
/// (tens of MB range) and a single `fs::write` would build the buffer twice.
fn write_pk_bin(out: &Path, pk_bytes: &[u8]) -> std::io::Result<()> {
    let path = out.join(DARK_DEX_PK_BIN_FILENAME);
    let file = fs::File::create(&path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(pk_bytes)?;
    writer.flush()?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), pk_bytes.len());
    Ok(())
}

fn write_break_points_json(out: &Path, json: &str) -> std::io::Result<()> {
    let path = out.join(DARK_DEX_BREAK_POINTS_FILENAME);
    fs::write(&path, json)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), json.len());
    Ok(())
}

fn write_config_params_json(out: &Path) -> std::io::Result<()> {
    let params = base_circuit_params();
    let json = serde_json::to_string_pretty(&params).unwrap();
    let path = out.join(DARK_DEX_CONFIG_PARAMS_FILENAME);
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

/// Render `HERMEZ_SRS_FILENAME_FMT` for a given `k` (substitutes `{k}`).
fn hermez_srs_filename(k: u32) -> String {
    HERMEZ_SRS_FILENAME_FMT.replace("{k}", &k.to_string())
}

/// Emit a self-contained `dex_instances_for_sdk_tests/` subfolder with VK +
/// (proof, instances) pairs at chain_len ∈ [`SDK_TEST_CHAIN_LENS`]. Reuses the
/// in-memory `srs` / `pk` / `vk` / `break_points` / `fixture` from
/// [`KeygenArtifacts`], so no keygen work is redone — only the additional
/// proofs (one per chain_len).
///
/// File layout matches the sibling `gen_legacy_gen_srs_dark_dex_keys` bin so
/// the folder can be hand-copied verbatim into tvm-sdk's unit-test data
/// directory.
fn write_prover_instances_for_sdk(
    out_root: &Path,
    a: &KeygenArtifacts,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = out_root.join(SDK_INSTANCES_SUBDIR);
    fs::create_dir_all(&dir)?;
    eprintln!("      Subfolder: {}", dir.display());

    // Include the VK in the subfolder too so the artifact set is self-contained.
    // Same bytes as the top-level `dark_dex_w128_vk.bin` — reused from
    // `KeygenArtifacts`, not re-serialized.
    let vk_path = dir.join(DARK_DEX_VK_BIN_FILENAME);
    fs::write(&vk_path, &a.vk_bytes)?;
    eprintln!(
        "      Wrote {} ({} bytes, mirrors top-level)",
        vk_path.display(),
        a.vk_bytes.len()
    );

    for &chain_len in &SDK_TEST_CHAIN_LENS {
        eprintln!("      [L{}] building prover circuit...", chain_len);
        let (prover_circuit, instances, _final_root) = a
            .fixture
            .build_prover_circuit(chain_len, a.break_points.clone());
        assert_eq!(instances.len(), 5, "SDK instance layout is 5 Fr");

        let t = Instant::now();
        let proof_bytes = gen_proof_with_instances(&a.srs, &a.pk, prover_circuit, &[&instances]);
        eprintln!(
            "      [L{}] prove: {:?} ({} B); sanity-verifying...",
            chain_len,
            t.elapsed(),
            proof_bytes.len()
        );
        check_proof_with_instances(&a.srs, &a.vk, &proof_bytes, &[&instances], true);

        // 5 × 32-byte LE Fr = 160 B. tvm-sdk decodes via `Fr::from_bytes_le` /
        // `Fr::from_repr`; encoding is byte-exact symmetric.
        let mut instances_bytes: Vec<u8> = Vec::with_capacity(5 * 32);
        for fr in &instances {
            instances_bytes.extend_from_slice(fr.to_repr().as_ref());
        }
        debug_assert_eq!(instances_bytes.len(), 160);

        let proof_path = dir.join(sdk_proof_filename(chain_len));
        let instances_path = dir.join(sdk_instances_filename(chain_len));
        fs::write(&proof_path, &proof_bytes)?;
        fs::write(&instances_path, &instances_bytes)?;
        eprintln!(
            "      [L{}] wrote {} ({} B) + {} ({} B)",
            chain_len,
            proof_path.display(),
            proof_bytes.len(),
            instances_path.display(),
            instances_bytes.len(),
        );
    }
    Ok(())
}

/// Resolve `p` against `base` if relative; return unchanged if already absolute.
/// Used to snapshot user-supplied paths against the *initial* CWD before we
/// chdir to `CARGO_MANIFEST_DIR` for the vouchers.txt read.
fn absolutize(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
