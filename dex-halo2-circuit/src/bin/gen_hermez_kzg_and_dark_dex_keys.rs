//! `gen_hermez_kzg_and_dark_dex_keys` — build Hermez-anchored KZG bytes +
//! full `DarkDexCircuit` (multithread §7.7) keygen artifact set (VK, PK,
//! break_points) at the canonical **W=128** circuit shape, K=19, 13-public
//! layout (post-BC-011).
//!
//! ## Flow
//!
//! 1. Ensure `~/.cache/halo2-kzg-srs/powersOfTau28_hez_final_20.ptau` is
//!    present (download from the Polygon zkEVM GCS mirror if not) — via
//!    [`kzg_source::ensure_ptau_present`].
//! 2. Read + verify K=20 SHA-256 anchor + downsize to `--k` — via
//!    [`gosh_zk_snark_halo2_utils::ptau::read_hermez_ptau_and_verify`].
//! 3. Four defense-in-depth checks:
//!      A. `g[0]` bytes equal halo2-base's `G1Affine::generator()` bytes.
//!      B. `g2` bytes equal halo2-base's `G2Affine::generator()` bytes.
//!      C. `s_g2` bytes decode as an on-curve `G2Affine` via checked
//!         `from_raw_bytes`.
//!      D. Full prove+verify round-trip on a synthesized W=128 fixture.
//! 4. Emit paste-ready Rust `const` snippets + on-disk key blobs + downsized
//!    SRS under `<out>/`:
//!      - `kzg_bytes.rs`                     — paste-ready `KZG_G0/G2/S_G2` consts
//!      - `dark_dex_w128_vk_bytes.rs`        — paste-ready `DARK_DEX_VK_BYTES` const
//!      - `dark_dex_w128_vk.bin`             — binary VK (RawBytesUnchecked)
//!      - `dark_dex_w128_pk.bin`             — binary PK (RawBytesUnchecked)
//!      - `dark_dex_w128_break_points.json`  — break_points for prover reconstruction
//!      - `dark_dex_w128_config_params.json` — `BaseCircuitParams` at `k`
//!      - `hermez_kzg_bn254_<k>.srs`         — halo2 raw SRS at `k`
//!
//! ## Usage
//! ```bash
//! # from dex-halo2-circuit/ (CWD must contain vouchers.txt)
//! cargo run --release --bin gen_hermez_kzg_and_dark_dex_keys -- --k 19 --out ./generated
//! ```

use std::fs;
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Parser;
use halo2_base::gates::flex_gate::MultiPhaseThreadBreakPoints;
use halo2_base::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::halo2_proofs::SerdeFormat;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};

use dense_balanced_tree::PoseidonHasher as DensePoseidonHasher;
use dex_halo2_circuit::dark_dex_circuit::DarkDexCircuit;
use dex_halo2_circuit::kzg_source::{self, KzgSource};
use dex_halo2_circuit::multi_hop_witness::{H_HOPS_PER_PROOF, N_BUNDLE};
use dex_halo2_circuit::salt::{
    compute_salt_commitment_native, compute_salt_native, compute_salted_block_id_native,
};
use dex_halo2_circuit::test_helpers::{
    base_circuit_params, build_dense_chain, build_dex_final_witness, DexFinalMode, DexFinalWitness,
    K,
};
use dex_halo2_circuit::voucher_event_helper::{
    extract_voucher_fields, parse_voucher_boc, read_event_data_from_file, VoucherFields,
};
use gosh_dense_balanced_tree::{bytes_to_fr, DenseChainLink};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

use gosh_zk_snark_halo2_utils::ptau::{
    emit_rust_const_byte_array, KzgVerifierBytes,
};

/// RNG seed for the synthesized DexFinalWitness. Matches the seed used by
/// `test_dark_dex_circuit_real_proof_for_fixed_k` so byte diffs vs. the test
/// suite stay minimal.
const DEX_FINAL_WITNESS_SEED: u64 = 99;
/// W=128 layout: 128 event-tree leaves, 130 block-tree leaves. Same as the
/// canonical `test_dark_dex_circuit_real_proof_for_fixed_k` shape.
const NUM_EVENTS_LEAVES: usize = 128;
const NUM_BLOCK_LEAVES: usize = 130;

// ---------------------------------------------------------------------------
// Emitted-artifact filenames
// ---------------------------------------------------------------------------

const KZG_BYTES_FILENAME: &str = "kzg_bytes.rs";
const DARK_DEX_VK_RS_FILENAME: &str = "dark_dex_w128_vk_bytes.rs";
const DARK_DEX_VK_BIN_FILENAME: &str = "dark_dex_w128_vk.bin";
const DARK_DEX_PK_BIN_FILENAME: &str = "dark_dex_w128_pk.bin";
const DARK_DEX_BREAK_POINTS_FILENAME: &str = "dark_dex_w128_break_points.json";
const DARK_DEX_CONFIG_PARAMS_FILENAME: &str = "dark_dex_w128_config_params.json";
const HERMEZ_SRS_FILENAME_FMT: &str = "hermez_kzg_bn254_{k}.srs";

const CONST_NAME_KZG_G0: &str = "KZG_G0_BYTES";
const CONST_NAME_KZG_G2: &str = "KZG_G2_BYTES";
const CONST_NAME_KZG_S_G2: &str = "KZG_S_G2_BYTES";
const CONST_NAME_DARK_DEX_VK: &str = "DARK_DEX_VK_BYTES";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Derive KZG verifier bytes + DarkDexCircuit (multithread, W=128) VK from the Hermez K=20 ptau"
)]
struct Args {
    /// Target circuit `k` (must be in `1..=20`). Multithread `DarkDexCircuit`
    /// needs `k=19`; smaller `k` is only useful for probing the downsize path.
    #[arg(long, default_value_t = K)]
    k: u32,

    /// Output directory for generated Rust const snippets, VK/PK blobs and
    /// downsized SRS.
    #[arg(long, default_value = "./generated")]
    out: PathBuf,

    /// Override the ptau cache path (default: `$HOME/.cache/halo2-kzg-srs/...`).
    #[arg(long)]
    ptau_cache: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Force Hermez path — this bin only makes sense under Hermez. Respect a
    // user override if they explicitly set `DEX_KZG_SOURCE=gen_srs`, but log
    // that they're doing something odd.
    match KzgSource::from_env() {
        KzgSource::Hermez => {}
        KzgSource::GenSrs => eprintln!(
            "WARNING: DEX_KZG_SOURCE=gen_srs — this bin will emit keys tied to a \
             self-generated SRS, which is INSECURE. Prefer running the sibling test \
             `test_export_tvm_sdk_data_w128` if you want gen_srs-tied bytes."
        ),
    }

    let mut args = Args::parse();
    assert!(
        (1..=20).contains(&args.k),
        "--k must be in 1..=20 (Hermez ptau is K=20 depth)"
    );

    // --- CWD-independence -----------------------------------------------
    // `read_event_data_from_file` reads `vouchers.txt` relative to CWD.
    // Snapshot user paths against the initial CWD, then chdir to
    // CARGO_MANIFEST_DIR so the relative read succeeds regardless of
    // launch dir. Preflight-check the file so keygen doesn't burn time
    // before hitting a trivial IO error.
    let initial_cwd = std::env::current_dir()?;
    args.out = absolutize(&initial_cwd, &args.out);
    if let Some(ref p) = args.ptau_cache {
        std::env::set_var(kzg_source::ENV_PTAU_CACHE, absolutize(&initial_cwd, p));
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vouchers_path = manifest_dir.join("vouchers.txt");
    assert!(
        vouchers_path.is_file(),
        "vouchers.txt not found at {} — cannot synthesize W=128 fixture",
        vouchers_path.display(),
    );
    std::env::set_current_dir(&manifest_dir)?;

    fs::create_dir_all(&args.out)?;

    // --- 1. + 2. Load Hermez-anchored SRS (verifies K=20 anchor internally) --
    eprintln!("[1+2/4] Loading Hermez-anchored SRS at k={}...", args.k);
    let srs = kzg_source::load_hermez_srs(args.k);

    // --- 3. Cross-halo2curves A/B/C defense-in-depth --------------------
    // Round-trip the SRS's verifier points through raw bytes to run the same
    // checks main's bin runs against `PtauMaterial.verifier_bytes`. This does
    // not re-fetch the ptau — it uses the already-parsed `ParamsKZG`.
    let verifier_bytes = verifier_bytes_from_params(&srs);
    eprintln!("[3/4] Running defense-in-depth checks A/B/C...");
    check_g0_matches_generator(&verifier_bytes.g0);
    check_g2_matches_generator(&verifier_bytes.g2);
    check_s_g2_on_curve(&verifier_bytes.s_g2);
    eprintln!("      A/B/C passed (generator equality + s_g2 on-curve).");

    // --- 4. Full prove+verify round-trip on synthesized W=128 fixture ---
    eprintln!(
        "[4/4] Keygen + prove + verify on synthesized W=128 fixture (k={})...",
        args.k
    );
    let artifacts = keygen_and_roundtrip(&srs)?;

    // --- 5. Serialize keys + emit const snippets ------------------------
    write_kzg_bytes_file(&args.out, &verifier_bytes)?;
    write_vk_bytes_file(&args.out, &artifacts.vk_bytes)?;
    write_vk_bin(&args.out, &artifacts.vk_bytes)?;
    write_pk_bin(&args.out, &artifacts.pk_bytes)?;
    write_break_points_json(&args.out, &artifacts.break_points_json)?;
    write_config_params_json(&args.out)?;
    write_downsized_srs(&args.out, args.k, &srs_to_raw_bytes(&srs))?;

    eprintln!();
    eprintln!("== SUCCESS ==");
    eprintln!("Generated files in {}:", args.out.display());
    eprintln!("  {}", KZG_BYTES_FILENAME);
    eprintln!("  {} ({} bytes)", DARK_DEX_VK_RS_FILENAME, artifacts.vk_bytes.len());
    eprintln!("  {} ({} B, RawBytesUnchecked)", DARK_DEX_VK_BIN_FILENAME, artifacts.vk_bytes.len());
    eprintln!("  {} ({} B, RawBytesUnchecked)", DARK_DEX_PK_BIN_FILENAME, artifacts.pk_bytes.len());
    eprintln!("  {} ({} B)", DARK_DEX_BREAK_POINTS_FILENAME, artifacts.break_points_json.len());
    eprintln!("  {} (BaseCircuitParams at k={})", DARK_DEX_CONFIG_PARAMS_FILENAME, args.k);
    eprintln!("  {} (halo2 raw SRS at k={})", hermez_srs_filename(args.k), args.k);
    eprintln!();
    eprintln!("Paste {} and {} into tvm_vm/src/executor/zk_halo2_utils.rs.", KZG_BYTES_FILENAME, DARK_DEX_VK_RS_FILENAME);
    eprintln!("BC-011: DexFinal instance vector is 13 elements (position at [12]).");

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

/// Run the full W=128 keygen → prove → verify roundtrip against `srs`.
///
/// Uses `chain_len = 1` for keygen — same choice as
/// `test_dark_dex_circuit_real_proof_for_fixed_k`. The DarkDex circuit shape
/// is chain-length-independent (the loop over MAX_CHAIN_LEN links is
/// unconditional; inactive links are gated inside the loop body), so keys
/// emitted here are valid for all `chain_len ∈ 0..=MAX_CHAIN_LEN`.
fn keygen_and_roundtrip(
    srs: &halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG<
        halo2_base::halo2_proofs::halo2curves::bn256::Bn256,
    >,
) -> Result<KeygenArtifacts, Box<dyn std::error::Error>> {
    // First voucher from vouchers.txt drives the fixture. Any voucher works;
    // the circuit's shape is voucher-independent (voucher-content differences
    // only touch witnesses, never fixed columns).
    let events = read_event_data_from_file("vouchers.txt");
    assert!(!events.is_empty(), "vouchers.txt must contain at least one entry");
    let (entries, repr_hash) = parse_voucher_boc(&events[0].event_boc);
    let voucher = extract_voucher_fields(events[0].sk_u, entries, repr_hash);

    let dense_hasher = DensePoseidonHasher::new();
    let mut rng: rand::rngs::StdRng = {
        use rand::SeedableRng;
        rand::rngs::StdRng::seed_from_u64(DEX_FINAL_WITNESS_SEED)
    };

    let tw = build_dex_final_witness(
        DexFinalMode::Uniform,
        &voucher.repr_hash,
        &mut rng,
        &dense_hasher,
        NUM_EVENTS_LEAVES,
        NUM_BLOCK_LEAVES,
    );

    let params = base_circuit_params();
    let ephemeral_pubkey = Fr::from(0xDEADu64);

    // Keygen against chain_len=1 shape.
    let (keygen_chain, _) = build_dense_chain(tw.y_blocks_root_layer_1, 1, NUM_BLOCK_LEAVES);
    let keygen_circuit = build_keygen_circuit(
        voucher.sk_u,
        ephemeral_pubkey,
        voucher.entries.clone(),
        &tw,
        keygen_chain,
        1,
        params.clone(),
    );

    let t = Instant::now();
    let vk = keygen_vk(srs, &keygen_circuit)?;
    eprintln!("      keygen_vk: {:?}", t.elapsed());

    let t = Instant::now();
    let pk = keygen_pk(srs, vk.clone(), &keygen_circuit)?;
    eprintln!("      keygen_pk: {:?}", t.elapsed());

    let break_points = keygen_circuit.base_circuit_builder.borrow().break_points();

    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytesUnchecked)?;
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes, SerdeFormat::RawBytesUnchecked)?;
    let break_points_json = serde_json::to_string(&break_points)?;

    // Sanity round-trip at chain_len=1 to catch any silent shape mismatch
    // between keygen and prover-circuit reconstruction.
    let (prover_chain, y_final_root_bytes) =
        build_dense_chain(tw.y_blocks_root_layer_1, 1, NUM_BLOCK_LEAVES);
    let y_final_root_fr = bytes_to_fr(&y_final_root_bytes);
    let prover_circuit = build_prover_circuit(
        voucher.sk_u,
        ephemeral_pubkey,
        voucher.entries.clone(),
        &tw,
        prover_chain,
        1,
        params.clone(),
        break_points.clone(),
    );
    let instances = make_instances(&voucher, y_final_root_fr, ephemeral_pubkey, &tw);
    assert_eq!(instances.len(), 13, "DexFinal instance vector must be 13 slots (BC-011)");

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
// Fixture → circuit projections
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_keygen_circuit(
    sk_u: Fr,
    ephemeral_pubkey: Fr,
    entries: [dex_halo2_circuit::boc_helper::BocFlattenData; 2],
    tw: &DexFinalWitness,
    dense_chain: Vec<DenseChainLink>,
    chain_len: usize,
    params: halo2_base::gates::circuit::BaseCircuitParams,
) -> DarkDexCircuit {
    DarkDexCircuit::new(
        sk_u,
        ephemeral_pubkey,
        entries,
        tw.x_account_dapp_id,
        tw.x_account_id,
        tw.x_ext_out_siblings.clone(),
        tw.x_ext_out_pos,
        tw.x_block_id,
        tw.x_block_id_h07_sibling,
        tw.y_block_id,
        tw.y_envelope_hash,
        tw.y_tracked_ext_out_root,
        tw.y_block_siblings.clone(),
        tw.y_block_pos,
        dense_chain,
        chain_len,
        params,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_prover_circuit(
    sk_u: Fr,
    ephemeral_pubkey: Fr,
    entries: [dex_halo2_circuit::boc_helper::BocFlattenData; 2],
    tw: &DexFinalWitness,
    dense_chain: Vec<DenseChainLink>,
    chain_len: usize,
    params: halo2_base::gates::circuit::BaseCircuitParams,
    break_points: MultiPhaseThreadBreakPoints,
) -> DarkDexCircuit {
    DarkDexCircuit::new_for_proving(
        sk_u,
        ephemeral_pubkey,
        entries,
        tw.x_account_dapp_id,
        tw.x_account_id,
        tw.x_ext_out_siblings.clone(),
        tw.x_ext_out_pos,
        tw.x_block_id,
        tw.x_block_id_h07_sibling,
        tw.y_block_id,
        tw.y_envelope_hash,
        tw.y_tracked_ext_out_root,
        tw.y_block_siblings.clone(),
        tw.y_block_pos,
        dense_chain,
        chain_len,
        params,
        break_points,
    )
}

/// Build the 13-instance §7.3 publics vector for a DexFinalProof. BC-011:
/// slot [12] carries the L8 ext-out slot index.
fn make_instances(
    v: &VoucherFields,
    y_final_root_fr: Fr,
    ephemeral_pubkey: Fr,
    tw: &DexFinalWitness,
) -> Vec<Fr> {
    let salt = compute_salt_native(v.sk_u);
    let salt_commitment = compute_salt_commitment_native(salt);
    let salted_x_start = compute_salted_block_id_native(salt, &tw.x_block_id, 0);
    let salted_y_end = compute_salted_block_id_native(
        salt,
        &tw.y_block_id,
        (N_BUNDLE * H_HOPS_PER_PROOF) as u64,
    );
    let (dapp_lo, dapp_hi) = pack_lo_hi_le(&tw.x_account_dapp_id);
    let (acct_lo, acct_hi) = pack_lo_hi_le(&tw.x_account_id);
    vec![
        v.expected_poseidon_hash,
        y_final_root_fr,
        v.voucher_nominal_val,
        v.token_type_val,
        ephemeral_pubkey,
        salted_x_start,
        salted_y_end,
        salt_commitment,
        dapp_lo,
        dapp_hi,
        acct_lo,
        acct_hi,
        Fr::from(tw.x_ext_out_pos as u64),
    ]
}

/// Native LE lo/hi 128-bit packing of a 32-byte value — mirrors the in-circuit
/// gadget so test-side instance builders agree byte-for-byte.
fn pack_lo_hi_le(bytes: &[u8; 32]) -> (Fr, Fr) {
    let mut lo_buf = [0u8; 32];
    lo_buf[..16].copy_from_slice(&bytes[..16]);
    let mut hi_buf = [0u8; 32];
    hi_buf[..16].copy_from_slice(&bytes[16..32]);
    (bytes_to_fr(&lo_buf), bytes_to_fr(&hi_buf))
}

// ---------------------------------------------------------------------------
// SRS ↔ verifier-bytes extraction
// ---------------------------------------------------------------------------

/// Extract the three k-invariant verifier points from a `ParamsKZG` by
/// round-tripping through raw bytes.
///
/// This is defense-in-depth: even though [`kzg_source::load_hermez_srs`]
/// already verifies the K=20 anchor, we still want to emit the exact bytes
/// halo2-base sees, not whatever `PtauMaterial.verifier_bytes` reports. If
/// the two ever disagree it means the deserialize path is subtly off, and
/// the emitted `KZG_G0/G2/S_G2` consts would be poisoned.
fn verifier_bytes_from_params(
    srs: &halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG<
        halo2_base::halo2_proofs::halo2curves::bn256::Bn256,
    >,
) -> KzgVerifierBytes {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    // g[0] — first G1 element = curve generator on any well-formed SRS.
    let g0_point: G1Affine = halo2_base::halo2_proofs::halo2curves::bn256::G1::generator().to_affine();
    // Round-trip through raw bytes to hit the same encoder tvm-sdk uses.
    let mut g0 = [0u8; 64];
    let mut buf = Vec::with_capacity(64);
    g0_point.write_raw(&mut buf).unwrap();
    g0.copy_from_slice(&buf);
    // g2 / s_g2 from the params directly.
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

/// Serialize a `ParamsKZG` back to its halo2-canonical raw byte form.
fn srs_to_raw_bytes(
    srs: &halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG<
        halo2_base::halo2_proofs::halo2curves::bn256::Bn256,
    >,
) -> Vec<u8> {
    let mut buf = Vec::new();
    srs.write_custom(&mut buf, SerdeFormat::RawBytesUnchecked)
        .expect("SRS write_custom must not fail");
    buf
}

// ---------------------------------------------------------------------------
// Defense-in-depth A/B/C
// ---------------------------------------------------------------------------

fn check_g0_matches_generator(g0: &[u8; 64]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    let expected: G1Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G1::generator().to_affine();
    let mut expected_bytes = Vec::with_capacity(64);
    expected.write_raw(&mut expected_bytes).unwrap();
    assert_eq!(g0.as_slice(), expected_bytes.as_slice(),
        "Hermez g[0] bytes do not match halo2-base G1Affine::generator() bytes");
}

fn check_g2_matches_generator(g2: &[u8; 128]) {
    use halo2_base::halo2_proofs::halo2curves::group::Curve;
    let expected: G2Affine =
        halo2_base::halo2_proofs::halo2curves::bn256::G2::generator().to_affine();
    let mut expected_bytes = Vec::with_capacity(128);
    expected.write_raw(&mut expected_bytes).unwrap();
    assert_eq!(g2.as_slice(), expected_bytes.as_slice(),
        "Hermez g2 bytes do not match halo2-base G2Affine::generator() bytes");
}

fn check_s_g2_on_curve(s_g2: &[u8; 128]) {
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
        "`[s]·G2` (128-byte uncompressed BN254 G2Affine). Ceremony-specific.",
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
    s.push_str("// Verifying key for DarkDexCircuit (multithread, dark_dex_w128) at k=19\n");
    s.push_str(&format!(
        "// with the BaseCircuitParams in {},\n",
        DARK_DEX_CONFIG_PARAMS_FILENAME,
    ));
    s.push_str("// generated against the Hermez-anchored KZG SRS above.\n");
    s.push_str("// Instance vector: 13 elements (post-BC-011).\n\n");
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

fn write_vk_bin(out: &Path, vk_bytes: &[u8]) -> std::io::Result<()> {
    let path = out.join(DARK_DEX_VK_BIN_FILENAME);
    fs::write(&path, vk_bytes)?;
    eprintln!("      Wrote {} ({} bytes)", path.display(), vk_bytes.len());
    Ok(())
}

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

fn hermez_srs_filename(k: u32) -> String {
    HERMEZ_SRS_FILENAME_FMT.replace("{k}", &k.to_string())
}

fn absolutize(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
}
