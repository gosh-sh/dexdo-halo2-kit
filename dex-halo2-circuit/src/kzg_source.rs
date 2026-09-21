//! KZG SRS source selection for `dex-halo2-circuit`.
//!
//! Two paths are supported:
//!
//! - **Hermez** (default, production): the SRS is derived from the Hermez
//!   Perpetual Powers of Tau ceremony (`powersOfTau28_hez_final_20.ptau`,
//!   K=20). This is the audited, community-anchored trust root; the raw
//!   SRS at K=20 has a byte-exact SHA-256 anchor
//!   (`80394564e2598883dbb5d7d61630287f34e29cdd806d7ef74f68acc6bffeb608`)
//!   that this module verifies before use.
//! - **`gen_srs`** (INSECURE, opt-in): halo2-base's `gen_srs(K)` generates
//!   the trapdoor in-process from RNG and caches it under `PARAMS_DIR`. The
//!   trapdoor is never deleted — anyone with access to that cache can forge
//!   proofs. Kept only for legacy compatibility with pre-Hermez blobs and
//!   for fast local iteration where SRS security is irrelevant.
//!
//! # Selection
//!
//! Callers use [`load_srs`], which dispatches on the `DEX_KZG_SOURCE`
//! environment variable:
//!
//! - unset or `hermez` → Hermez path (this module ensures the ptau cache is
//!   populated, validates the K=20 anchor, and downsizes to the requested K).
//! - `gen_srs` → self-generated SRS via `halo2_base::utils::fs::gen_srs`.
//!
//! Anything else panics — silent fallback would defeat the point of an
//! explicit trust-root switch.
//!
//! # Ptau cache
//!
//! The K=20 ptau (~2.3 GB) is cached at
//! `$HOME/.cache/halo2-kzg-srs/powersOfTau28_hez_final_20.ptau`, matching the
//! `bridge/scripts/bootstrap_hermez_srs.sh` convention. Override with the
//! `HERMEZ_PTAU_CACHE` env var. If the file is missing or has wrong size, it
//! is downloaded from the Polygon zkEVM GCS mirror.
//!
//! # Concurrency
//!
//! No in-process cache: each call to `load_srs` re-parses the raw SRS bytes.
//! At K=17..19 this is ~50 ms — negligible next to the ~seconds-to-minutes
//! keygen/prove that follows. If test runs start showing this on the flame
//! graph we can add a `OnceCell` layer.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use halo2_base::halo2_proofs::halo2curves::bn256::Bn256;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;

use gosh_zk_snark_halo2_utils::ptau::{
    read_hermez_ptau_and_verify, HERMEZ_K20_PTAU_SIZE, HERMEZ_K20_PTAU_URL,
    HERMEZ_K20_RAW_SRS_SHA256,
};

/// Filename of the Hermez K=20 ptau inside the cache directory.
const PTAU_FILENAME: &str = "powersOfTau28_hez_final_20.ptau";

/// Env var selecting the SRS source. Values: unset / "hermez" / "gen_srs".
pub const ENV_KZG_SOURCE: &str = "DEX_KZG_SOURCE";
/// Env var overriding the default Hermez ptau cache path.
pub const ENV_PTAU_CACHE: &str = "HERMEZ_PTAU_CACHE";

/// KZG source families. Exposed so callers (bins) can log which path they took.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KzgSource {
    /// Audited Hermez K=20 ceremony (default).
    Hermez,
    /// Self-generated via `halo2_base::utils::fs::gen_srs`. INSECURE.
    GenSrs,
}

impl KzgSource {
    /// Read [`ENV_KZG_SOURCE`] and return the selected source (default Hermez).
    /// Panics on unknown values — silent fallback to `gen_srs` would defeat
    /// the point of an explicit trust-root switch.
    pub fn from_env() -> Self {
        match std::env::var(ENV_KZG_SOURCE).ok().as_deref() {
            None | Some("") | Some("hermez") | Some("Hermez") | Some("HERMEZ") => KzgSource::Hermez,
            Some("gen_srs") | Some("legacy") | Some("insecure") => KzgSource::GenSrs,
            Some(other) => panic!(
                "Unknown {} value: {:?}. Expected 'hermez' or 'gen_srs'.",
                ENV_KZG_SOURCE, other
            ),
        }
    }
}

/// Default path to the Hermez ptau cache: `$HOME/.cache/halo2-kzg-srs/<PTAU_FILENAME>`.
/// Overridable via `HERMEZ_PTAU_CACHE`.
pub fn default_ptau_cache() -> PathBuf {
    if let Ok(p) = std::env::var(ENV_PTAU_CACHE) {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").expect("HOME must be set for default ptau cache");
    PathBuf::from(home)
        .join(".cache/halo2-kzg-srs")
        .join(PTAU_FILENAME)
}

/// Ensure the Hermez ptau exists at `path` with the expected size, downloading
/// it from the Polygon zkEVM GCS mirror if missing or corrupt.
///
/// This is the same fetch strategy `bootstrap_hermez_srs.sh` uses. The
/// downloaded file is size-checked but *not* SHA-256-checked here — the
/// SHA-256 is verified against `HERMEZ_K20_RAW_SRS_SHA256` on the derived
/// raw SRS inside [`load_hermez_srs`], not on the ptau blob itself.
pub fn ensure_ptau_present(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.len() == HERMEZ_K20_PTAU_SIZE {
            eprintln!(
                "[kzg_source] Ptau cached at {} ({} bytes) — OK",
                path.display(),
                meta.len()
            );
            return Ok(());
        }
        eprintln!(
            "[kzg_source] Ptau at {} has wrong size ({} vs expected {}) — re-downloading",
            path.display(),
            meta.len(),
            HERMEZ_K20_PTAU_SIZE
        );
    } else {
        eprintln!(
            "[kzg_source] Ptau not cached — downloading from {}",
            HERMEZ_K20_PTAU_URL
        );
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut resp = reqwest::blocking::get(HERMEZ_K20_PTAU_URL)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        .error_for_status()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let mut file = fs::File::create(path)?;
    let bytes = std::io::copy(&mut resp, &mut file)?;
    eprintln!(
        "[kzg_source] Downloaded {} bytes to {}",
        bytes,
        path.display()
    );
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

/// Load a Hermez-anchored SRS at circuit degree `k` (must be ≤ 20).
///
/// Flow: cache → read → verify K=20 SHA-256 anchor → downsize to `k` →
/// deserialize as `ParamsKZG<Bn256>` via `SerdeFormat::RawBytesUnchecked`.
///
/// Panics if the K=20 SHA-256 anchor does not match. This is a hard-stop:
/// a mismatched anchor means either the ptau file was tampered with or the
/// upstream ceremony bytes changed — never silently proceed.
pub fn load_hermez_srs(k: u32) -> ParamsKZG<Bn256> {
    assert!(
        (1..=20).contains(&k),
        "load_hermez_srs: k must be in 1..=20 (Hermez ptau is K=20 depth), got {}",
        k
    );
    let path = default_ptau_cache();
    ensure_ptau_present(&path).expect("failed to ensure ptau cache");

    let t = Instant::now();
    let mut reader = fs::File::open(&path).expect("failed to open ptau cache");
    let material = read_hermez_ptau_and_verify(&mut reader, k);
    assert_eq!(
        material.k20_sha256, HERMEZ_K20_RAW_SRS_SHA256,
        "Hermez K=20 SHA-256 anchor mismatch — ptau file is not the expected ceremony",
    );
    eprintln!(
        "[kzg_source] Hermez SRS derived at k={} ({} raw bytes) in {:?}",
        k,
        material.raw_srs.len(),
        t.elapsed(),
    );

    let mut cursor: &[u8] = &material.raw_srs;
    ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytesUnchecked)
        .expect("failed to parse Hermez-derived raw SRS as ParamsKZG")
}

/// Load a self-generated SRS via halo2-base's `gen_srs(k)`. INSECURE: the
/// trapdoor is materialized in-process from RNG and cached to disk under
/// `PARAMS_DIR`. Never ship keys derived from this to production.
pub fn load_gen_srs(k: u32) -> ParamsKZG<Bn256> {
    eprintln!(
        "[kzg_source] gen_srs(K={}) — INSECURE, self-generated trapdoor",
        k
    );
    halo2_base::utils::fs::gen_srs(k)
}

/// Dispatch on [`ENV_KZG_SOURCE`]: default Hermez, `gen_srs` on explicit opt-in.
///
/// Callers should prefer this over `halo2_base::utils::fs::gen_srs` — it
/// leaves the source choice to CI / the operator without touching source code.
pub fn load_srs(k: u32) -> ParamsKZG<Bn256> {
    match KzgSource::from_env() {
        KzgSource::Hermez => load_hermez_srs(k),
        KzgSource::GenSrs => load_gen_srs(k),
    }
}
