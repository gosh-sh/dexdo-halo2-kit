//! Bundle orchestrator — produces 1 DexFinal proof + `N_BUNDLE` MultiHopProof
//! snarks from a single [`BundleWitnessJson`].
//!
//! The [`BundleProver`] holds one long-lived [`Prover`] (DexFinal) and one
//! long-lived [`MultiHopProver`], so keygen happens at most twice across
//! the whole bundle regardless of how many snarks are produced.
//!
//! ## Cross-check (native)
//!
//! Before proof generation the orchestrator loads the referenced DexFinal
//! fixture, runs the stateless `compute_instances_from_json` helper to
//! materialise its salted-endpoint values, and asserts:
//!
//! * `dex_final.salt_commitment == bundle.snarks[i].salt_commitment` for every `i`
//! * `dex_final.salted_x_start == bundle.snarks[0].hops[0].salted_start_block_id`
//! * `dex_final.salted_y_end == bundle.snarks[N-1].hops[H-1].salted_end_block_id`
//! * `bundle.snarks[i].hops[H-1].salted_end == bundle.snarks[i+1].hops[0].salted_start`
//!
//! These are the same equalities the on-chain `verify_bundle` enforces on
//! the *public instances of the emitted proofs*; running them here catches
//! witness-side glue bugs before we spend ~30-60 s per snark on real
//! prove-time.

use gosh_dark_dex_halo2_new_circuit::bundle_verifier::{
    multihop_offset, verify_bundle, BundleError, BundleProof,
};
use gosh_dark_dex_halo2_new_circuit::multi_hop_witness::{H_HOPS_PER_PROOF, N_BUNDLE};
use gosh_dark_dex_halo2_new_circuit::salt::compute_salt_commitment_native;
use gosh_dark_dex_halo2_new_circuit::salt::compute_salt_native;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;

use dex_witness_export::bundle_witness::BundleWitnessJson;

use serde::{Deserialize, Serialize};

use std::fs;
use std::path::Path;

use crate::multi_hop::{MultiHopProofOutput, MultiHopProver};
use crate::{compute_instances_from_json, ProofOutput, Prover, ProverError};

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// Full bundle output — 1 DexFinal proof + `N_BUNDLE` MultiHopProof snarks.
///
/// The order matches `bundle_verifier::verify_bundle`'s convention: index 0
/// is the DexFinal proof, indices `1..=N_BUNDLE` are the MultiHop snarks in
/// bundle order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProofsOutput {
    /// Human-readable summary carried over from the input witness.
    pub description: String,
    /// The DexFinal proof.
    pub dex_final: ProofOutput,
    /// The `N_BUNDLE` MultiHopProof snarks, in bundle order.
    pub multi_hops: Vec<MultiHopProofOutput>,
}

// ---------------------------------------------------------------------------
// Native cross-check helpers
// ---------------------------------------------------------------------------

fn hex_to_fr(hex_str: &str) -> Result<Fr, ProverError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ProverError::Fixture(format!("invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| ProverError::Fixture(format!("expected 32 bytes, got {}", v.len())))?;
    Option::from(Fr::from_repr(arr))
        .ok_or_else(|| ProverError::Fixture("hex value is not a valid Fr element".into()))
}

fn native_cross_check(
    bundle: &BundleWitnessJson,
    dex_final_salt_commitment: Fr,
    dex_final_salted_x_start: Fr,
    dex_final_salted_y_end: Fr,
) -> Result<(), ProverError> {
    // (1) salt_commitment agreement across DexFinal + every snark.
    let sk_u = hex_to_fr(&bundle.sk_u_hex)?;
    let derived_salt_commitment = compute_salt_commitment_native(compute_salt_native(sk_u));
    if derived_salt_commitment != dex_final_salt_commitment {
        return Err(ProverError::Fixture(
            "bundle sk_u disagrees with DexFinal fixture's derived salt_commitment".into(),
        ));
    }
    for (i, snark) in bundle.snarks.iter().enumerate() {
        let snark_sc = hex_to_fr(&snark.salt_commitment_hex)?;
        if snark_sc != dex_final_salt_commitment {
            return Err(ProverError::Fixture(format!(
                "bundle.snarks[{}].salt_commitment disagrees with DexFinal salt_commitment",
                i
            )));
        }
    }

    // (2) Head link: DexFinal.salted_x_start == snarks[0].hops[0].salted_start.
    let head_start = hex_to_fr(&bundle.snarks[0].hops[0].salted_start_block_id_hex)?;
    if head_start != dex_final_salted_x_start {
        return Err(ProverError::Fixture(
            "DexFinal.salted_x_start != bundle.snarks[0].hops[0].salted_start_block_id".into(),
        ));
    }

    // (3) Tail link: DexFinal.salted_y_end == snarks[N-1].hops[H-1].salted_end.
    let tail_end = hex_to_fr(
        &bundle.snarks[N_BUNDLE - 1].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id_hex,
    )?;
    if tail_end != dex_final_salted_y_end {
        return Err(ProverError::Fixture(
            "DexFinal.salted_y_end != bundle.snarks[N-1].hops[H-1].salted_end_block_id".into(),
        ));
    }

    // (4) Inter-snark continuity.
    for i in 0..(N_BUNDLE - 1) {
        let left_end = hex_to_fr(
            &bundle.snarks[i].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id_hex,
        )?;
        let right_start = hex_to_fr(&bundle.snarks[i + 1].hops[0].salted_start_block_id_hex)?;
        if left_end != right_start {
            return Err(ProverError::Fixture(format!(
                "bundle continuity break between snark {} and {}",
                i,
                i + 1
            )));
        }
    }

    // (5) Intra-snark continuity within each snark.
    for (i, snark) in bundle.snarks.iter().enumerate() {
        for h in 0..(H_HOPS_PER_PROOF - 1) {
            let left_end = hex_to_fr(&snark.hops[h].salted_end_block_id_hex)?;
            let right_start = hex_to_fr(&snark.hops[h + 1].salted_start_block_id_hex)?;
            if left_end != right_start {
                return Err(ProverError::Fixture(format!(
                    "bundle.snarks[{}] hop continuity break between hop {} and {}",
                    i,
                    h,
                    h + 1
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// Stateful bundle prover — holds one DexFinal [`Prover`] and one
/// [`MultiHopProver`], so keygen happens at most twice per process
/// regardless of how many bundles are produced.
pub struct BundleProver {
    dex_final_prover: Prover,
    multi_hop_prover: MultiHopProver,
}

impl BundleProver {
    /// Create a new bundle prover.
    ///
    /// * `dex_final_cache_dir` — optional PK/BP/VK cache dir for the DexFinal
    ///   `DarkDexCircuit` (K=19).
    /// * `multi_hop_cache_dir` — optional PK/BP/VK cache dir for the
    ///   MultiHopProof snarks (K=17).
    ///
    /// Both SRSes are loaded eagerly; PKs are loaded from cache if present or
    /// generated lazily on first `generate` call.
    pub fn new(
        dex_final_cache_dir: Option<&Path>,
        multi_hop_cache_dir: Option<&Path>,
    ) -> Result<Self, ProverError> {
        let dex_final_prover = Prover::new(dex_final_cache_dir)?;
        let multi_hop_prover = MultiHopProver::new(multi_hop_cache_dir)?;
        Ok(Self {
            dex_final_prover,
            multi_hop_prover,
        })
    }

    /// Produce the DexFinal proof + `N_BUNDLE` MultiHopProof snarks.
    ///
    /// The DexFinal fixture is loaded from `bundle.dex_final_fixture_path`
    /// (resolved relative to CWD).
    pub fn generate(
        &mut self,
        bundle_json_str: &str,
    ) -> Result<BundleProofsOutput, ProverError> {
        let bundle: BundleWitnessJson = serde_json::from_str(bundle_json_str)
            .map_err(|e| ProverError::Fixture(format!("bundle JSON parse: {e}")))?;

        // -- 1. Load DexFinal fixture from disk ------------------------------
        let dex_final_json_str = fs::read_to_string(&bundle.dex_final_fixture_path)
            .map_err(|e| ProverError::Fixture(format!(
                "cannot read dex_final_fixture_path '{}': {e}",
                bundle.dex_final_fixture_path
            )))?;

        // -- 2. Native pre-flight cross-check --------------------------------
        //
        // Uses `compute_instances_from_json` to derive the DexFinal salted
        // endpoints + salt_commitment without touching the prover; catches
        // witness glue bugs before we spend ~60s on the DexFinal proof.
        let dex_final_values = compute_instances_from_json(&dex_final_json_str)?;
        let dex_final_salt_commitment = hex_to_fr(&dex_final_values.salt_commitment)?;
        let dex_final_salted_x_start = hex_to_fr(&dex_final_values.salted_x_start)?;
        let dex_final_salted_y_end = hex_to_fr(&dex_final_values.salted_y_end)?;
        native_cross_check(
            &bundle,
            dex_final_salt_commitment,
            dex_final_salted_x_start,
            dex_final_salted_y_end,
        )?;

        // -- 3. Produce the DexFinal proof -----------------------------------
        eprintln!("[bundle] generating DexFinal proof (K=19)...");
        let dex_final = self.dex_final_prover.generate_proof(&dex_final_json_str)?;

        // -- 4. Produce all N_BUNDLE MultiHop snarks -------------------------
        let mut multi_hops = Vec::with_capacity(N_BUNDLE);
        for (i, snark) in bundle.snarks.iter().enumerate() {
            eprintln!(
                "[bundle] generating MultiHopProof snark {}/{} (K=17)...",
                i + 1,
                N_BUNDLE
            );
            let out = self
                .multi_hop_prover
                .generate_proof(snark, &bundle.sk_u_hex)?;
            multi_hops.push(out);
        }

        Ok(BundleProofsOutput {
            description: bundle.description,
            dex_final,
            multi_hops,
        })
    }

    /// Borrow the underlying MultiHop prover — used by
    /// [`BundleProofsOutput::verify_in_process`] callers that hold a
    /// `BundleProver` and want to self-check the emitted snarks.
    pub fn multi_hop_prover(&self) -> &MultiHopProver {
        &self.multi_hop_prover
    }
}

// ---------------------------------------------------------------------------
// Bundle-shape helpers
// ---------------------------------------------------------------------------

/// Materialise a bundle output as the `Vec<BundleProof>` shape consumed by
/// `dex_halo2_circuit::bundle_verifier::verify_bundle` — DexFinal at index 0,
/// then the `N_BUNDLE` MultiHop snarks in bundle order.
///
/// The `Vec<Fr>` inside each entry is the exact public-instance vector the
/// halo2 verifier consumes for that snark, so the returned bundle is the
/// same shape `RootPN.sol` reads on-chain.
pub fn output_to_bundle_proofs(
    output: &BundleProofsOutput,
) -> Result<Vec<BundleProof>, ProverError> {
    let mut bundle = Vec::with_capacity(1 + N_BUNDLE);

    // DexFinal instances: parse `pub_inputs_hex` (13 × 32 B LE) into a Vec<Fr>.
    let dex_final_bytes = hex::decode(&output.dex_final.pub_inputs_hex).map_err(|e| {
        ProverError::Fixture(format!("dex_final.pub_inputs_hex decode: {e}"))
    })?;
    if dex_final_bytes.len() % 32 != 0 {
        return Err(ProverError::Fixture(format!(
            "dex_final.pub_inputs_hex length {} is not a multiple of 32",
            dex_final_bytes.len()
        )));
    }
    let mut dex_final_instances = Vec::with_capacity(dex_final_bytes.len() / 32);
    for chunk in dex_final_bytes.chunks_exact(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        let fr = Option::from(Fr::from_repr(arr)).ok_or_else(|| {
            ProverError::Fixture("dex_final instance is not a valid Fr element".into())
        })?;
        dex_final_instances.push(fr);
    }
    bundle.push(BundleProof::new_dex_final(dex_final_instances));

    // MultiHop instances: [salted_start, salted_end, salt_commitment].
    for mh in &output.multi_hops {
        let salted_start = hex_to_fr(&mh.salted_start_block_id)?;
        let salted_end = hex_to_fr(&mh.salted_end_block_id)?;
        let salt_commitment = hex_to_fr(&mh.salt_commitment)?;
        let mut instances = vec![Fr::zero(); 3];
        instances[multihop_offset::SALTED_START_BLOCK_ID] = salted_start;
        instances[multihop_offset::SALTED_END_BLOCK_ID] = salted_end;
        instances[multihop_offset::SALT_COMMITMENT] = salt_commitment;
        bundle.push(BundleProof::new_multi_hop(instances));
    }

    Ok(bundle)
}

// ---------------------------------------------------------------------------
// Bundle self-verify
// ---------------------------------------------------------------------------

/// Public-instance self-verify — runs `bundle_verifier::verify_bundle`
/// against the exact instance vectors emitted in `output`. Does *not*
/// re-run the halo2 KZG verifier on the individual proof bytes.
///
/// This mirrors what `RootPN.sol` runs on-chain: the smart contract does
/// not re-verify proofs, it consumes only the public instances (each
/// halo2 verifier ran once during proof submission).
pub fn verify_bundle_publics(output: &BundleProofsOutput) -> Result<(), ProverError> {
    let bundle = output_to_bundle_proofs(output)?;
    verify_bundle(&bundle).map_err(|e: BundleError| {
        ProverError::ProofGen(format!("bundle_verifier rejected bundle: {:?}", e))
    })
}

