//! dark_dex_halo2_private_witness_export_lib — collects Merkle proof data from
//! a running acki-nacki node and produces JSON fixtures for the
//! gosh-dark-dex-halo2-new-circuit witness/public-input generation.
//!
//! Library entry point: [`make_private_witness_and_public_data`], driven by
//! the [`ExportParams`] struct.

pub mod blockchain;
pub mod bundle_witness;
pub mod hop_chain;
pub mod poseidon;
pub mod proof;
pub mod types;

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};

use crate::poseidon::HISTORY_PROOF_WINDOW_SIZE;
use crate::types::ThreadIdentifier;

use crate::blockchain::create_client;
use crate::blockchain::get_layer_0_data;
use crate::blockchain::get_layer_n_data;
use crate::blockchain::query_block_by_height;
use crate::blockchain::query_block_by_id;
use crate::blockchain::query_latest_block_height;
use crate::blockchain::TRACKED_EXT_OUT_MESSAGES_ROOT_LEAF_INDEX;
use crate::proof::generate_ext_message_proof;
use crate::proof::generate_layer0_proof;
use crate::proof::generate_layer_n_proof;
use crate::proof::verify_dense_proof;

// Depth-4 SHA block-id tree helpers live in the sibling circuit crate;
// consuming them directly keeps the exporter and the prover byte-for-byte
// in sync with the in-circuit reconstruction gadget.
use dex_halo2_circuit::block_id_tree::compute_block_id_from_l8_native;
use dex_halo2_circuit::multi_hop_witness::{
    block_merkle_leaf_proof, block_merkle_root, verify_block_merkle_leaf_proof,
    BLOCK_MERKLE_DEPTH,
};

// ---------------------------------------------------------------------------
// Public input parameters
// ---------------------------------------------------------------------------

pub struct ExportParams {
    /// Network endpoint (e.g. "localhost" or "http://127.0.0.1:80")
    pub network: String,
    /// Block height containing the event (use this OR block_id)
    pub block_height: Option<u64>,
    /// Block ID (hash) containing the event (use this OR block_height)
    pub block_id: Option<String>,
    /// Event BOC in base64 encoding
    pub event_boc: String,
    /// Secret key sk_u in hex
    pub sk_u: String,
    /// Ephemeral public key in hex (32 bytes, the pubkey committed to the voucher)
    pub ephemeral_pubkey: String,
    /// Output JSON file path
    pub output: String,
    /// Maximum number of chain layers to collect (strict requirement if set)
    pub max_layers: Option<u32>,
}

// ---------------------------------------------------------------------------
// JSON output structures (matches DexFixtureJson in test_real_data.rs)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct ChainLinkJson {
    pub active: bool,
    pub siblings_hex: Vec<String>,
    pub position: usize,
    pub leaf_hex: String,
}

#[derive(Serialize, Deserialize)]
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
    /// Final root to which the whole construction converges (L0 cycle root if
    /// the dense_chain is empty, otherwise the root of the topmost layer).
    /// This is what `halo2-proover` emits as `final_layer_historical_hash_root`
    /// and what the contract passes to `gosh.check_layer_hash`.
    pub final_layer_historical_hash_root_hex: String,
    /// CONTRACT-FACING layer index corresponding to
    /// `final_layer_historical_hash_root_hex`. Equals `num_active_chain_steps + 1`.
    pub final_layer_number: u32,
    /// Depth-4 SHA-256 block-id-tree sibling `H07 = SHA-root(leaves 0..=7)`.
    ///
    /// Required by `halo2-proover` for real proof generation (spec §12.4):
    /// the circuit binds `x_l8_tracked_ext_out_root` into `x_block_id` via
    /// a single top-level SHA hop against this sibling. Derived here from
    /// the GQL-served `block_merkle_tree_leaves` — the exporter also
    /// self-checks that the reconstruction matches `block_id` before
    /// emitting the fixture.
    pub x_block_id_h07_sibling_hex: String,
    /// The 16 depth-4 SHA-256 leaves of the block-id tree as served by
    /// GQL (spec §12.4). Passed through so downstream bundle-witness
    /// builders can recompute per-hop `block_merkle_leaf_proof_l7`
    /// openings without re-querying the GQL server. Leaf 8 must equal
    /// `tracked_ext_out_messages_root`; leaves 9..=15 are BC-007 zero
    /// padding.
    pub block_merkle_tree_leaves_hex: Vec<String>,
    /// Variable-width parent + cross-thread `proof_block_refs`
    /// (spec §5.2). Element 0 is the parent of this block on the same
    /// thread; the bundle-witness chain walker walks this list
    /// backwards to synthesize the hop chain. Empty for the chain root.
    pub proof_block_refs_hex: Vec<String>,
}

fn bytes_to_hex(b: &[u8; 32]) -> String {
    hex::encode(b)
}

// ---------------------------------------------------------------------------
// Main public API
// ---------------------------------------------------------------------------

pub async fn make_private_witness_and_public_data(
    params: &ExportParams,
) -> anyhow::Result<String> {
    let client = create_client(&params.network)?;
    let thread_id = ThreadIdentifier::default();

    let block = match (&params.block_id, &params.block_height) {
        (Some(id), _) => {
            tracing::info!("Querying block by ID {}...", id);
            query_block_by_id(client.clone(), id).await?
        }
        (None, Some(h)) => {
            tracing::info!("Querying block at height {}...", h);
            query_block_by_height(client.clone(), thread_id, *h).await?
        }
        (None, None) => {
            anyhow::bail!("Either block_id or block_height must be specified");
        }
    };

    let block_height = block.height;
    tracing::info!("Got block at height {}", block_height);

    let last_block_height = query_latest_block_height(client.clone(), thread_id).await?;
    tracing::info!("Latest block height: {}", last_block_height);

    // --- ext_out_message proof ---
    let ext_messages = &block.tracked_ext_out_messages;
    let ext_root = block.tracked_ext_out_messages_root;
    tracing::info!("Block has {} tracked account(s) with ext messages", ext_messages.len());
    tracing::info!("Block ext_out_messages_root: {}", hex::encode(ext_root));
    tracing::info!("Block ID: {}", hex::encode(block.block_id));
    for (routing, msgs) in ext_messages.iter() {
        tracing::info!("  Account routing: {}, messages: {}", routing, msgs.len());
        for msg in msgs {
            tracing::info!("    msg hash: {}", hex::encode(msg));
        }
    }

    ensure!(!ext_messages.is_empty(), "Block has no tracked ext_out_messages");

    let (target_routing, target_msg_hash) = ext_messages
        .iter()
        .flat_map(|(routing, msgs)| msgs.iter().map(move |m| (*routing, *m)))
        .next()
        .ok_or(anyhow::anyhow!("No ext messages in block"))?;

    let (dapp_id, account_id) = target_routing.unpack_for_hash();
    tracing::info!(
        "Target message: dapp={}, account={}, hash={}",
        hex::encode(dapp_id),
        hex::encode(account_id),
        hex::encode(target_msg_hash)
    );

    let (computed_root, _msg_leaf, msg_pos, inner_proof) =
        generate_ext_message_proof(ext_messages, &target_routing, &target_msg_hash)?;

    ensure!(
        computed_root == ext_root,
        "Computed ext_out root {} != block ext_out root {}",
        hex::encode(computed_root),
        hex::encode(ext_root)
    );
    let inner_valid = verify_dense_proof(&computed_root, &_msg_leaf, msg_pos, &inner_proof);
    ensure!(inner_valid, "Inner ext_message proof is invalid");
    tracing::info!(
        "Inner proof verified: events_proof_position={}, siblings={}",
        msg_pos,
        inner_proof.len()
    );

    // --- block proof (L0) ---
    let block_id_bytes = block.block_id;
    let env_hash_bytes = block.envelope_hash;
    let block_leaf = block.block_leaf_hash();

    let target_pos_in_window = (block_height % HISTORY_PROOF_WINDOW_SIZE as u64) as usize;

    let (leaf_hashes, same_layer_root, higher_layer_root) =
        get_layer_0_data(client.clone(), thread_id, block_height).await?;

    let (root_layer_0, proof_layer_0, pos_layer_0) = generate_layer0_proof(
        &leaf_hashes,
        target_pos_in_window,
        same_layer_root,
        higher_layer_root,
    )?;

    let outer_valid =
        verify_dense_proof(&root_layer_0, &block_leaf, pos_layer_0, &proof_layer_0);
    ensure!(outer_valid, "Outer layer 0 proof is invalid");
    tracing::info!(
        "Block proof verified: position={}, siblings={}, root={}",
        pos_layer_0,
        proof_layer_0.len(),
        hex::encode(root_layer_0)
    );

    // --- chain of higher-layer proofs ---
    let upper_cap = params.max_layers.unwrap_or(u32::MAX);
    let mut available_max_layer = 0u32;
    loop {
        if available_max_layer >= upper_cap {
            break;
        }
        let Some(denominator) =
            (HISTORY_PROOF_WINDOW_SIZE as u64).checked_pow(available_max_layer + 1)
        else {
            break;
        };
        let Some(next_layer_height) =
            block_height.div_ceil(denominator).checked_mul(denominator)
        else {
            break;
        };
        if next_layer_height > last_block_height {
            tracing::info!(
                "Layer {} next height {} > last block height {}, stopping",
                available_max_layer + 1,
                next_layer_height,
                last_block_height
            );
            break;
        }
        available_max_layer += 1;
    }
    while available_max_layer > 0 {
        let Some(denom) =
            (HISTORY_PROOF_WINDOW_SIZE as u64).checked_pow(available_max_layer + 1)
        else {
            available_max_layer -= 1;
            continue;
        };
        let Some(boundary) = block_height.div_ceil(denom).checked_mul(denom) else {
            available_max_layer -= 1;
            continue;
        };
        if boundary > last_block_height {
            tracing::info!(
                "Layer {} boundary {} > last block height {}, reducing available_max_layer",
                available_max_layer,
                boundary,
                last_block_height
            );
            available_max_layer -= 1;
        } else {
            break;
        }
    }
    tracing::info!("Max available layers above L0: {}", available_max_layer);

    let max_layer = match params.max_layers {
        Some(requested) => {
            anyhow::ensure!(
                available_max_layer >= requested,
                "requested max_layers = {} but only {} layer(s) are available on-chain \
                 (last_block_height = {}, block_height = {}). Wait for the chain to \
                 reach height {} before re-running.",
                requested,
                available_max_layer,
                last_block_height,
                block_height,
                block_height
                    .div_ceil(
                        (HISTORY_PROOF_WINDOW_SIZE as u64)
                            .checked_pow(requested + 1)
                            .unwrap_or(u64::MAX)
                    )
                    .saturating_mul(
                        (HISTORY_PROOF_WINDOW_SIZE as u64)
                            .checked_pow(requested + 1)
                            .unwrap_or(u64::MAX)
                    )
            );
            requested
        }
        None => available_max_layer,
    };

    let mut chain: Vec<ChainLinkJson> = Vec::new();
    let mut root_cursor = root_layer_0;

    for layer in 1..=max_layer {
        tracing::info!("Collecting layer {} data...", layer);
        let (layer_data, sl_root, hl_root) =
            get_layer_n_data(client.clone(), thread_id, block_height, layer as u8).await?;

        let (root_layer_n, proof_layer_n, pos_layer_n) =
            generate_layer_n_proof(&layer_data, root_cursor, sl_root, hl_root)?;

        let valid =
            verify_dense_proof(&root_layer_n, &root_cursor, pos_layer_n, &proof_layer_n);
        ensure!(valid, "Layer {} proof is invalid", layer);
        tracing::info!(
            "Layer {} proof verified: pos={}, siblings={}, root={}",
            layer,
            pos_layer_n,
            proof_layer_n.len(),
            hex::encode(root_layer_n)
        );

        chain.push(ChainLinkJson {
            active: true,
            siblings_hex: proof_layer_n.iter().map(bytes_to_hex).collect(),
            position: pos_layer_n,
            leaf_hex: bytes_to_hex(&root_cursor),
        });

        root_cursor = root_layer_n;
    }

    let num_active_chain_steps = chain.len();
    let final_layer_historical_hash_root = root_cursor;

    // --- depth-4 SHA block-id tree self-check + H07 sibling ---
    //
    // The circuit reconstructs `x_block_id` from a single top-level SHA
    // hop against the H07 sibling; before we hand the fixture off we
    // verify the GQL-served leaves are internally consistent (leaf 8 ==
    // tracked_ext_out_messages_root; SHA-root(leaves) == block_id;
    // depth-4 opening of leaf 8 verifies; native compute helper
    // reproduces block_id from leaf 8 + top sibling).
    let block_merkle_leaves = block.block_merkle_tree_leaves;
    ensure!(
        block_merkle_leaves[TRACKED_EXT_OUT_MESSAGES_ROOT_LEAF_INDEX]
            == block.tracked_ext_out_messages_root,
        "block_merkle_tree_leaves[8] ({}) does not match tracked_ext_out_messages_root ({})",
        hex::encode(block_merkle_leaves[TRACKED_EXT_OUT_MESSAGES_ROOT_LEAF_INDEX]),
        hex::encode(block.tracked_ext_out_messages_root)
    );
    let computed_block_id = block_merkle_root(&block_merkle_leaves);
    ensure!(
        computed_block_id == block.block_id,
        "SHA-root(block_merkle_tree_leaves) ({}) does not match block.block_id ({})",
        hex::encode(computed_block_id),
        hex::encode(block.block_id)
    );
    let leaf8_proof = block_merkle_leaf_proof(
        &block_merkle_leaves,
        TRACKED_EXT_OUT_MESSAGES_ROOT_LEAF_INDEX,
    );
    ensure!(
        verify_block_merkle_leaf_proof(
            &block.block_id,
            &block.tracked_ext_out_messages_root,
            TRACKED_EXT_OUT_MESSAGES_ROOT_LEAF_INDEX,
            &leaf8_proof,
        ),
        "depth-4 SHA leaf-8 opening does not verify against block.block_id"
    );
    let x_block_id_h07_sibling = leaf8_proof[BLOCK_MERKLE_DEPTH - 1];
    let derived_block_id = compute_block_id_from_l8_native(
        &block.tracked_ext_out_messages_root,
        &x_block_id_h07_sibling,
    );
    ensure!(
        derived_block_id == block.block_id,
        "compute_block_id_from_l8_native disagrees with block.block_id \
         (derived {} vs block {})",
        hex::encode(derived_block_id),
        hex::encode(block.block_id)
    );
    tracing::info!(
        "Depth-4 SHA opening OK: H07 sibling = {}",
        hex::encode(x_block_id_h07_sibling)
    );

    let fixture = DexFixtureJson {
        description: format!(
            "L{} test case: {} chain step(s), block height {}, W={}",
            max_layer, num_active_chain_steps, block_height, HISTORY_PROOF_WINDOW_SIZE
        ),
        sk_u_hex: params.sk_u.clone(),
        ephemeral_pubkey_hex: params.ephemeral_pubkey.clone(),
        event_boc_base64: params.event_boc.clone(),
        events_proof_siblings_hex: inner_proof.iter().map(bytes_to_hex).collect(),
        events_proof_position: msg_pos,
        account_dapp_id_hex: bytes_to_hex(&dapp_id),
        account_id_hex: bytes_to_hex(&account_id),
        block_id_hex: bytes_to_hex(&block_id_bytes),
        envelope_hash_hex: bytes_to_hex(&env_hash_bytes),
        block_proof_siblings_hex: proof_layer_0.iter().map(bytes_to_hex).collect(),
        block_proof_position: pos_layer_0,
        num_active_chain_steps,
        dense_chain: chain,
        final_layer_historical_hash_root_hex: bytes_to_hex(&final_layer_historical_hash_root),
        final_layer_number: max_layer + 1,
        x_block_id_h07_sibling_hex: bytes_to_hex(&x_block_id_h07_sibling),
        block_merkle_tree_leaves_hex: block_merkle_leaves.iter().map(bytes_to_hex).collect(),
        proof_block_refs_hex: block.proof_block_refs.iter().map(bytes_to_hex).collect(),
    };

    let json_str = serde_json::to_string_pretty(&fixture)?;
    std::fs::write(&params.output, &json_str)?;
    tracing::info!("Fixture written to {}", params.output);

    Ok(json_str)
}

// ---------------------------------------------------------------------------
// Bundle-witness orchestrator (E6): DexFinal fixture + MultiHop bundle
// witness in one call, sharing GQL client and salt derivation.
// ---------------------------------------------------------------------------

/// Additional parameters for [`make_dex_final_and_bundle_witnesses`].
///
/// The bundle witness references the DexFinal fixture by *path*
/// (`dex_final_fixture_path` inside `BundleWitnessJson`) rather than
/// inlining it, so the two artifacts can be regenerated independently.
pub struct BundleParams {
    /// Output path for the bundle witness JSON (mirror of `ExportParams::output`
    /// but for the bundle side).
    pub bundle_output: String,
    /// Ordered chain `[X_block_id_hex, ..., Y_block_id_hex]` (oldest to
    /// newest). Length in `[1, 21]`. For t=0 (single-thread) pass
    /// `[X]` — a single entry equal to the DexFinal event block; the
    /// walker emits 20 inactive-padding slots and the bundle shape is
    /// indistinguishable from the multi-thread case (spec §7.5).
    pub path_hex: Vec<String>,
    /// Optional human-readable description embedded in the bundle JSON.
    /// Defaults to a summary of `path_hex.len() - 1` real-hop count.
    pub description: Option<String>,
}

/// Build BOTH the DexFinal fixture and the MultiHop bundle witness in one
/// call. Returns `(dex_final_json, bundle_json)` — both are also written to
/// disk at the paths configured in `ExportParams::output` and
/// `BundleParams::bundle_output` respectively.
///
/// Cross-check: `bundle_params.path_hex[0]` must equal the DexFinal
/// event block's `block_id_hex`; otherwise the bundle's `salted_X_start`
/// would not equal the DexFinal `salted_X_start` and
/// `dex_halo2_circuit::bundle_verifier::verify_bundle` would reject the
/// pair on-chain.
///
/// ## Current single-block DexFinal limitation
///
/// The existing [`make_private_witness_and_public_data`] fetches ONE
/// block and uses it as both the event source (X-side ext-out proof)
/// and the anchor source (Y-side block-leaf + layer chain). This is
/// exact for t=0 (X = Y) but incorrect for t≠0 (event happens on
/// thread t, anchor is a different thread-0 block). Populating the
/// t≠0 DexFinal fixture requires a follow-up slice: extend
/// `DexFixtureJson` with `x_*` / `y_*` field split, fetch both blocks
/// here, and update the halo2-proover consumer at
/// `halo2-proover/src/lib.rs:144` accordingly. Until then, passing a
/// `path_hex` where `path.first() != path.last()` triggers a hard
/// error at the field-mismatch check below.
///
/// The unified chain walker itself already handles both cases — see
/// `hop_chain::build_bundle_witness`; only the DexFinal side needs
/// extension.
pub async fn make_dex_final_and_bundle_witnesses(
    params: &ExportParams,
    bundle_params: &BundleParams,
) -> anyhow::Result<(String, String)> {
    let dex_final_json = make_private_witness_and_public_data(params).await?;

    let fixture: DexFixtureJson = serde_json::from_str(&dex_final_json)
        .context("failed to re-parse DexFinal fixture JSON we just wrote")?;
    let event_block_id_hex = fixture.block_id_hex.clone();

    ensure!(
        !bundle_params.path_hex.is_empty(),
        "bundle path must contain at least the event block (path[0] = X)"
    );
    ensure!(
        bundle_params.path_hex[0] == event_block_id_hex,
        "bundle path[0] ({}) does not match DexFinal event block_id ({}); \
         salted_X_start would diverge and verify_bundle would reject the pair",
        bundle_params.path_hex[0],
        event_block_id_hex
    );

    // Detect the t≠0 case that would need a two-block DexFinal fixture.
    let anchor_hex = bundle_params
        .path_hex
        .last()
        .expect("path non-empty checked above");
    ensure!(
        *anchor_hex == event_block_id_hex,
        "bundle path spans distinct X ({}) and Y ({}) blocks — this is the \
         t≠0 case which requires a two-block DexFinal fixture (`x_*` / `y_*` \
         field split + Y-block fetch). The chain walker itself supports it; \
         the DexFinal fixture shape does not, yet. Track this at task #28 \
         (follow-up slice).",
        event_block_id_hex,
        anchor_hex
    );

    let client = crate::blockchain::create_client(&params.network)?;
    let description = bundle_params.description.clone().unwrap_or_else(|| {
        format!(
            "bundle for event block {} (path len {}, real hops {})",
            &event_block_id_hex[..16.min(event_block_id_hex.len())],
            bundle_params.path_hex.len(),
            bundle_params.path_hex.len().saturating_sub(1),
        )
    });

    let bundle = hop_chain::build_bundle_witness(
        client,
        &params.sk_u,
        &params.output,
        &bundle_params.path_hex,
        description,
    )
    .await?;

    let bundle_json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&bundle_params.bundle_output, &bundle_json)
        .with_context(|| format!("failed to write {}", bundle_params.bundle_output))?;
    tracing::info!("Bundle witness written to {}", bundle_params.bundle_output);

    Ok((dex_final_json, bundle_json))
}
