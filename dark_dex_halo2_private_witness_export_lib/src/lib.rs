//! dark_dex_halo2_private_witness_export_lib — collects Merkle proof data from
//! a running acki-nacki node and produces JSON fixtures for the
//! gosh-dark-dex-halo2-new-circuit witness/public-input generation.
//!
//! Library entry point: [`make_private_witness_and_public_data`], driven by
//! the [`ExportParams`] struct.

pub mod block;
pub mod blockchain;
pub mod proof;

use anyhow::ensure;
use node_block_client::envelope_hash;
use node_block_client::history_proof::compute_block_leaf_hash;
use node_block_client::history_proof::HISTORY_PROOF_WINDOW_SIZE;
use node_block_client::BLSSignedEnvelope;
use node_block_client::BlockHeight;
use node_block_client::ThreadIdentifier;
use serde::Serialize;

use crate::blockchain::block_id_for_leaf;
use crate::blockchain::create_client;
use crate::blockchain::get_layer_0_data;
use crate::blockchain::get_layer_n_data;
use crate::blockchain::query_block_with_canonical_id_by_height;
use crate::blockchain::query_block_with_canonical_id_by_id;
use crate::blockchain::query_latest_block_height;
use crate::proof::generate_ext_message_proof;
use crate::proof::generate_layer0_proof;
use crate::proof::generate_layer_n_proof;
use crate::proof::verify_dense_proof;

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

#[derive(Serialize)]
pub struct ChainLinkJson {
    pub active: bool,
    pub siblings_hex: Vec<String>,
    pub position: usize,
    pub leaf_hex: String,
}

#[derive(Serialize)]
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

    let (block, canonical_block_id) = match (&params.block_id, &params.block_height) {
        (Some(id), _) => {
            tracing::info!("Querying block by ID {}...", id);
            query_block_with_canonical_id_by_id(client.clone(), id).await?
        }
        (None, Some(h)) => {
            tracing::info!("Querying block at height {}...", h);
            query_block_with_canonical_id_by_height(
                client.clone(),
                BlockHeight::builder().height(*h).thread_identifier(thread_id).build(),
            )
            .await?
        }
        (None, None) => {
            anyhow::bail!("Either block_id or block_height must be specified");
        }
    };
    let block_id_bytes = block_id_for_leaf(&block, canonical_block_id);

    let block_height = *block.data().common_section().block_height().height();
    tracing::info!("Got block at height {}", block_height);

    let last_block_height =
        *query_latest_block_height(client.clone(), thread_id).await?.height();
    tracing::info!("Latest block height: {}", last_block_height);

    // --- ext_out_message proof ---
    let ext_messages = block.data().common_section().tracked_ext_out_messages();
    let ext_root = *block.data().common_section().tracked_ext_out_messages_root();
    tracing::info!("Block has {} tracked account(s) with ext messages", ext_messages.len());
    tracing::info!("Block ext_out_messages_root: {}", hex::encode(ext_root));
    tracing::info!("Block ID: {}", hex::encode(block_id_bytes));
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
    let env_hash_bytes = envelope_hash(&block).0;
    let block_leaf = compute_block_leaf_hash(&block_id_bytes, &env_hash_bytes, &ext_root);

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
    };

    let json_str = serde_json::to_string_pretty(&fixture)?;
    std::fs::write(&params.output, &json_str)?;
    tracing::info!("Fixture written to {}", params.output);

    Ok(json_str)
}
