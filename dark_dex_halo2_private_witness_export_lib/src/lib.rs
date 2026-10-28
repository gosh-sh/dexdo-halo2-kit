//! dark_dex_halo2_private_witness_export_lib — collects Merkle proof data from
//! a running acki-nacki node and produces JSON fixtures for the
//! gosh-dark-dex-halo2-new-circuit witness/public-input generation.
//!
//! Library entry points: [`make_private_witness_with_anchor`], which takes the
//! anchor layer explicitly (see [`anchor`]), and the older
//! [`make_private_witness_and_public_data`]. Both are driven by the
//! [`ExportParams`] struct.

pub mod anchor;
pub mod blockchain;
pub mod poseidon;
pub mod proof;
pub mod types;

use anyhow::ensure;
use anyhow::Context;
use serde::Serialize;

use crate::poseidon::HISTORY_PROOF_WINDOW_SIZE;
use crate::types::ThreadIdentifier;

use crate::anchor::anchor_block_height;
use crate::anchor::anchor_expiry_height;
use crate::anchor::approx_duration;
use crate::anchor::rung_position;
use crate::anchor::validate_layer;
use crate::anchor::AnchorLayerMode;
use crate::anchor::AnchorOptions;
use crate::anchor::WaitOptions;
use crate::anchor::MAX_ANCHOR_LAYER;
use crate::anchor::NOMINAL_BLOCKS_PER_SECOND;
use crate::blockchain::create_client;
use crate::blockchain::get_layer_0_data;
use crate::blockchain::get_layer_n_data;
use crate::blockchain::query_block_by_height;
use crate::blockchain::query_block_by_id;
use crate::blockchain::query_latest_block_height;
use crate::blockchain::try_query_block_by_height;
use crate::blockchain::GqlProofBlock;
use crate::blockchain::TvmClient;
use crate::proof::generate_ext_message_proof;
use crate::proof::generate_layer0_proof;
use crate::proof::generate_layer_n_proof_at;
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
    /// Legacy layer selector, counted in chain steps above L1: `Some(n)`
    /// anchors to layer `n + 1`. [`make_private_witness_and_public_data`]
    /// reads `None` as "highest layer already produced";
    /// [`make_private_witness_with_anchor`] takes the layer from its `anchor`
    /// argument and only checks that a `Some` here agrees with it.
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
    /// Height of the block that holds the event.
    pub event_block_height: u64,
    /// Block that publishes `final_layer_historical_hash_root_hex` (`T_n`, see
    /// [`anchor`]). A claim can use the root from the next block on.
    pub anchor_block_height: u64,
    /// First block whose history cursor no longer holds that root (`E_n`), or
    /// `null` if beyond `u64`. Once it exists, the chain rejects the proof.
    pub anchor_expires_at_height: Option<u64>,
}

fn bytes_to_hex(b: &[u8; 32]) -> String {
    hex::encode(b)
}

// ---------------------------------------------------------------------------
// Main public API
// ---------------------------------------------------------------------------

/// Legacy entry point. The anchor layer comes from `params.max_layers`
/// (`Some(n)` is layer `n + 1`, `None` the highest layer already produced);
/// it does not wait for the anchor block and rejects evicted anchors. See
/// [`make_private_witness_with_anchor`].
pub async fn make_private_witness_and_public_data(
    params: &ExportParams,
) -> anyhow::Result<String> {
    let anchor = AnchorOptions {
        layer: AnchorLayerMode::from_max_layers(params.max_layers),
        ..AnchorOptions::default()
    };
    make_private_witness_with_anchor(params, &anchor).await
}

/// Builds the fixture for the event in `params`, anchored to the history
/// layer chosen by `anchor`, writes it to `params.output` and returns it.
///
/// Nothing is written if the anchor block does not exist yet (unless
/// `anchor.wait` is set and it appears in time), if the node has already
/// evicted the anchor root (unless `anchor.allow_expired`), or if a rebuilt
/// root differs from the one the node published.
pub async fn make_private_witness_with_anchor(
    params: &ExportParams,
    anchor: &AnchorOptions,
) -> anyhow::Result<String> {
    if let AnchorLayerMode::Explicit(layer) = anchor.layer {
        validate_layer(layer)?;
    }
    if let Some(steps) = params.max_layers {
        let legacy = AnchorLayerMode::from_max_layers(Some(steps));
        ensure!(
            legacy == anchor.layer,
            "max_layers = {steps} selects anchor layer {legacy}, which conflicts with anchor \
             layer {}",
            anchor.layer
        );
    }

    let event_bytes = tvm_types::base64_decode(&params.event_boc)
        .map_err(|e| anyhow::anyhow!("Invalid event_boc base64: {e}"))?;
    let event_msg_hash = tvm_types::read_single_root_boc(event_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid event_boc: {e}"))?
        .repr_hash()
        .inner();

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
        .find(|(_, msg_hash)| *msg_hash == event_msg_hash)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Event BOC message hash {} not found in block tracked ext_out_messages",
                hex::encode(event_msg_hash)
            )
        })?;

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

    // --- anchor: which layer, and is its root published and still accepted ---
    let resolved = resolve_anchor(&client, thread_id, block_height, anchor).await?;
    let layer = resolved.layer;
    let anchor_block = &resolved.anchor_block;
    tracing::info!(
        "Anchor layer {}: root published in block {}, usable until block {}",
        layer,
        anchor_block.height,
        resolved.expires_at.map_or_else(|| "beyond u64".to_string(), |h| h.to_string())
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

    // --- chain of higher-layer proofs: one rung per layer above L1 ---
    let mut chain: Vec<ChainLinkJson> = Vec::new();
    let mut root_cursor = root_layer_0;

    for lower in 1..layer {
        let upper = lower + 1;
        tracing::info!("Collecting layer {} tree data...", upper);
        let (layer_data, sl_root, hl_root) =
            get_layer_n_data(client.clone(), thread_id, block_height, lower as u8).await?;

        // The data leaves come from the node, so finding our lower-layer root
        // at its computed position also checks it against the node's.
        let position = rung_position(block_height, lower)
            .ok_or_else(|| anyhow::anyhow!("layer {lower} rung position does not fit in u64"))?;
        let (root_layer_n, proof_layer_n) =
            generate_layer_n_proof_at(&layer_data, root_cursor, position, sl_root, hl_root)
                .with_context(|| {
                    format!(
                        "the layer-{lower} root rebuilt for the event is not the one the node \
                         published in block {}",
                        anchor_block_height(block_height, lower).unwrap_or_default()
                    )
                })?;

        let valid = verify_dense_proof(&root_layer_n, &root_cursor, position, &proof_layer_n);
        ensure!(valid, "Layer {} proof is invalid", upper);
        tracing::info!(
            "Layer {} proof verified: pos={}, siblings={}, root={}",
            upper,
            position,
            proof_layer_n.len(),
            hex::encode(root_layer_n)
        );

        chain.push(ChainLinkJson {
            active: true,
            siblings_hex: proof_layer_n.iter().map(bytes_to_hex).collect(),
            position,
            leaf_hex: bytes_to_hex(&root_cursor),
        });

        root_cursor = root_layer_n;
    }

    let num_active_chain_steps = chain.len();
    let final_layer_historical_hash_root = root_cursor;

    // --- the final root must be the one the node published ---
    let node_root = anchor_block.history_proofs.get(&(layer as u8)).ok_or_else(|| {
        anyhow::anyhow!(
            "block {} reports no layer-{} history root (it lists layers {:?})",
            anchor_block.height,
            layer,
            anchor_block.history_proofs.keys().collect::<Vec<_>>()
        )
    })?;
    ensure!(
        *node_root == final_layer_historical_hash_root,
        "rebuilt layer-{} root {} differs from the root {} the node published in block {}; \
         refusing to write a fixture the chain would reject",
        layer,
        hex::encode(final_layer_historical_hash_root),
        hex::encode(node_root),
        anchor_block.height
    );

    let fixture = DexFixtureJson {
        description: format!(
            "anchor layer {}: {} chain step(s), event block {}, anchor block {}, W={}",
            layer,
            num_active_chain_steps,
            block_height,
            anchor_block.height,
            HISTORY_PROOF_WINDOW_SIZE
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
        final_layer_number: layer,
        event_block_height: block_height,
        anchor_block_height: anchor_block.height,
        anchor_expires_at_height: resolved.expires_at,
    };

    let json_str = serde_json::to_string_pretty(&fixture)?;
    std::fs::write(&params.output, &json_str)?;
    tracing::info!("Fixture written to {}", params.output);

    Ok(json_str)
}

// ---------------------------------------------------------------------------
// Anchor resolution
// ---------------------------------------------------------------------------

struct ResolvedAnchor {
    layer: u32,
    /// Block `T_n`, which publishes the layer-`layer` root.
    anchor_block: GqlProofBlock,
    /// `E_n`; `None` if beyond `u64`.
    expires_at: Option<u64>,
}

/// Picks the layer, makes sure its anchor block exists (waiting for it if
/// allowed) and that the node still accepts its root.
async fn resolve_anchor(
    client: &TvmClient,
    thread_id: ThreadIdentifier,
    event_height: u64,
    options: &AnchorOptions,
) -> anyhow::Result<ResolvedAnchor> {
    let mut layer = match options.layer {
        AnchorLayerMode::Explicit(layer) => layer,
        AnchorLayerMode::Auto => 1,
    };
    let mut anchor_block =
        wait_for_anchor_block(client, thread_id, event_height, layer, options.wait).await?;

    if options.layer == AnchorLayerMode::Auto {
        while layer < MAX_ANCHOR_LAYER {
            let Some(next_height) = anchor_block_height(event_height, layer + 1) else {
                break;
            };
            if next_height != anchor_block.height {
                match try_query_block_by_height(client.clone(), thread_id, next_height).await? {
                    Some(block) => anchor_block = block,
                    None => break,
                }
            }
            layer += 1;
        }
        tracing::info!("Anchor layer auto: layer {} is the highest one produced", layer);
    }

    let expires_at = anchor_expiry_height(event_height, layer);
    let next_height = anchor_block_height(event_height, layer + 1);
    if let Some(expiry) = expires_at {
        if try_query_block_by_height(client.clone(), thread_id, expiry).await?.is_some() {
            let hint = match next_height {
                Some(next) if layer < MAX_ANCHOR_LAYER => {
                    format!("use --anchor-layer {} (its root is in block {next})", layer + 1)
                }
                _ => "no higher layer is available".to_string(),
            };
            let message = format!(
                "anchor layer {layer}: block {expiry} exists, so the node no longer accepts the \
                 layer-{layer} root from block {}; {hint}, or pass --allow-expired for an \
                 offline fixture",
                anchor_block.height
            );
            ensure!(options.allow_expired, "{message}");
            tracing::warn!("{message}; continuing because expired anchors are allowed");
        } else if let Some(next) = next_height {
            let next_exists = next == anchor_block.height
                || try_query_block_by_height(client.clone(), thread_id, next).await?.is_some();
            if next_exists {
                let head = query_latest_block_height(client.clone(), thread_id).await.ok();
                let (blocks_left, counted_from) = match head {
                    Some(head) => (expiry.saturating_sub(head), "after the current head"),
                    None => (expiry - next, "at most, after that block"),
                };
                tracing::warn!(
                    "anchor layer {layer}: block {next} exists, so the node accepts this root \
                     only until block {expiry}: {blocks_left} block(s) {counted_from}, {} at \
                     ~{NOMINAL_BLOCKS_PER_SECOND} blocks/s. Submit the proof promptly or use \
                     --anchor-layer {}",
                    approx_duration(blocks_left),
                    layer + 1
                );
            }
        }
    }

    Ok(ResolvedAnchor { layer, anchor_block, expires_at })
}

/// Returns block `T_layer` for the event, polling per `wait` while the chain
/// has not produced it yet.
async fn wait_for_anchor_block(
    client: &TvmClient,
    thread_id: ThreadIdentifier,
    event_height: u64,
    layer: u32,
    wait: Option<WaitOptions>,
) -> anyhow::Result<GqlProofBlock> {
    let height = anchor_block_height(event_height, layer).ok_or_else(|| {
        anyhow::anyhow!("anchor layer {layer}: its anchor block height does not fit in u64")
    })?;
    let started = std::time::Instant::now();
    loop {
        if let Some(block) = try_query_block_by_height(client.clone(), thread_id, height).await? {
            return Ok(block);
        }
        let head = query_latest_block_height(client.clone(), thread_id).await.ok();
        let to_go = match head {
            Some(head) => {
                format!("{} block(s) after the current head {head}", height.saturating_sub(head))
            }
            None => format!("at most {} block(s) after the event block", height - event_height),
        };
        let eta = approx_duration(height.saturating_sub(head.unwrap_or(event_height)));
        let status = format!(
            "block {height}, which publishes the layer-{layer} root covering event block \
             {event_height}, has not been produced yet: {to_go}, {eta} at \
             ~{NOMINAL_BLOCKS_PER_SECOND} blocks/s"
        );
        let Some(wait) = wait else {
            anyhow::bail!("anchor layer {layer}: {status}; re-run later or pass --wait-for-anchor");
        };
        let elapsed = started.elapsed();
        ensure!(
            elapsed < wait.timeout,
            "anchor layer {layer}: gave up after {elapsed:.0?}: {status}"
        );
        tracing::info!("Waiting for the layer-{layer} anchor: {status}");
        tokio::time::sleep(wait.poll_interval.min(wait.timeout - elapsed)).await;
    }
}
