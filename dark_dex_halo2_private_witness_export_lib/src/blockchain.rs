use std::ops::Div;
use std::sync::Arc;

use anyhow::ensure;
use node_block_client::history_proof::compute_block_leaf_hash;
use node_block_client::history_proof::LayerNumber;
use node_block_client::history_proof::HISTORY_PROOF_WINDOW_SIZE;
use node_block_client::AckiNackiBlock;
use node_block_client::BLSSignedEnvelope;
use node_block_client::BlockHeight;
use node_block_client::Envelope;
use node_block_client::ThreadIdentifier;
use node_block_client::envelope_hash;
use serde_json::json;
use serde_json::Value;

use crate::block::decode_envelope;

/// Lightweight GraphQL client backed by reqwest.
pub struct GqlClient {
    http: reqwest::Client,
    url: String,
}

pub type TvmClient = Arc<GqlClient>;

pub fn create_client(network: &str) -> anyhow::Result<TvmClient> {
    // Accept either a bare host ("localhost") or a full URL.
    let url = if network.starts_with("http://") || network.starts_with("https://") {
        if network.trim_end_matches('/').ends_with("/graphql") {
            network.to_string()
        } else {
            format!("{}/graphql", network.trim_end_matches('/'))
        }
    } else {
        format!("http://{}/graphql", network)
    };
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| anyhow::format_err!("failed to create http client: {}", e))?;
    Ok(Arc::new(GqlClient { http, url }))
}

async fn gql_query(client: &GqlClient, query: &str) -> anyhow::Result<Value> {
    let resp = client
        .http
        .post(&client.url)
        .json(&json!({ "query": query }))
        .send()
        .await
        .map_err(|e| anyhow::format_err!("Failed to execute query: {}", e))?;
    let body: Value = resp
        .json()
        .await
        .map_err(|e| anyhow::format_err!("Failed to decode GraphQL response: {}", e))?;
    if let Some(errors) = body.get("errors") {
        anyhow::bail!("GraphQL error: {}", errors);
    }
    body.get("data").cloned().ok_or_else(|| anyhow::format_err!("No data in GraphQL response"))
}

fn extract_boc(block_obj: &Value) -> anyhow::Result<String> {
    block_obj
        .as_object()
        .ok_or_else(|| anyhow::format_err!("block is not an object"))?
        .get("boc")
        .ok_or_else(|| anyhow::format_err!("boc key not found"))?
        .as_str()
        .map(|s| s.to_string().replace("\"", ""))
        .ok_or_else(|| anyhow::format_err!("Failed to parse boc field"))
}

fn pad_thread_id(thread_id: ThreadIdentifier) -> String {
    // new API expects a 68-char zero-padded thread id
    let raw = format!("{:x}", thread_id);
    format!("{:0>68}", raw)
}

pub async fn query_block_by_id(
    context: TvmClient,
    block_id: &str,
) -> anyhow::Result<Envelope<AckiNackiBlock>> {
    let q = format!(r#"{{ blockchain {{ block(hash: "{block_id}") {{ boc }} }} }}"#,);
    let data = gql_query(&context, &q).await?;
    let block_obj =
        data.get("blockchain").and_then(|b| b.get("block")).cloned().unwrap_or(Value::Null);
    if block_obj.is_null() {
        anyhow::bail!("block with id {block_id} not found");
    }
    let encoded = extract_boc(&block_obj)?;
    decode_envelope(&encoded)
}

pub async fn query_block_by_height(
    context: TvmClient,
    block_height: BlockHeight,
) -> anyhow::Result<Envelope<AckiNackiBlock>> {
    let tid = pad_thread_id(*block_height.thread_identifier());
    let h = block_height.height();
    let q = format!(
        r#"{{ blockchain {{ blockByHeight(thread_id: "{tid}", height: {h}) {{ boc }} }} }}"#,
    );
    let data = gql_query(&context, &q).await?;
    let block_obj =
        data.get("blockchain").and_then(|b| b.get("blockByHeight")).cloned().unwrap_or(Value::Null);
    if block_obj.is_null() {
        anyhow::bail!("block at height {h} (thread {tid}) not found");
    }
    let encoded = extract_boc(&block_obj)?;
    decode_envelope(&encoded)
}

pub async fn query_block_with_event(
    context: TvmClient,
    root_pn_address: &str,
) -> anyhow::Result<Envelope<AckiNackiBlock>> {
    // Find the latest ExtOut message from root_pn_address addressed to the
    // VoucherGenerated event destination, then fetch the block that carries it.
    let voucher_event_dst = ":0000000000000000000000000000000000000000000000000000000000000087";
    let q = format!(
        r#"{{ blockchain {{ account(address: "{root_pn_address}") {{ messages(msg_type: [ExtOut], last: 50) {{ edges {{ node {{ dst src_transaction {{ id }} }} }} }} }} }} }}"#,
    );
    let data = gql_query(&context, &q).await?;
    let edges = data
        .get("blockchain")
        .and_then(|b| b.get("account"))
        .and_then(|a| a.get("messages"))
        .and_then(|m| m.get("edges"))
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let node = edges
        .iter()
        .rev()
        .find_map(|edge| {
            let node = edge.get("node")?;
            if node.get("dst").and_then(|v| v.as_str()) == Some(voucher_event_dst) {
                Some(node.clone())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::format_err!("No VoucherGenerated event found"))?;
    let tx_id = node
        .get("src_transaction")
        .and_then(|t| t.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::format_err!("src_transaction.id missing"))?
        .to_string();
    // Fetch transaction to get block hash.
    let tq = format!(r#"{{ blockchain {{ transaction(hash: "{tx_id}") {{ block_id }} }} }}"#,);
    let tdata = gql_query(&context, &tq).await?;
    let block_id = tdata
        .get("blockchain")
        .and_then(|b| b.get("transaction"))
        .and_then(|t| t.get("block_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::format_err!("transaction.block_id missing"))?
        .to_string();
    query_block_by_id(context.clone(), &block_id).await
}

pub async fn query_latest_block_height(
    context: TvmClient,
    thread_id: ThreadIdentifier,
) -> anyhow::Result<BlockHeight> {
    // New API has no direct "latest block height in thread" query, but we can
    // ask for the latest blocks via master_seq_no pagination. Here we use the
    // top-level `blockchain.blocks(last: N)` and filter client-side by the
    // thread id.
    let tid = pad_thread_id(thread_id);
    // Query a reasonable window of recent blocks; filter by thread.
    let q = r#"{ blockchain { blocks(last: 200) { edges { node { thread_id height } } } } }"#;
    let data = gql_query(&context, q).await?;
    let edges = data
        .get("blockchain")
        .and_then(|b| b.get("blocks"))
        .and_then(|m| m.get("edges"))
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let height = edges
        .iter()
        .filter_map(|edge| {
            let node = edge.get("node")?;
            let node_tid = node.get("thread_id").and_then(|v| v.as_str())?;
            if node_tid == tid {
                node.get("height").and_then(|v| v.as_u64())
            } else {
                None
            }
        })
        .max()
        .ok_or_else(|| anyhow::format_err!("No blocks found for thread {tid}"))?;
    Ok(BlockHeight::builder().height(height).thread_identifier(thread_id).build())
}

pub async fn get_layer_0_data(
    context: TvmClient,
    thread_identifier: ThreadIdentifier,
    proof_block_height: u64,
) -> anyhow::Result<(Vec<[u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>)> {
    let window_start =
        proof_block_height.div(HISTORY_PROOF_WINDOW_SIZE as u64) * HISTORY_PROOF_WINDOW_SIZE as u64;

    let same_layer_root = if window_start != 0 {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder()
                .height(window_start)
                .thread_identifier(thread_identifier)
                .build(),
        )
        .await?;
        tracing::trace!("fetched L0 boundary block at height {}", window_start);
        block.data().common_section().history_proofs().get(&1).map(|v| *v.root_hash())
    } else {
        None
    };

    let w_sq = (HISTORY_PROOF_WINDOW_SIZE as u64) * (HISTORY_PROOF_WINDOW_SIZE as u64);
    let higher_boundary = window_start.div(w_sq) * w_sq;
    let higher_layer_root = if higher_boundary != 0 {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder()
                .height(higher_boundary)
                .thread_identifier(thread_identifier)
                .build(),
        )
        .await?;
        tracing::trace!("fetched L1 boundary block at height {}", higher_boundary);
        block.data().common_section().history_proofs().get(&2).map(|v| *v.root_hash())
    } else {
        None
    };

    let mut leaf_hashes = Vec::with_capacity(HISTORY_PROOF_WINDOW_SIZE);
    let mut height = window_start;
    for _ in 0..HISTORY_PROOF_WINDOW_SIZE {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder().height(height).thread_identifier(thread_identifier).build(),
        )
        .await?;
        let block_id = block.data().identifier();
        let env_hash = envelope_hash(&block);
        let ext_out_root = *block.data().common_section().tracked_ext_out_messages_root();
        let leaf_hash = compute_block_leaf_hash(block_id.as_array(), &env_hash.0, &ext_out_root);
        leaf_hashes.push(leaf_hash);
        height += 1;
    }

    ensure!(leaf_hashes.len() == HISTORY_PROOF_WINDOW_SIZE);
    Ok((leaf_hashes, same_layer_root, higher_layer_root))
}

pub async fn get_layer_n_data(
    context: TvmClient,
    thread_identifier: ThreadIdentifier,
    proof_block_height: u64,
    layer_number: LayerNumber,
) -> anyhow::Result<(Vec<[u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>)> {
    let Some(denominator) = (HISTORY_PROOF_WINDOW_SIZE as u64).checked_pow(layer_number as u32 + 1)
    else {
        anyhow::bail!("Failed to calculate denominator");
    };
    let step = denominator / HISTORY_PROOF_WINDOW_SIZE as u64;
    let mut cursor = proof_block_height.div(denominator) * denominator;

    let same_layer_root = if cursor != 0 {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder().height(cursor).thread_identifier(thread_identifier).build(),
        )
        .await?;
        tracing::trace!("fetched same-layer boundary block at height {}", cursor);
        block
            .data()
            .common_section()
            .history_proofs()
            .get(&(layer_number + 1))
            .map(|v| *v.root_hash())
    } else {
        None
    };

    let Some(higher_denom) = denominator.checked_mul(HISTORY_PROOF_WINDOW_SIZE as u64) else {
        anyhow::bail!("Failed to calculate higher-layer denominator");
    };
    let higher_boundary = cursor.div(higher_denom) * higher_denom;
    let higher_layer_root = if higher_boundary != 0 {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder()
                .height(higher_boundary)
                .thread_identifier(thread_identifier)
                .build(),
        )
        .await?;
        tracing::trace!("fetched higher-layer boundary block at height {}", higher_boundary);
        block
            .data()
            .common_section()
            .history_proofs()
            .get(&(layer_number + 2))
            .map(|v| *v.root_hash())
    } else {
        None
    };

    cursor += step;
    let mut result = Vec::new();
    for _ in 0..HISTORY_PROOF_WINDOW_SIZE {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder().height(cursor).thread_identifier(thread_identifier).build(),
        )
        .await?;
        cursor += step;
        result.push(
            *block
                .data()
                .common_section()
                .history_proofs()
                .get(&layer_number)
                .cloned()
                .ok_or(anyhow::format_err!("layer number {} not found", layer_number))?
                .root_hash(),
        );
    }
    Ok((result, same_layer_root, higher_layer_root))
}

/// Scan blocks in `[from_height..=to_height]` and return the first block
/// whose `tracked_ext_out_messages` is non-empty.
#[allow(unused)]
pub async fn find_block_with_ext_out_messages(
    context: TvmClient,
    thread_identifier: ThreadIdentifier,
    from_height: u64,
    to_height: u64,
) -> anyhow::Result<Option<Envelope<AckiNackiBlock>>> {
    for height in from_height..=to_height {
        let block = query_block_by_height(
            context.clone(),
            BlockHeight::builder().height(height).thread_identifier(thread_identifier).build(),
        )
        .await?;
        if !block.data().common_section().tracked_ext_out_messages().is_empty() {
            return Ok(Some(block));
        }
    }
    Ok(None)
}
