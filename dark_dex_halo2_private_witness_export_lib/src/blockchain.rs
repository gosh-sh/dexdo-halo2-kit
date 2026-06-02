use std::collections::BTreeMap;
use std::ops::Div;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::ensure;
use anyhow::Context;
use serde_json::json;
use serde_json::Value;

use crate::poseidon::compute_block_leaf_hash;
use crate::poseidon::LayerNumber;
use crate::poseidon::HISTORY_PROOF_WINDOW_SIZE;
use crate::types::AccountRouting;
use crate::types::ThreadIdentifier;

const PROOF_BLOCK_FRAGMENT: &str = r#"
fragment ProofBlockFields on Block {
  id
  block_id
  thread_id
  height
  envelope_hash
  tracked_ext_out_messages_root
  tracked_ext_out_message_hashes { routing message_hashes }
  history_proofs { layer root_hash }
}
"#;

#[derive(Clone, Debug)]
pub struct GqlProofBlock {
    pub block_id: [u8; 32],
    pub thread_id: ThreadIdentifier,
    pub height: u64,
    pub envelope_hash: [u8; 32],
    pub tracked_ext_out_messages_root: [u8; 32],
    pub tracked_ext_out_messages: BTreeMap<AccountRouting, Vec<[u8; 32]>>,
    pub history_proofs: BTreeMap<LayerNumber, [u8; 32]>,
}

impl GqlProofBlock {
    pub fn block_leaf_hash(&self) -> [u8; 32] {
        compute_block_leaf_hash(
            &self.block_id,
            &self.envelope_hash,
            &self.tracked_ext_out_messages_root,
        )
    }
}

pub struct GqlClient {
    http: reqwest::Client,
    url: String,
}
pub type TvmClient = Arc<GqlClient>;

pub fn create_client(network: &str) -> anyhow::Result<TvmClient> {
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

async fn gql_query(client: &GqlClient, query: &str, variables: Value) -> anyhow::Result<Value> {
    let resp = client
        .http
        .post(&client.url)
        .json(&json!({ "query": query, "variables": variables }))
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
    Ok(body)
}

pub async fn query_block_by_id(
    context: TvmClient,
    block_id: &str,
) -> anyhow::Result<GqlProofBlock> {
    tracing::trace!("query_block_by_id with id {}", block_id);
    let query = format!(
        r#"query BlockById($hash: String!) {{ blockchain {{ block(hash: $hash) {{ ...ProofBlockFields }} }} }}{PROOF_BLOCK_FRAGMENT}"#
    );
    let data = gql_query(&context, &query, json!({ "hash": block_id })).await?;
    let value = ensure_graphql_value(&data, "/data/blockchain/block", "block")?;
    parse_proof_block(value)
}

pub async fn query_block_by_height(
    context: TvmClient,
    thread_id: ThreadIdentifier,
    height: u64,
) -> anyhow::Result<GqlProofBlock> {
    let thread_id_hex = format!("{thread_id:x}");
    tracing::trace!("query_block_by_height thread_id={thread_id_hex} height={height}");
    let query = format!(
        r#"query BlockByHeight($threadId: String!, $height: Int!) {{ blockchain {{ block_by_height: blockByHeight(thread_id: $threadId, height: $height) {{ ...ProofBlockFields }} }} }}{PROOF_BLOCK_FRAGMENT}"#
    );
    let data =
        gql_query(&context, &query, json!({ "threadId": thread_id_hex, "height": height })).await?;
    let value = ensure_graphql_value(&data, "/data/blockchain/block_by_height", "block_by_height")
        .map_err(|_| {
            anyhow::format_err!("block not found for thread_id {thread_id_hex} at height {height}")
        })?;
    parse_proof_block(value)
}

pub async fn query_latest_block_height(
    context: TvmClient,
    thread_id: ThreadIdentifier,
) -> anyhow::Result<u64> {
    let expected = format!("{thread_id:x}");
    let query = r#"query LatestBlock { blockchain { latest_blocks: blocks(last: 1) { edges { node { thread_id height } } } } }"#;
    let data = gql_query(&context, query, json!({})).await?;
    let actual = parse_string_field(
        &data,
        "/data/blockchain/latest_blocks/edges/0/node/thread_id",
        "thread_id",
    )?;
    ensure!(actual == expected, "latest block thread_id mismatch: expected {expected}, got {actual}");
    parse_u64_field(&data, "/data/blockchain/latest_blocks/edges/0/node/height", "height")
}

async fn fetch_marker(
    context: &TvmClient,
    thread_id: ThreadIdentifier,
    boundary_height: u64,
    layer: LayerNumber,
) -> anyhow::Result<Option<[u8; 32]>> {
    if boundary_height == 0 {
        return Ok(None);
    }
    let block = query_block_by_height(context.clone(), thread_id, boundary_height).await?;
    tracing::trace!("fetch_marker layer={} boundary={}", layer, boundary_height);
    Ok(block.history_proofs.get(&layer).copied())
}

pub async fn get_layer_0_data(
    context: TvmClient,
    thread_id: ThreadIdentifier,
    proof_block_height: u64,
) -> anyhow::Result<(Vec<[u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>)> {
    let w = HISTORY_PROOF_WINDOW_SIZE as u64;
    let window_start = proof_block_height.div(w) * w;
    let higher_boundary = proof_block_height.div(w * w) * (w * w);

    let same_layer_root = fetch_marker(&context, thread_id, window_start, 1).await?;
    let higher_layer_root = fetch_marker(&context, thread_id, higher_boundary, 2).await?;

    let mut leaf_hashes = Vec::with_capacity(HISTORY_PROOF_WINDOW_SIZE);
    for height in window_start..window_start + w {
        let block = query_block_by_height(context.clone(), thread_id, height).await?;
        leaf_hashes.push(block.block_leaf_hash());
    }
    ensure!(leaf_hashes.len() == HISTORY_PROOF_WINDOW_SIZE);
    Ok((leaf_hashes, same_layer_root, higher_layer_root))
}

pub async fn get_layer_n_data(
    context: TvmClient,
    thread_id: ThreadIdentifier,
    proof_block_height: u64,
    layer_number: LayerNumber,
) -> anyhow::Result<(Vec<[u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>)> {
    let w = HISTORY_PROOF_WINDOW_SIZE as u64;
    let denominator = w
        .checked_pow(layer_number as u32 + 1)
        .ok_or_else(|| anyhow::format_err!("Failed to calculate denominator"))?;
    let step = denominator / w;
    let mut cursor = proof_block_height.div(denominator) * denominator;

    let same_layer_root = fetch_marker(&context, thread_id, cursor, layer_number + 1).await?;
    let higher_boundary = match w.checked_pow(layer_number as u32 + 2) {
        Some(d) => proof_block_height / d * d,
        None => 0,
    };
    let higher_layer_root =
        fetch_marker(&context, thread_id, higher_boundary, layer_number + 2).await?;

    cursor += step;
    let mut result = Vec::with_capacity(HISTORY_PROOF_WINDOW_SIZE);
    for _ in 0..HISTORY_PROOF_WINDOW_SIZE {
        let height = cursor;
        cursor += step;
        let block = query_block_by_height(context.clone(), thread_id, height).await?;
        result.push(*block.history_proofs.get(&layer_number).ok_or_else(|| {
            anyhow::format_err!(
                "history proof layer {} not found in block at height {}",
                layer_number,
                height
            )
        })?);
    }
    Ok((result, same_layer_root, higher_layer_root))
}

// ─── JSON parsing ──────────────────────────────────────────────────────────

fn parse_proof_block(value: &Value) -> anyhow::Result<GqlProofBlock> {
    Ok(GqlProofBlock {
        block_id: decode_hash_hex(required_string(value, "block_id")?).context("block_id")?,
        thread_id: ThreadIdentifier::try_from(required_string(value, "thread_id")?.to_string())
            .context("thread_id")?,
        height: parse_u64_member(value, "height")?,
        envelope_hash: decode_hash_hex(required_string(value, "envelope_hash")?)
            .context("envelope_hash")?,
        tracked_ext_out_messages_root: decode_hash_hex(required_string(
            value,
            "tracked_ext_out_messages_root",
        )?)
        .context("tracked_ext_out_messages_root")?,
        tracked_ext_out_messages: parse_tracked_ext_out_messages(value)?,
        history_proofs: parse_history_proofs(value)?,
    })
}

fn parse_tracked_ext_out_messages(
    value: &Value,
) -> anyhow::Result<BTreeMap<AccountRouting, Vec<[u8; 32]>>> {
    let mut out = BTreeMap::new();
    let Some(raw) = value.get("tracked_ext_out_message_hashes") else {
        return Ok(out);
    };
    if raw.is_null() {
        return Ok(out);
    }
    let entries = raw
        .as_array()
        .ok_or_else(|| anyhow::format_err!("tracked_ext_out_message_hashes is not an array"))?;
    for entry in entries {
        let routing = AccountRouting::from_str(required_string(entry, "routing")?)
            .context("tracked ext-out routing")?;
        let hashes = entry
            .get("message_hashes")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::format_err!("message_hashes is not an array"))?;
        let mut msgs = Vec::with_capacity(hashes.len());
        for (i, h) in hashes.iter().enumerate() {
            let s = h.as_str().ok_or_else(|| anyhow::format_err!("hash {i} is not a string"))?;
            msgs.push(decode_hash_hex(s).with_context(|| format!("tracked message hash {i}"))?);
        }
        ensure!(out.insert(routing, msgs).is_none(), "duplicate routing");
    }
    Ok(out)
}

fn parse_history_proofs(value: &Value) -> anyhow::Result<BTreeMap<LayerNumber, [u8; 32]>> {
    let mut out = BTreeMap::new();
    let Some(raw) = value.get("history_proofs") else {
        return Ok(out);
    };
    let entries =
        raw.as_array().ok_or_else(|| anyhow::format_err!("history_proofs is not an array"))?;
    for entry in entries {
        let layer = parse_u64_member(entry, "layer")?;
        ensure!(layer <= u8::MAX as u64, "history proof layer out of range: {layer}");
        let layer = layer as u8;
        let root_hash = decode_hash_hex(required_string(entry, "root_hash")?)
            .with_context(|| format!("history proof layer {layer}"))?;
        ensure!(out.insert(layer, root_hash).is_none(), "duplicate history proof layer {layer}");
    }
    Ok(out)
}

fn decode_hash_hex(hex_hash: &str) -> anyhow::Result<[u8; 32]> {
    ensure!(hex_hash.len() == 64, "expected 32-byte hex hash, got {}", hex_hash.len());
    let mut hash = [0u8; 32];
    hex::decode_to_slice(hex_hash, &mut hash).context("invalid hex hash")?;
    Ok(hash)
}

fn required_string<'a>(value: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::format_err!("missing or invalid block.{field}"))
}

fn parse_string_field(data: &Value, pointer: &str, field: &str) -> anyhow::Result<String> {
    data.pointer(pointer)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::format_err!("Failed to parse {field}"))
}

fn ensure_graphql_value<'a>(
    data: &'a Value,
    pointer: &str,
    field: &str,
) -> anyhow::Result<&'a Value> {
    let value = data.pointer(pointer).ok_or_else(|| anyhow::format_err!("{field} key not found"))?;
    ensure!(!value.is_null(), "{field} not found");
    Ok(value)
}

fn parse_u64_member(value: &Value, field: &str) -> anyhow::Result<u64> {
    parse_u64_value(
        value.get(field).ok_or_else(|| anyhow::format_err!("missing {field}"))?,
        field,
    )
}

fn parse_u64_field(data: &Value, pointer: &str, field: &str) -> anyhow::Result<u64> {
    parse_u64_value(
        data.pointer(pointer).ok_or_else(|| anyhow::format_err!("{field} key not found"))?,
        field,
    )
}

fn parse_u64_value(value: &Value, field: &str) -> anyhow::Result<u64> {
    if let Some(v) = value.as_u64() {
        return Ok(v);
    }
    if let Some(v) = value.as_i64() {
        return u64::try_from(v).with_context(|| format!("{field} is negative"));
    }
    if let Some(v) = value.as_f64() {
        ensure!(v.is_finite() && v >= 0.0 && v.fract() == 0.0, "{field} is not an integer");
        return Ok(v as u64);
    }
    anyhow::bail!("{field} is not a number")
}
