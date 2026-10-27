//! Anchor-layer tests against a simulated thread-0 chain whose history proofs
//! follow the node's rules (acki-nacki `node/src/types/history_proof.rs`,
//! `calculate_expected_history_proofs_from_cursor`): which block publishes
//! which root, the header roots of each tree, and the order of its leaves.
//! Events sit on window boundaries, inside later windows (non-zero header
//! roots), and right before an L2 boundary; the adjustable head decides which
//! anchor blocks exist yet and which roots the node has already evicted.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::GraphqlServer;
use dark_dex_halo2_private_witness_export_lib::{
    anchor::{AnchorLayerMode, AnchorOptions, WaitOptions},
    make_private_witness_and_public_data, make_private_witness_with_anchor,
    poseidon::{
        compute_block_leaf_hash, dense_merkle_root, PoseidonHasher, HISTORY_PROOF_WINDOW_SIZE,
    },
    proof::generate_ext_message_proof,
    types::AccountRouting,
    ExportParams,
};
use serde_json::{json, Value};

const W: u64 = HISTORY_PROOF_WINDOW_SIZE as u64;

// A VoucherGenerated message from dex-halo2-circuit/vouchers.txt.
const EVENT: &str = "te6ccgEBAgEAnQABn+AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAAAAAAAAoJ2mmmKhgAQCQY4DCGmJ5ISCGMbyhgDMqxWRzAGVpG4lV54dtIO+ahzbvIoYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF0h26AAAAAAC";

/// Blocks holding the event: an exact L1 boundary, the middle of an L1 window,
/// the last block before an L2 boundary, and an exact L2 boundary.
const EVENT_HEIGHTS: [u64; 4] = [W, W + 72, W * W - 1, W * W];

/// Covers E_1 = 2·W² + W of the event at W².
const MAX_HEIGHT: u64 = 2 * W * W + 2 * W;

/// E_2 of every event above: T_3 + W² with T_3 = W³.
const L2_EXPIRY: u64 = W * W * W + W * W;

fn hash(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

struct Chain {
    routing: AccountRouting,
    message_hash: [u8; 32],
    event_ext_root: [u8; 32],
    /// The node's `history_proofs` of every block that has any.
    history: BTreeMap<u64, BTreeMap<u8, [u8; 32]>>,
}

/// Simulated once per test binary.
fn chain() -> &'static Chain {
    static CHAIN: OnceLock<Chain> = OnceLock::new();
    CHAIN.get_or_init(Chain::simulate)
}

/// Pushes into a history cursor buffer, clearing it first when full.
fn push(buffer: &mut Vec<[u8; 32]>, value: [u8; 32]) {
    if buffer.len() == HISTORY_PROOF_WINDOW_SIZE {
        buffer.clear();
    }
    buffer.push(value);
}

impl Chain {
    fn simulate() -> Self {
        let routing = AccountRouting::new(hash(4), hash(16));
        let event = tvm_types::base64_decode(EVENT).unwrap();
        let message_hash = tvm_types::read_single_root_boc(event)
            .unwrap()
            .repr_hash()
            .inner();
        let messages = BTreeMap::from([(routing, vec![message_hash])]);
        let event_ext_root = generate_ext_message_proof(&messages, &routing, &message_hash)
            .unwrap()
            .0;
        let mut chain = Self {
            routing,
            message_hash,
            event_ext_root,
            history: BTreeMap::new(),
        };

        // The cursor's buffer for layer n >= 1 holds the layer-n roots. Only
        // the event windows get real L1 roots over their block leaves: the
        // exporter rebuilds no other window, so the rest are placeholders.
        let hasher = PoseidonHasher::new();
        let mut cursor: BTreeMap<u8, Vec<[u8; 32]>> = BTreeMap::new();
        for height in (W..=MAX_HEIGHT).step_by(HISTORY_PROOF_WINDOW_SIZE) {
            let latest = |layer: u8| {
                cursor
                    .get(&layer)
                    .and_then(|roots| roots.last().copied())
                    .unwrap_or_default()
            };
            let window = height - W..height;
            let l1_root = if EVENT_HEIGHTS.iter().any(|event| window.contains(event)) {
                let mut leaves = vec![latest(2), latest(1)];
                leaves.extend(window.map(|block| chain.block_leaf(block)));
                dense_merkle_root(&hasher, &leaves)
            } else {
                hash(5_000 + height)
            };
            let mut proofs = BTreeMap::from([(1u8, l1_root)]);
            let (mut scaled, mut layer) = (height, 1u8);
            loop {
                scaled /= W;
                if scaled == 0 || scaled % W != 0 {
                    break;
                }
                let mut data = cursor.get(&layer).cloned().unwrap_or_default();
                push(&mut data, proofs[&layer]);
                assert_eq!(data.len(), HISTORY_PROOF_WINDOW_SIZE);
                let mut leaves = vec![latest(layer + 2), latest(layer + 1)];
                leaves.extend(&data);
                proofs.insert(layer + 1, dense_merkle_root(&hasher, &leaves));
                layer += 1;
            }
            for (layer, root) in &proofs {
                push(cursor.entry(*layer).or_default(), *root);
            }
            chain.history.insert(height, proofs);
        }
        chain
    }

    fn ext_root(&self, height: u64) -> [u8; 32] {
        if EVENT_HEIGHTS.contains(&height) {
            self.event_ext_root
        } else {
            hash(3_000 + height)
        }
    }

    fn block_leaf(&self, height: u64) -> [u8; 32] {
        compute_block_leaf_hash(
            &hash(1_000 + height),
            &hash(2_000 + height),
            &self.ext_root(height),
        )
    }

    /// The layer-`layer` root that block `height` publishes.
    fn root(&self, height: u64, layer: u8) -> [u8; 32] {
        self.history[&height][&layer]
    }

    fn block_json(&self, height: u64, overrides: &BTreeMap<(u64, u8), [u8; 32]>) -> Value {
        let tracked = if EVENT_HEIGHTS.contains(&height) {
            json!([{
                "routing": self.routing.to_string(),
                "message_hashes": [hex::encode(self.message_hash)],
            }])
        } else {
            json!([])
        };
        let history: Vec<Value> = self
            .history
            .get(&height)
            .into_iter()
            .flatten()
            .map(|(layer, root)| {
                let root = overrides.get(&(height, *layer)).unwrap_or(root);
                json!({ "layer": layer, "root_hash": hex::encode(root) })
            })
            .collect();
        json!({
            "block_id": hex::encode(hash(1_000 + height)),
            "thread_id": "00".repeat(34),
            "height": height,
            "envelope_hash": hex::encode(hash(2_000 + height)),
            "tracked_ext_out_messages_root": hex::encode(self.ext_root(height)),
            "tracked_ext_out_message_hashes": tracked,
            "history_proofs": history,
        })
    }
}

/// A node serving [`chain`] up to an adjustable head, optionally reporting
/// different history roots for some `(height, layer)`.
struct Node {
    server: GraphqlServer,
    head: Arc<AtomicU64>,
}

impl Node {
    async fn start(head: u64, overrides: BTreeMap<(u64, u8), [u8; 32]>) -> Self {
        let head = Arc::new(AtomicU64::new(head));
        let current = head.clone();
        let handler: common::Handler = Arc::new(move |query: &str, variables: &Value| {
            let head = current.load(Ordering::SeqCst);
            if query.contains("LatestBlock") {
                json!({ "blockchain": { "latest_blocks": { "edges": [{ "node": {
                    "thread_id": "00".repeat(34), "height": head
                }}]}}})
            } else if query.contains("BlockByHeight") {
                let height = variables["height"].as_u64().unwrap();
                let block = (height <= head).then(|| chain().block_json(height, &overrides));
                json!({ "blockchain": { "block_by_height": block } })
            } else {
                Value::Null
            }
        });
        Self {
            server: GraphqlServer::start(handler).await,
            head,
        }
    }

    fn set_head(&self, head: u64) {
        self.head.store(head, Ordering::SeqCst);
    }

    fn params(&self, event_height: u64, output: &Path) -> ExportParams {
        ExportParams {
            network: self.server.url.clone(),
            block_height: Some(event_height),
            block_id: None,
            event_boc: EVENT.to_owned(),
            sk_u: "00".repeat(32),
            ephemeral_pubkey: "01".repeat(32),
            output: output.to_str().unwrap().to_owned(),
            max_layers: None,
        }
    }

    async fn export(
        &self,
        event_height: u64,
        anchor: AnchorOptions,
        output: &Path,
    ) -> anyhow::Result<Value> {
        let params = self.params(event_height, output);
        let fixture = make_private_witness_with_anchor(&params, &anchor).await?;
        Ok(serde_json::from_str(&fixture)?)
    }
}

fn layer(layer: u32) -> AnchorOptions {
    AnchorOptions {
        layer: AnchorLayerMode::Explicit(layer),
        ..AnchorOptions::default()
    }
}

#[tokio::test]
async fn anchors_to_l1_and_l2_for_events_anywhere_in_a_window() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    // (event, T_1, E_1, T_2, position of the L1 root among the L2 tree's leaves)
    for (event, t1, e1, t2, rung) in [
        (W, 2 * W, W * W + W, W * W, 3),
        (W + 72, 2 * W, W * W + W, W * W, 3),
        (W * W - 1, W * W, W * W + W, W * W, W + 1),
        (W * W, W * W + W, 2 * W * W + W, 2 * W * W, 2),
    ] {
        // L1, in the last block before the node evicts its root.
        let node = Node::start(e1 - 1, BTreeMap::new()).await;
        let fixture = node.export(event, layer(1), &output).await.unwrap();
        assert_eq!(fixture["final_layer_number"], 1, "event {event}");
        assert_eq!(fixture["num_active_chain_steps"], 0);
        assert_eq!(fixture["anchor_block_height"], t1);
        assert_eq!(fixture["anchor_expires_at_height"], e1);
        assert_eq!(
            fixture["final_layer_historical_hash_root_hex"],
            hex::encode(chain().root(t1, 1))
        );

        // L2, as soon as its root is published.
        let node = Node::start(t2, BTreeMap::new()).await;
        let fixture = node.export(event, layer(2), &output).await.unwrap();
        assert_eq!(fixture["final_layer_number"], 2, "event {event}");
        assert_eq!(fixture["num_active_chain_steps"], 1);
        assert_eq!(fixture["anchor_block_height"], t2);
        assert_eq!(fixture["anchor_expires_at_height"], L2_EXPIRY);
        assert_eq!(fixture["dense_chain"][0]["position"], rung);
        assert_eq!(
            fixture["dense_chain"][0]["leaf_hex"],
            hex::encode(chain().root(t1, 1))
        );
        assert_eq!(
            fixture["final_layer_historical_hash_root_hex"],
            hex::encode(chain().root(t2, 2))
        );
    }
}

#[tokio::test]
async fn an_event_on_a_boundary_is_not_anchored_by_its_own_block() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    // Block W publishes the root of window 0, not of the event's window.
    let node = Node::start(2 * W - 1, BTreeMap::new()).await;
    let error = node
        .export(W, layer(1), &output)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&format!("block {}", 2 * W)) && error.contains("has not been produced yet"),
        "unexpected error: {error}"
    );
    node.set_head(2 * W);
    let fixture = node.export(W, layer(1), &output).await.unwrap();
    assert_eq!(fixture["anchor_block_height"], 2 * W);

    // Likewise block W² is not the L2 anchor of the event at W².
    let node = Node::start(2 * W * W - 1, BTreeMap::new()).await;
    let error = node
        .export(W * W, layer(2), &output)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&format!("block {}", 2 * W * W)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn an_evicted_l1_root_is_refused_unless_allowed() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    // The event right before an L2 boundary: its L1 root, published in block
    // W², is evicted at W² + W.
    let node = Node::start(W * W + W, BTreeMap::new()).await;
    let error = node
        .export(W * W - 1, layer(1), &output)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("no longer accepts") && error.contains("--anchor-layer 2"),
        "unexpected error: {error}"
    );
    assert!(
        !output.exists(),
        "a refused export must not produce a fixture"
    );

    let allowed = AnchorOptions {
        allow_expired: true,
        ..layer(1)
    };
    let fixture = node.export(W * W - 1, allowed, &output).await.unwrap();
    assert_eq!(fixture["anchor_expires_at_height"], W * W + W);

    let fixture = node.export(W * W - 1, layer(2), &output).await.unwrap();
    assert_eq!(fixture["final_layer_number"], 2);
}

#[tokio::test]
async fn auto_takes_the_highest_layer_produced_so_far() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    let auto = AnchorOptions {
        layer: AnchorLayerMode::Auto,
        ..AnchorOptions::default()
    };
    let node = Node::start(2 * W, BTreeMap::new()).await;
    let fixture = node.export(W + 72, auto, &output).await.unwrap();
    assert_eq!(fixture["final_layer_number"], 1);
    node.set_head(W * W);
    let fixture = node.export(W + 72, auto, &output).await.unwrap();
    assert_eq!(fixture["final_layer_number"], 2);
}

#[tokio::test]
async fn waits_for_the_anchor_block_when_asked() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    let node = Node::start(2 * W - 6, BTreeMap::new()).await;
    let head = node.head.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        head.store(2 * W, Ordering::SeqCst);
    });
    let waiting = AnchorOptions {
        wait: Some(WaitOptions {
            timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(50),
        }),
        ..layer(1)
    };
    let fixture = node.export(W + 72, waiting, &output).await.unwrap();
    assert_eq!(fixture["anchor_block_height"], 2 * W);
}

#[tokio::test]
async fn a_rebuilt_root_that_differs_from_the_node_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    // The node reports another L1 root in the event's anchor block 2W.
    let node = Node::start(W * W, BTreeMap::from([((2 * W, 1), hash(9_999))])).await;
    let error = node.export(W + 72, layer(1), &output).await.unwrap_err();
    assert!(
        error.to_string().contains("differs from the root"),
        "unexpected error: {error:#}"
    );
    // At L2 that root is the L2 tree's leaf at the rung position.
    let error = node.export(W + 72, layer(2), &output).await.unwrap_err();
    assert!(
        format!("{error:#}").contains(&format!("published in block {}", 2 * W)),
        "unexpected error: {error:#}"
    );
    assert!(
        !output.exists(),
        "a refused export must not produce a fixture"
    );
}

#[tokio::test]
async fn legacy_max_layers_exports_the_same_fixtures() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    let node = Node::start(2 * W * W, BTreeMap::new()).await;
    for (max_layers, mode) in [
        (Some(0), AnchorLayerMode::Explicit(1)),
        (Some(1), AnchorLayerMode::Explicit(2)),
        (None, AnchorLayerMode::Auto),
    ] {
        let legacy = make_private_witness_and_public_data(&ExportParams {
            max_layers,
            ..node.params(W * W, &output)
        })
        .await
        .unwrap();
        let anchor = AnchorOptions {
            layer: mode,
            ..AnchorOptions::default()
        };
        let explicit = node.export(W * W, anchor, &output).await.unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&legacy).unwrap(),
            explicit,
            "max_layers = {max_layers:?}"
        );
    }
}
