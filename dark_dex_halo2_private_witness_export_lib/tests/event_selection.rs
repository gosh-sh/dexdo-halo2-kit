use std::collections::BTreeMap;
use std::time::Duration;

use dark_dex_halo2_private_witness_export_lib::{
    anchor::{AnchorLayerMode, AnchorOptions, WaitOptions},
    make_private_witness_and_public_data, make_private_witness_with_anchor,
    poseidon::{compute_block_leaf_hash, HISTORY_PROOF_WINDOW_SIZE},
    proof::{generate_ext_message_proof, generate_layer0_proof, generate_layer_n_proof},
    types::AccountRouting,
    ExportParams,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

// Public VoucherGenerated messages from dex-halo2-circuit/vouchers.txt.
const EVENT_A: &str = "te6ccgEBAgEAnQABn+AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAAAAAAAAoJ2mmmKhgAQCQY4DCGmJ5ISCGMbyhgDMqxWRzAGVpG4lV54dtIO+ahzbvIoYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF0h26AAAAAAC";
const EVENT_B: &str = "te6ccgEBAgEAnQABn+AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAAAAAAAAoNmmmmKpgAQCQY4DCGkEfJFgTOGMI0RlWv18bvInSbOo4BhqH4nPGJ0P42fQOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF0h26AAAAAAC";
const EVENT_ABSENT: &str = "te6ccgEBAgEAnQABn+AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAAAAAAAAoRWmmmKxgAQCQY4DCGn1erZEmTOWpHNSp+1VaRCWpGBA5F6x324RZEtDb7BwKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF0h26AAAAAAC";
const EVENT_HEIGHT: u64 = 7;

type Messages = BTreeMap<AccountRouting, Vec<[u8; 32]>>;

fn hash(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn event_hash(boc: &str) -> [u8; 32] {
    let cell = tvm_types::read_single_root_boc(tvm_types::base64_decode(boc).unwrap()).unwrap();
    cell.repr_hash().inner()
}

fn messages(separate_accounts: bool) -> Messages {
    let first = AccountRouting::new(hash(4), hash(16));
    if separate_accounts {
        BTreeMap::from([
            (first, vec![event_hash(EVENT_A)]),
            (
                AccountRouting::new(hash(5), hash(17)),
                vec![event_hash(EVENT_B)],
            ),
        ])
    } else {
        BTreeMap::from([(first, vec![event_hash(EVENT_A), event_hash(EVENT_B)])])
    }
}

struct Node {
    network: String,
    roots: [[u8; 32]; 2],
    task: JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Node {
    async fn start(messages: &Messages) -> Self {
        let (routing, hashes) = messages.first_key_value().unwrap();
        let ext_root = generate_ext_message_proof(messages, routing, &hashes[0])
            .unwrap()
            .0;
        let tracked: Vec<_> = messages.iter().map(|(routing, hashes)| {
            json!({"routing": routing.to_string(), "message_hashes": hashes.iter().map(hex::encode).collect::<Vec<_>>()})
        }).collect();
        let mut blocks = BTreeMap::new();
        let mut leaves = Vec::new();
        for height in 0..HISTORY_PROOF_WINDOW_SIZE as u64 {
            let root = if height == EVENT_HEIGHT {
                ext_root
            } else {
                hash(3000 + height)
            };
            leaves.push(compute_block_leaf_hash(
                &hash(1000 + height),
                &hash(2000 + height),
                &root,
            ));
            blocks.insert(height, json!({
                "block_id": hex::encode(hash(1000 + height)), "thread_id": "00".repeat(34),
                "height": height, "envelope_hash": hex::encode(hash(2000 + height)),
                "tracked_ext_out_messages_root": hex::encode(root),
                "tracked_ext_out_message_hashes": if height == EVENT_HEIGHT { json!(tracked) } else { json!([]) },
                "history_proofs": []
            }));
        }
        let root0 = generate_layer0_proof(&leaves, EVENT_HEIGHT as usize, None, None)
            .unwrap()
            .0;
        let mut roots = Vec::new();
        for index in 1..=HISTORY_PROOF_WINDOW_SIZE {
            let height = (index * HISTORY_PROOF_WINDOW_SIZE) as u64;
            let root = if index == 1 {
                root0
            } else {
                hash(4000 + index as u64)
            };
            roots.push(root);
            blocks.insert(height, json!({
                "block_id": hex::encode(hash(1000 + height)), "thread_id": "00".repeat(34),
                "height": height, "envelope_hash": hex::encode(hash(2000 + height)),
                "tracked_ext_out_messages_root": hex::encode(hash(3000 + height)),
                "tracked_ext_out_message_hashes": [], "history_proofs": [{"layer": 1, "root_hash": hex::encode(root)}]
            }));
        }
        let root1 = generate_layer_n_proof(&roots, root0, None, None).unwrap().0;
        // A block lists the root of every layer whose window closes at it, so
        // the L2 boundary carries the L2 root too.
        blocks
            .get_mut(&((HISTORY_PROOF_WINDOW_SIZE * HISTORY_PROOF_WINDOW_SIZE) as u64))
            .unwrap()["history_proofs"]
            .as_array_mut()
            .unwrap()
            .push(json!({"layer": 2, "root_hash": hex::encode(root1)}));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let network = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 8192];
                let headers_end = loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let headers = std::str::from_utf8(&request[..headers_end]).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                while request.len() < headers_end + length {
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                }
                let request: Value =
                    serde_json::from_slice(&request[headers_end..headers_end + length]).unwrap();
                let query = request["query"].as_str().unwrap();
                let response = if query.contains("LatestBlock") {
                    json!({"data": {"blockchain": {"latest_blocks": {"edges": [{"node": {
                        "thread_id": "00".repeat(34), "height": HISTORY_PROOF_WINDOW_SIZE * HISTORY_PROOF_WINDOW_SIZE
                    }}]}}}})
                } else if query.contains("BlockByHeight") {
                    let height = request["variables"]["height"].as_u64().unwrap();
                    json!({"data": {"blockchain": {"block_by_height": blocks.get(&height)}}})
                } else {
                    assert_eq!(
                        request["variables"]["hash"],
                        blocks[&EVENT_HEIGHT]["block_id"]
                    );
                    json!({"data": {"blockchain": {"block": blocks[&EVENT_HEIGHT]}}})
                };
                let body = serde_json::to_vec(&response).unwrap();
                let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        });
        Self {
            network,
            roots: [root0, root1],
            task,
        }
    }

    fn params(&self, event: &str, layer: u32, output: &std::path::Path) -> ExportParams {
        ExportParams {
            network: self.network.clone(),
            block_height: Some(EVENT_HEIGHT),
            block_id: None,
            event_boc: event.to_owned(),
            sk_u: "00".repeat(32),
            ephemeral_pubkey: "01".repeat(32),
            output: output.to_str().unwrap().to_owned(),
            max_layers: Some(layer),
        }
    }
}

async fn assert_selected_event(layer: u32, separate_accounts: bool) {
    let messages = messages(separate_accounts);
    let node = Node::start(&messages).await;
    let directory = tempfile::tempdir().unwrap();
    for (expected_position, event) in [EVENT_A, EVENT_B].into_iter().enumerate() {
        let message_hash = event_hash(event);
        let (routing, _) = messages
            .iter()
            .find(|(_, hashes)| hashes.contains(&message_hash))
            .unwrap();
        let (_, _, position, siblings) =
            generate_ext_message_proof(&messages, routing, &message_hash).unwrap();
        assert_eq!(position, expected_position);
        let mut params = node.params(event, layer, &directory.path().join("fixture.json"));
        // Exercise both public block lookup forms.
        if expected_position == 1 {
            params.block_height = None;
            params.block_id = Some(hex::encode(hash(1000 + EVENT_HEIGHT)));
        }
        let fixture = make_private_witness_and_public_data(&params).await.unwrap();
        let fixture: Value = serde_json::from_str(&fixture).unwrap();
        let (dapp, account) = routing.unpack_for_hash();
        assert_eq!(fixture["event_boc_base64"], event);
        assert_eq!(fixture["events_proof_position"], expected_position);
        assert_eq!(
            fixture["events_proof_siblings_hex"],
            json!(siblings.iter().map(hex::encode).collect::<Vec<_>>())
        );
        assert_eq!(fixture["account_dapp_id_hex"], hex::encode(dapp));
        assert_eq!(fixture["account_id_hex"], hex::encode(account));
        assert_eq!(fixture["num_active_chain_steps"], layer);
        assert_eq!(
            fixture["final_layer_historical_hash_root_hex"],
            hex::encode(node.roots[layer as usize])
        );
    }
}

#[tokio::test]
async fn selects_each_event_in_same_block_at_base_layer() {
    assert_selected_event(0, false).await;
}

#[tokio::test]
async fn selects_each_event_in_same_block_with_upper_history_step() {
    assert_selected_event(1, false).await;
}

#[tokio::test]
async fn selects_event_under_later_account_routing() {
    for layer in 0..=1 {
        assert_selected_event(layer, true).await;
    }
}

async fn assert_rejected(event: &str, expected_error: &str) {
    let node = Node::start(&messages(false)).await;
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    let error = make_private_witness_and_public_data(&node.params(event, 0, &output))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains(expected_error),
        "unexpected error: {error:#}"
    );
    assert!(
        !output.exists(),
        "a rejected event must not produce a fixture"
    );
}

#[tokio::test]
async fn rejects_event_absent_from_tracked_messages() {
    assert_rejected(EVENT_ABSENT, "not found").await;
}

#[tokio::test]
async fn rejects_invalid_event_base64() {
    assert_rejected("!invalid-base64!", "event_boc").await;
}

#[tokio::test]
async fn rejects_invalid_event_boc() {
    assert_rejected("bm90IGEgYm9j", "event_boc").await;
}

// --- anchor layer selection (the mock head is 128², so L1 and L2 exist) ---

const W: u64 = HISTORY_PROOF_WINDOW_SIZE as u64;

fn anchor(layer: AnchorLayerMode) -> AnchorOptions {
    AnchorOptions {
        layer,
        ..AnchorOptions::default()
    }
}

async fn export_with_anchor(
    node: &Node,
    output: &std::path::Path,
    anchor: AnchorOptions,
) -> anyhow::Result<Value> {
    let params = ExportParams {
        max_layers: None,
        ..node.params(EVENT_A, 0, output)
    };
    let fixture = make_private_witness_with_anchor(&params, &anchor).await?;
    Ok(serde_json::from_str(&fixture)?)
}

#[tokio::test]
async fn explicit_anchor_layers_report_their_blocks() {
    let node = Node::start(&messages(false)).await;
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    for (layer, anchor_height, expiry) in [(1u32, W, W * W + W), (2, W * W, W * W * W + W * W)] {
        let fixture = export_with_anchor(&node, &output, anchor(AnchorLayerMode::Explicit(layer)))
            .await
            .unwrap();
        assert_eq!(fixture["final_layer_number"], layer);
        assert_eq!(fixture["num_active_chain_steps"], layer - 1);
        assert_eq!(
            fixture["final_layer_historical_hash_root_hex"],
            hex::encode(node.roots[layer as usize - 1])
        );
        assert_eq!(fixture["event_block_height"], EVENT_HEIGHT);
        assert_eq!(fixture["anchor_block_height"], anchor_height);
        assert_eq!(fixture["anchor_expires_at_height"], expiry);
    }
}

#[tokio::test]
async fn auto_anchor_takes_the_highest_produced_layer_like_legacy_none() {
    let node = Node::start(&messages(false)).await;
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    let fixture = export_with_anchor(&node, &output, anchor(AnchorLayerMode::Auto))
        .await
        .unwrap();
    assert_eq!(fixture["final_layer_number"], 2);
    let legacy = make_private_witness_and_public_data(&ExportParams {
        max_layers: None,
        ..node.params(EVENT_A, 0, &output)
    })
    .await
    .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&legacy).unwrap(), fixture);
}

#[tokio::test]
async fn missing_anchor_block_fails_or_times_out() {
    let node = Node::start(&messages(false)).await;
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    // T_3 = 128³ is far beyond the mock head.
    let error = export_with_anchor(&node, &output, anchor(AnchorLayerMode::Explicit(3)))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("has not been produced yet"),
        "unexpected error: {error:#}"
    );

    let timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let error = export_with_anchor(
        &node,
        &output,
        AnchorOptions {
            wait: Some(WaitOptions {
                timeout,
                poll_interval: Duration::from_millis(100),
            }),
            ..anchor(AnchorLayerMode::Explicit(3))
        },
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("gave up"),
        "unexpected error: {error:#}"
    );
    assert!(started.elapsed() >= timeout);
    assert!(
        !output.exists(),
        "a failed export must not produce a fixture"
    );
}

#[tokio::test]
async fn max_layers_must_agree_with_the_anchor_layer() {
    let node = Node::start(&messages(false)).await;
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("fixture.json");
    // max_layers = 0 selects layer 1.
    let params = node.params(EVENT_A, 0, &output);
    let error = make_private_witness_with_anchor(&params, &anchor(AnchorLayerMode::Explicit(2)))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("conflicts"),
        "unexpected error: {error:#}"
    );
    assert!(!output.exists());
    make_private_witness_with_anchor(&params, &anchor(AnchorLayerMode::Explicit(1)))
        .await
        .unwrap();
}
