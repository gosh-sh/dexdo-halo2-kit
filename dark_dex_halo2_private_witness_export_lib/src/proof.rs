use std::collections::HashMap;

use node_block_client::history_proof::compute_ext_message_leaf_hash;
use node_block_client::history_proof::dense_merkle_proof;
use node_block_client::history_proof::dense_merkle_root;
use node_block_client::history_proof::dense_merkle_verify;
use node_block_client::history_proof::PoseidonHasher;
use node_block_client::AccountRouting;
use serde::Deserialize;
use serde::Serialize;
use typed_builder::TypedBuilder;

#[derive(Serialize, Deserialize, TypedBuilder)]
pub struct ProofData {
    leaf: [u8; 32],
    root: [u8; 32],
    pos: usize,
    proof: Vec<[u8; 32]>,
}

impl ProofData {
    pub fn unpack(&self) -> ([u8; 32], [u8; 32], usize, Vec<[u8; 32]>) {
        (self.leaf, self.root, self.pos, self.proof.clone())
    }
}

fn build_leaves(
    data_leaves: &[[u8; 32]],
    same_layer_root: Option<[u8; 32]>,
    higher_layer_root: Option<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut leaves = Vec::with_capacity(2 + data_leaves.len());
    leaves.push(higher_layer_root.unwrap_or([0u8; 32]));
    leaves.push(same_layer_root.unwrap_or([0u8; 32]));
    leaves.extend_from_slice(data_leaves);
    leaves
}

pub fn generate_layer0_proof(
    block_leaf_hashes: &[[u8; 32]],
    target_pos_in_window: usize,
    same_layer_root: Option<[u8; 32]>,
    higher_layer_root: Option<[u8; 32]>,
) -> anyhow::Result<([u8; 32], Vec<[u8; 32]>, usize)> {
    let hasher = PoseidonHasher::new();
    let leaves = build_leaves(block_leaf_hashes, same_layer_root, higher_layer_root);
    let pos = target_pos_in_window + 2; // +2 because positions 0,1 = higher_layer_root, same_layer_root
    let root = dense_merkle_root(&hasher, &leaves);
    let proof = dense_merkle_proof(&hasher, &leaves, pos);
    Ok((root, proof, pos))
}

pub fn generate_layer_n_proof(
    layer_root_hashes: &[[u8; 32]],
    target_root_hash: [u8; 32],
    same_layer_root: Option<[u8; 32]>,
    higher_layer_root: Option<[u8; 32]>,
) -> anyhow::Result<([u8; 32], Vec<[u8; 32]>, usize)> {
    let hasher = PoseidonHasher::new();
    let leaves = build_leaves(layer_root_hashes, same_layer_root, higher_layer_root);

    let pos = leaves
        .iter()
        .position(|h| *h == target_root_hash)
        .ok_or(anyhow::anyhow!("target root hash not found in leaves"))?;

    let root = dense_merkle_root(&hasher, &leaves);
    let proof = dense_merkle_proof(&hasher, &leaves, pos);
    Ok((root, proof, pos))
}

pub fn verify_dense_proof(
    root: &[u8; 32],
    leaf: &[u8; 32],
    pos: usize,
    proof: &[[u8; 32]],
) -> bool {
    let hasher = PoseidonHasher::new();
    dense_merkle_verify(&hasher, root, leaf, pos, proof)
}

/// Generate a Merkle proof for a specific ext_out message inside a block.
///
/// Builds the leaf array from `tracked_ext_out_messages` (same iteration as
/// `compute_ext_out_messages_root`), locates the target message, and returns
/// `(root, leaf_hash, position, proof_path)`.
pub fn generate_ext_message_proof(
    tracked_ext_out_messages: &HashMap<AccountRouting, Vec<[u8; 32]>>,
    target_account_routing: &AccountRouting,
    target_message_hash: &[u8; 32],
) -> anyhow::Result<([u8; 32], [u8; 32], usize, Vec<[u8; 32]>)> {
    let hasher = PoseidonHasher::new();

    // Build leaf hashes in the same order as compute_ext_out_messages_root
    let mut leaf_hashes = vec![];
    for (account_routing, messages) in tracked_ext_out_messages {
        let (dapp, acc) = account_routing.unpack_for_hash();
        for message in messages {
            leaf_hashes.push(compute_ext_message_leaf_hash(&dapp, &acc, message));
        }
    }

    // Compute the target leaf hash
    let (dapp, acc) = target_account_routing.unpack_for_hash();
    let target_leaf = compute_ext_message_leaf_hash(&dapp, &acc, target_message_hash);

    // Find position of the target leaf
    let pos = leaf_hashes
        .iter()
        .position(|h| *h == target_leaf)
        .ok_or(anyhow::anyhow!("target message leaf not found in ext_out_messages"))?;

    let root = dense_merkle_root(&hasher, &leaf_hashes);
    let proof = dense_merkle_proof(&hasher, &leaf_hashes, pos);

    Ok((root, target_leaf, pos, proof))
}
