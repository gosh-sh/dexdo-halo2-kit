//! Unified chain walker for `MultiHopProof` bundle witnesses.
//!
//! Produces a `BundleWitnessJson` from an ordered path of block IDs
//! `[X, ..., Y]` (X = event block, thread t; Y = anchor block, thread 0).
//! One code path handles both:
//!
//! - **t = 0** (single-thread event): caller passes `path = [X]` (length 1).
//!   All `N_BUNDLE * H_HOPS_PER_PROOF = 20` hop slots are emitted as
//!   inactive padding with `ref_block_id == block_id == X`. Salted endpoints
//!   still differ across slots because BC-005 mixes each position tag
//!   `0..=20` into the Poseidon output — the bundle shape is
//!   indistinguishable from the multi-thread case (spec §7.5).
//! - **t ≠ 0**: `path = [X, mid_1, ..., mid_{L-1}, Y]` (length `L + 1`,
//!   `L ∈ [1, 20]`). First `L` slots are active hops; the remaining
//!   `20 - L` slots are inactive padding carrying `Y`.
//!
//! ## Hop direction and semantics
//!
//! The circuit's per-hop invariant (per
//! `dex_halo2_circuit::multi_hop_proof::prove_hop_salted_endpoints`):
//!
//! ```text
//! salted_start = Poseidon(salt, ref_block_id, start_position)
//! salted_end   = Poseidon(salt, block_id,     end_position)
//! ```
//!
//! Combined with the SHA-256 opening of `block_id → block_merkle_tree_leaves[7]`
//! and the Poseidon opening of `L7 → proof_block_refs[ref_index]`, this
//! proves *`block` (the newer opening block) references `ref_block` (older)*
//! via one of its cross-thread `refs` slots (`ref_index ≥ 1`, spec §5.1).
//!
//! Refs point to older blocks (spec §2.3), so `ref_block_id` is older than
//! `block_id`. The chain therefore runs chronologically **oldest → newest**:
//! `X` (path[0], oldest) is on the event thread; `Y` (path[last], newest)
//! is the thread-0 anchor whose transitive L7 refs commit back to `X`.
//!
//! For hop `i` (0-indexed):
//! - `ref_block_id = path[i]`     (older)
//! - `block_id     = path[i + 1]` (newer; whose L7 we open)
//!
//! The walker fetches `path[1..]` from GQL to get their `proof_block_refs`,
//! finds the `ref_index` at which `path[i]` appears, and builds the
//! Poseidon inner path + SHA-256 depth-4 outer path.

use anyhow::{ensure, Context};

use dex_halo2_circuit::multi_hop_witness::{
    block_merkle_leaf_proof, proof_block_ref_inner_path_native, proof_block_refs_root_native,
    ref_leaf_hash_native, verify_block_merkle_leaf_proof, verify_proof_block_ref_inner_path,
    BLOCK_MERKLE_DEPTH, H_HOPS_PER_PROOF, MAX_PROOF_BLOCK_REFS_DEPTH, N_BUNDLE,
};
use dex_halo2_circuit::salt::{
    compute_salt_commitment_native, compute_salt_native, compute_salted_block_id_native,
};
use gosh_dense_balanced_tree::{bytes_to_fr, fr_to_bytes};

use crate::blockchain::{query_block_by_id, GqlProofBlock, TvmClient, PROOF_BLOCK_REFS_LEAF_INDEX};
use crate::bundle_witness::{BundleWitnessJson, HopWitnessJson, MultiHopSnarkWitnessJson};

/// Total hop slots in a bundle. `N_BUNDLE * H_HOPS_PER_PROOF = 20`.
pub const BUNDLE_HOP_SLOTS: usize = N_BUNDLE * H_HOPS_PER_PROOF;

/// Fixed inactive-hop `ref_index`. Any value in `[1, 2^refs_tree_depth)` is
/// accepted by the circuit when `is_active == 0`, but we pick `1` for
/// determinism.
const INACTIVE_HOP_REF_INDEX: usize = 1;
/// Fixed inactive-hop `refs_tree_depth`. Range check requires it in
/// `[0, MAX_PROOF_BLOCK_REFS_DEPTH]`; `1` keeps `INACTIVE_HOP_REF_INDEX` valid.
const INACTIVE_HOP_REFS_TREE_DEPTH: u8 = 1;

fn parse_block_id_hex(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).with_context(|| format!("invalid hex `{hex_str}`"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        anyhow::format_err!(
            "expected 32-byte block_id, got {} bytes for `{hex_str}`",
            hex_str.len() / 2
        )
    })
}

fn bytes_to_hex(b: &[u8; 32]) -> String {
    hex::encode(b)
}

fn fr_to_hex(f: halo2_base::halo2_proofs::halo2curves::bn256::Fr) -> String {
    hex::encode(fr_to_bytes(f))
}

/// Compute the salted-block-id at a given bundle-global position. The
/// `block_id_bytes` are raw 32-byte LE bytes (byte identical to the on-disk
/// block_id from GQL). Position semantics: X-side start = 0, hop 0 covers
/// positions (0, 1), ..., hop 19 covers (19, 20), Y-side end = 20.
fn salted_at(
    salt: halo2_base::halo2_proofs::halo2curves::bn256::Fr,
    block_id: &[u8; 32],
    position: u64,
) -> halo2_base::halo2_proofs::halo2curves::bn256::Fr {
    compute_salted_block_id_native(salt, block_id, position)
}

/// Fetch one hop's opening block from GQL and locate `ref_block_id` inside
/// its `proof_block_refs`. Returns the fully populated (except for
/// salted-endpoint fields) hop witness.
///
/// Self-check: reruns `block_merkle_leaf_proof` (SHA outer) and
/// `proof_block_ref_inner_path_native` (Poseidon inner) natively and verifies
/// both openings before emitting.
async fn build_active_hop(
    client: TvmClient,
    ref_block_id: &[u8; 32],
    block_id: &[u8; 32],
) -> anyhow::Result<HopWitnessJson> {
    let block_id_hex = bytes_to_hex(block_id);
    let block = query_block_by_id(client, &block_id_hex)
        .await
        .with_context(|| format!("failed to fetch opening block {block_id_hex}"))?;
    ensure!(
        block.block_id == *block_id,
        "GQL returned block_id {} for query {}",
        bytes_to_hex(&block.block_id),
        block_id_hex
    );

    let l7 = block.block_merkle_tree_leaves[PROOF_BLOCK_REFS_LEAF_INDEX];
    let outer_siblings = block_merkle_leaf_proof(
        &block.block_merkle_tree_leaves,
        PROOF_BLOCK_REFS_LEAF_INDEX,
    );
    ensure!(
        verify_block_merkle_leaf_proof(
            &block.block_id,
            &l7,
            PROOF_BLOCK_REFS_LEAF_INDEX,
            &outer_siblings,
        ),
        "SHA depth-4 opening of L7 does not verify for opening block {block_id_hex}"
    );

    // Locate `ref_block_id` inside the opening block's proof_block_refs.
    // Slot 0 is the parent (same-thread) and forbidden as a hop edge (§5.1),
    // so search from index 1.
    let ref_index = block
        .proof_block_refs
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, r)| **r == *ref_block_id)
        .map(|(i, _)| i)
        .ok_or_else(|| {
            anyhow::format_err!(
                "ref_block_id {} not found in proof_block_refs[1..] of opening block {block_id_hex}",
                bytes_to_hex(ref_block_id)
            )
        })?;

    let (inner_path, refs_tree_depth) =
        proof_block_ref_inner_path_native(&block.proof_block_refs, ref_index);
    let leaf_hash = ref_leaf_hash_native(ref_index, ref_block_id);
    ensure!(
        verify_proof_block_ref_inner_path(&l7, &leaf_hash, ref_index, &inner_path, refs_tree_depth),
        "Poseidon L7 inner opening does not verify for opening block {block_id_hex}"
    );
    let recomputed_l7 = proof_block_refs_root_native(&block.proof_block_refs);
    ensure!(
        recomputed_l7 == l7,
        "recomputed L7 root {} != block_merkle_tree_leaves[7] {} on opening block {block_id_hex}",
        bytes_to_hex(&recomputed_l7),
        bytes_to_hex(&l7)
    );

    // Sanity-check envelope_hash is present (unconstrained on chain, but we
    // still want to fail loudly if GQL returned a zero envelope).
    let _ = &block.envelope_hash;

    Ok(HopWitnessJson {
        is_active: true,
        ref_block_id_hex: bytes_to_hex(ref_block_id),
        block_id_hex: bytes_to_hex(block_id),
        l7_hex: bytes_to_hex(&l7),
        block_merkle_leaf_proof_l7_hex: [
            bytes_to_hex(&outer_siblings[0]),
            bytes_to_hex(&outer_siblings[1]),
            bytes_to_hex(&outer_siblings[2]),
            bytes_to_hex(&outer_siblings[3]),
        ],
        ref_index,
        refs_tree_depth,
        proof_block_ref_inner_path_hex: std::array::from_fn(|i| bytes_to_hex(&inner_path[i])),
        // Endpoints filled in by the enclosing bundle builder once bundle-global
        // positions are known.
        salted_start_block_id_hex: String::new(),
        salted_end_block_id_hex: String::new(),
    })
}

/// Build an inactive-padding hop carrying `pad_bid` on both endpoints.
/// Circuit constraint `ref_block_id_bytes == block_id_bytes` (byte-equality)
/// is what gates the propagation; the salted endpoints still differ (they
/// absorb distinct positions).
fn build_inactive_hop(pad_bid: &[u8; 32]) -> HopWitnessJson {
    HopWitnessJson {
        is_active: false,
        ref_block_id_hex: bytes_to_hex(pad_bid),
        block_id_hex: bytes_to_hex(pad_bid),
        l7_hex: bytes_to_hex(&[0u8; 32]),
        block_merkle_leaf_proof_l7_hex: std::array::from_fn(|_| bytes_to_hex(&[0u8; 32])),
        ref_index: INACTIVE_HOP_REF_INDEX,
        refs_tree_depth: INACTIVE_HOP_REFS_TREE_DEPTH,
        proof_block_ref_inner_path_hex: std::array::from_fn(|_| bytes_to_hex(&[0u8; 32])),
        salted_start_block_id_hex: String::new(),
        salted_end_block_id_hex: String::new(),
    }
}

/// Assemble the full 20-slot hop list from `L` active hops + `20 - L`
/// inactive pads, then populate every slot's `salted_start`/`salted_end` at
/// its bundle-global position. Also cross-checks intra-chain glue
/// (`hops[i].block_id == hops[i+1].ref_block_id`) matches by construction.
fn assemble_full_hop_list(
    salt: halo2_base::halo2_proofs::halo2curves::bn256::Fr,
    active: Vec<HopWitnessJson>,
    pad_bid: &[u8; 32],
) -> anyhow::Result<Vec<HopWitnessJson>> {
    ensure!(
        active.len() <= BUNDLE_HOP_SLOTS,
        "chain length {} exceeds bundle capacity N_BUNDLE * H_HOPS_PER_PROOF = {BUNDLE_HOP_SLOTS}",
        active.len()
    );

    let mut hops: Vec<HopWitnessJson> = Vec::with_capacity(BUNDLE_HOP_SLOTS);
    hops.extend(active);
    while hops.len() < BUNDLE_HOP_SLOTS {
        hops.push(build_inactive_hop(pad_bid));
    }

    for (slot, hop) in hops.iter_mut().enumerate() {
        let ref_bytes = parse_block_id_hex(&hop.ref_block_id_hex)?;
        let block_bytes = parse_block_id_hex(&hop.block_id_hex)?;
        let start_position = slot as u64;
        let end_position = slot as u64 + 1;
        let salted_start = salted_at(salt, &ref_bytes, start_position);
        let salted_end = salted_at(salt, &block_bytes, end_position);
        hop.salted_start_block_id_hex = fr_to_hex(salted_start);
        hop.salted_end_block_id_hex = fr_to_hex(salted_end);
    }

    // Intra-chain glue: hops[i].block_id == hops[i+1].ref_block_id. Active-run
    // is glued by walker construction; inactive pads carry `pad_bid` on both
    // sides. The active→inactive boundary requires the last active hop's
    // block_id (= path.last() = Y = pad_bid). Enforce here so a mis-built
    // walker fails loudly before proof generation.
    for i in 0..hops.len() - 1 {
        ensure!(
            hops[i].block_id_hex == hops[i + 1].ref_block_id_hex,
            "intra-bundle chain glue broken at slot {i}: block_id {} != next.ref_block_id {}",
            hops[i].block_id_hex,
            hops[i + 1].ref_block_id_hex
        );
    }

    Ok(hops)
}

/// Group the 20 hops into `N_BUNDLE` snarks of `H_HOPS_PER_PROOF` hops each.
fn group_into_snarks(
    hops: Vec<HopWitnessJson>,
    salt_commitment_hex: &str,
) -> anyhow::Result<[MultiHopSnarkWitnessJson; N_BUNDLE]> {
    ensure!(
        hops.len() == BUNDLE_HOP_SLOTS,
        "expected {BUNDLE_HOP_SLOTS} hops, got {}",
        hops.len()
    );
    let mut iter = hops.into_iter();
    let snarks: [MultiHopSnarkWitnessJson; N_BUNDLE] = std::array::from_fn(|b| {
        let hop_arr: [HopWitnessJson; H_HOPS_PER_PROOF] =
            std::array::from_fn(|_| iter.next().expect("hop count checked above"));
        MultiHopSnarkWitnessJson {
            bundle_index: b as u32,
            hops: hop_arr,
            salt_commitment_hex: salt_commitment_hex.to_string(),
        }
    });
    Ok(snarks)
}

/// Build a full bundle witness. Handles t=0 and t≠0 uniformly (spec §7.5).
///
/// `path_hex` is the ordered chain `[X, ..., Y]` (oldest to newest). For
/// t=0 pass `path_hex = [X]` (single entry). For t≠0 pass all intermediate
/// blocks between X and Y inclusive. Length must be in `[1, 21]`.
///
/// Cross-checks salted-endpoint continuity so the emitted witness matches
/// what `dex_halo2_circuit::bundle_verifier::verify_bundle` will assert
/// on-chain (bundle head/tail vs DexFinal salted_X_start/salted_Y_end and
/// adjacent-snark continuity).
pub async fn build_bundle_witness(
    client: TvmClient,
    sk_u_hex: &str,
    dex_final_fixture_path: &str,
    path_hex: &[String],
    description: String,
) -> anyhow::Result<BundleWitnessJson> {
    ensure!(!path_hex.is_empty(), "path must contain at least the event block (path[0] = X)");
    ensure!(
        path_hex.len() <= BUNDLE_HOP_SLOTS + 1,
        "path length {} exceeds N_BUNDLE * H_HOPS_PER_PROOF + 1 = {}",
        path_hex.len(),
        BUNDLE_HOP_SLOTS + 1
    );

    let path_bytes: Vec<[u8; 32]> = path_hex
        .iter()
        .map(|h| parse_block_id_hex(h))
        .collect::<anyhow::Result<_>>()?;
    let x_block_id = path_bytes[0];
    let y_block_id = *path_bytes.last().expect("path non-empty checked");

    // Salt derivation matches dex_halo2_circuit::salt exactly.
    let sk_u_bytes = parse_block_id_hex(sk_u_hex).context("invalid sk_u_hex")?;
    let sk_u_fr = bytes_to_fr(&sk_u_bytes);
    let salt = compute_salt_native(sk_u_fr);
    let salt_commitment = compute_salt_commitment_native(salt);
    let salt_commitment_hex = fr_to_hex(salt_commitment);

    // Walk path[0..len-1] → path[1..len], one hop per adjacent pair. For
    // path.len() == 1 (t=0), the loop is empty and `active` stays [].
    let mut active: Vec<HopWitnessJson> = Vec::with_capacity(path_bytes.len().saturating_sub(1));
    for i in 0..path_bytes.len().saturating_sub(1) {
        let hop = build_active_hop(client.clone(), &path_bytes[i], &path_bytes[i + 1]).await?;
        active.push(hop);
    }

    // Padding endpoint carries the anchor block (Y). For t=0 the anchor is
    // X itself, so pad_bid == X == Y.
    let pad_bid = y_block_id;
    let hops = assemble_full_hop_list(salt, active, &pad_bid)?;

    // Cross-check the bundle-level salted continuity that
    // `verify_bundle` will assert on-chain:
    // - hops[0].salted_start must equal DexFinal salted_X_start (salted(X, 0))
    // - hops[last].salted_end must equal DexFinal salted_Y_end (salted(Y, 20))
    let expected_head = fr_to_hex(salted_at(salt, &x_block_id, 0));
    let expected_tail = fr_to_hex(salted_at(salt, &y_block_id, BUNDLE_HOP_SLOTS as u64));
    ensure!(
        hops[0].salted_start_block_id_hex == expected_head,
        "bundle head salted_start {} != expected salted(X, 0) {}",
        hops[0].salted_start_block_id_hex,
        expected_head
    );
    ensure!(
        hops[BUNDLE_HOP_SLOTS - 1].salted_end_block_id_hex == expected_tail,
        "bundle tail salted_end {} != expected salted(Y, {}) {}",
        hops[BUNDLE_HOP_SLOTS - 1].salted_end_block_id_hex,
        BUNDLE_HOP_SLOTS,
        expected_tail
    );

    let snarks = group_into_snarks(hops, &salt_commitment_hex)?;

    Ok(BundleWitnessJson {
        description,
        sk_u_hex: sk_u_hex.to_string(),
        dex_final_fixture_path: dex_final_fixture_path.to_string(),
        snarks,
    })
}

// ---------------------------------------------------------------------------
// Native fixture builder (no GQL) — used by tests and by callers who
// already have `GqlProofBlock` values in-memory.
// ---------------------------------------------------------------------------

/// Native variant of [`build_bundle_witness`] that consumes pre-fetched
/// blocks instead of querying GQL. `opening_blocks[i]` must be the block at
/// `path_bytes[i + 1]` (the newer, opening block of hop `i`). Pass an empty
/// `opening_blocks` slice for the t=0 case.
pub fn build_bundle_witness_from_blocks(
    sk_u_hex: &str,
    dex_final_fixture_path: &str,
    path_bytes: &[[u8; 32]],
    opening_blocks: &[GqlProofBlock],
    description: String,
) -> anyhow::Result<BundleWitnessJson> {
    ensure!(
        !path_bytes.is_empty(),
        "path must contain at least the event block (path[0] = X)"
    );
    ensure!(
        path_bytes.len() <= BUNDLE_HOP_SLOTS + 1,
        "path length {} exceeds N_BUNDLE * H_HOPS_PER_PROOF + 1 = {}",
        path_bytes.len(),
        BUNDLE_HOP_SLOTS + 1
    );
    ensure!(
        opening_blocks.len() + 1 == path_bytes.len(),
        "opening_blocks len {} must equal path len {} - 1",
        opening_blocks.len(),
        path_bytes.len()
    );

    let sk_u_bytes = parse_block_id_hex(sk_u_hex).context("invalid sk_u_hex")?;
    let sk_u_fr = bytes_to_fr(&sk_u_bytes);
    let salt = compute_salt_native(sk_u_fr);
    let salt_commitment = compute_salt_commitment_native(salt);
    let salt_commitment_hex = fr_to_hex(salt_commitment);

    let mut active: Vec<HopWitnessJson> = Vec::with_capacity(opening_blocks.len());
    for (i, block) in opening_blocks.iter().enumerate() {
        ensure!(
            block.block_id == path_bytes[i + 1],
            "opening_blocks[{i}].block_id {} does not match path[{}] {}",
            bytes_to_hex(&block.block_id),
            i + 1,
            bytes_to_hex(&path_bytes[i + 1])
        );
        let hop = build_active_hop_from_block(&path_bytes[i], block)?;
        active.push(hop);
    }

    let y_block_id = *path_bytes.last().expect("path non-empty checked");
    let hops = assemble_full_hop_list(salt, active, &y_block_id)?;
    let snarks = group_into_snarks(hops, &salt_commitment_hex)?;

    Ok(BundleWitnessJson {
        description,
        sk_u_hex: sk_u_hex.to_string(),
        dex_final_fixture_path: dex_final_fixture_path.to_string(),
        snarks,
    })
}

/// Native twin of [`build_active_hop`]. Kept private; the two entry points
/// share [`assemble_full_hop_list`] for endpoint computation and glue checks.
fn build_active_hop_from_block(
    ref_block_id: &[u8; 32],
    block: &GqlProofBlock,
) -> anyhow::Result<HopWitnessJson> {
    let block_id_hex = bytes_to_hex(&block.block_id);
    let l7 = block.block_merkle_tree_leaves[PROOF_BLOCK_REFS_LEAF_INDEX];
    let outer_siblings = block_merkle_leaf_proof(
        &block.block_merkle_tree_leaves,
        PROOF_BLOCK_REFS_LEAF_INDEX,
    );
    ensure!(
        verify_block_merkle_leaf_proof(
            &block.block_id,
            &l7,
            PROOF_BLOCK_REFS_LEAF_INDEX,
            &outer_siblings,
        ),
        "SHA depth-4 opening of L7 does not verify for opening block {block_id_hex}"
    );

    let ref_index = block
        .proof_block_refs
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, r)| **r == *ref_block_id)
        .map(|(i, _)| i)
        .ok_or_else(|| {
            anyhow::format_err!(
                "ref_block_id {} not found in proof_block_refs[1..] of opening block {block_id_hex}",
                bytes_to_hex(ref_block_id)
            )
        })?;

    let (inner_path, refs_tree_depth) =
        proof_block_ref_inner_path_native(&block.proof_block_refs, ref_index);
    let leaf_hash = ref_leaf_hash_native(ref_index, ref_block_id);
    ensure!(
        verify_proof_block_ref_inner_path(&l7, &leaf_hash, ref_index, &inner_path, refs_tree_depth),
        "Poseidon L7 inner opening does not verify for opening block {block_id_hex}"
    );
    let recomputed_l7 = proof_block_refs_root_native(&block.proof_block_refs);
    ensure!(
        recomputed_l7 == l7,
        "recomputed L7 root {} != block_merkle_tree_leaves[7] {} on opening block {block_id_hex}",
        bytes_to_hex(&recomputed_l7),
        bytes_to_hex(&l7)
    );

    let _ = BLOCK_MERKLE_DEPTH; // silence unused-import lint if outer_siblings type ever changes
    let _ = MAX_PROOF_BLOCK_REFS_DEPTH;

    Ok(HopWitnessJson {
        is_active: true,
        ref_block_id_hex: bytes_to_hex(ref_block_id),
        block_id_hex,
        l7_hex: bytes_to_hex(&l7),
        block_merkle_leaf_proof_l7_hex: [
            bytes_to_hex(&outer_siblings[0]),
            bytes_to_hex(&outer_siblings[1]),
            bytes_to_hex(&outer_siblings[2]),
            bytes_to_hex(&outer_siblings[3]),
        ],
        ref_index,
        refs_tree_depth,
        proof_block_ref_inner_path_hex: std::array::from_fn(|i| bytes_to_hex(&inner_path[i])),
        salted_start_block_id_hex: String::new(),
        salted_end_block_id_hex: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Tests — cover both the uniformity path (t=0, empty walk) and a synthetic
// t≠0 walk built against handcrafted `GqlProofBlock` values.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use dex_halo2_circuit::multi_hop_witness::BLOCK_MERKLE_LEAF_COUNT;
    use std::collections::BTreeMap;

    use crate::types::ThreadIdentifier;

    fn synthetic_block(
        block_id_seed: u8,
        proof_block_refs: Vec<[u8; 32]>,
    ) -> GqlProofBlock {
        // Compute L7 = Poseidon root of proof_block_refs, embed at leaf 7,
        // recompute block_id = SHA-root(leaves).
        let l7 = proof_block_refs_root_native(&proof_block_refs);
        let mut leaves = [[0u8; 32]; BLOCK_MERKLE_LEAF_COUNT];
        leaves[PROOF_BLOCK_REFS_LEAF_INDEX] = l7;
        // Leaf 0..=6 and 8..=15: fill with predictable seed patterns so we
        // exercise a non-degenerate SHA path. Leaf 8 = tracked_ext_out root
        // (arbitrary here — walker doesn't touch it).
        for (i, leaf) in leaves.iter_mut().enumerate() {
            if i == PROOF_BLOCK_REFS_LEAF_INDEX {
                continue;
            }
            leaf[0] = block_id_seed;
            leaf[1] = i as u8;
        }
        let block_id =
            dex_halo2_circuit::multi_hop_witness::block_merkle_root(&leaves);
        GqlProofBlock {
            block_id,
            thread_id: ThreadIdentifier::default(),
            height: block_id_seed as u64,
            envelope_hash: [block_id_seed; 32],
            tracked_ext_out_messages_root: leaves[8],
            tracked_ext_out_messages: BTreeMap::new(),
            history_proofs: BTreeMap::new(),
            block_merkle_tree_leaves: leaves,
            proof_block_refs,
        }
    }

    #[test]
    fn t0_path_produces_all_inactive_bundle_with_valid_endpoints() {
        // t=0: path = [X], no opening blocks needed.
        let x_id = [7u8; 32];
        let sk_u_hex = "0100000000000000000000000000000000000000000000000000000000000000";
        let bundle = build_bundle_witness_from_blocks(
            sk_u_hex,
            "irrelevant.json",
            &[x_id],
            &[],
            "t=0 all-inactive".to_string(),
        )
        .expect("t=0 bundle build");

        for (b, snark) in bundle.snarks.iter().enumerate() {
            assert_eq!(snark.bundle_index, b as u32);
            for hop in snark.hops.iter() {
                assert!(!hop.is_active, "t=0 must be all-inactive");
                assert_eq!(hop.ref_block_id_hex, hex::encode(x_id));
                assert_eq!(hop.block_id_hex, hex::encode(x_id));
                assert_ne!(
                    hop.salted_start_block_id_hex, hop.salted_end_block_id_hex,
                    "BC-005: salted endpoints must differ across positions even for X=Y"
                );
                // Salt commitment is shared across snarks.
                assert_eq!(snark.salt_commitment_hex, bundle.snarks[0].salt_commitment_hex);
            }
        }

        // Continuity: snark[b].hops[last].salted_end == snark[b+1].hops[0].salted_start.
        for b in 0..N_BUNDLE - 1 {
            assert_eq!(
                bundle.snarks[b].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id_hex,
                bundle.snarks[b + 1].hops[0].salted_start_block_id_hex,
                "inter-snark salted continuity broken at bundle boundary {b}"
            );
        }
    }

    #[test]
    fn t_nonzero_two_hop_path_glues_end_to_end() {
        // path = [X, mid, Y], two active hops:
        // hop 0: ref = X, opening block = mid   (mid.refs must contain X at slot ≥ 1)
        // hop 1: ref = mid, opening block = Y   (Y.refs must contain mid at slot ≥ 1)
        let x_id = [1u8; 32];
        let mid_parent = [42u8; 32];
        let y_parent = [43u8; 32];

        let mid_block = synthetic_block(0x10, vec![mid_parent, x_id]);
        let y_block = synthetic_block(0x20, vec![y_parent, mid_block.block_id]);

        let path = vec![x_id, mid_block.block_id, y_block.block_id];
        let sk_u_hex = "0200000000000000000000000000000000000000000000000000000000000000";
        let bundle = build_bundle_witness_from_blocks(
            sk_u_hex,
            "irrelevant.json",
            &path,
            &[mid_block.clone(), y_block.clone()],
            "t!=0 L=2".to_string(),
        )
        .expect("t!=0 bundle build");

        // Slot 0: active hop X → mid.
        let hop0 = &bundle.snarks[0].hops[0];
        assert!(hop0.is_active);
        assert_eq!(hop0.ref_block_id_hex, hex::encode(x_id));
        assert_eq!(hop0.block_id_hex, hex::encode(mid_block.block_id));

        // Slot 1: active hop mid → Y.
        let hop1 = &bundle.snarks[0].hops[1];
        assert!(hop1.is_active);
        assert_eq!(hop1.ref_block_id_hex, hex::encode(mid_block.block_id));
        assert_eq!(hop1.block_id_hex, hex::encode(y_block.block_id));

        // Slots 2..20: inactive pads carrying Y.
        for slot in 2..BUNDLE_HOP_SLOTS {
            let s = slot / H_HOPS_PER_PROOF;
            let h = slot % H_HOPS_PER_PROOF;
            let hop = &bundle.snarks[s].hops[h];
            assert!(!hop.is_active, "slot {slot} must be inactive padding");
            assert_eq!(hop.ref_block_id_hex, hex::encode(y_block.block_id));
            assert_eq!(hop.block_id_hex, hex::encode(y_block.block_id));
        }

        // Intra-chain glue at active→inactive boundary (slot 1 → slot 2):
        // hops[1].block_id (= Y) == hops[2].ref_block_id (= Y).
        assert_eq!(hop1.block_id_hex, bundle.snarks[0].hops[2].ref_block_id_hex);

        // Cross-snark continuity for every boundary.
        for b in 0..N_BUNDLE - 1 {
            assert_eq!(
                bundle.snarks[b].hops[H_HOPS_PER_PROOF - 1].salted_end_block_id_hex,
                bundle.snarks[b + 1].hops[0].salted_start_block_id_hex,
                "inter-snark salted continuity broken at bundle boundary {b}"
            );
        }
    }

    #[test]
    fn walker_rejects_ref_at_parent_slot_zero() {
        // Slot 0 of proof_block_refs is the parent (same-thread) and must
        // not be openable as a cross-thread hop edge (§5.1). We put the
        // sought ref at slot 0 only and expect the walker to fail.
        let x_id = [3u8; 32];
        let mid_block = synthetic_block(0x11, vec![x_id]); // x_id at slot 0 only

        let path = vec![x_id, mid_block.block_id];
        let sk_u_hex = "0300000000000000000000000000000000000000000000000000000000000000";
        let err = build_bundle_witness_from_blocks(
            sk_u_hex,
            "irrelevant.json",
            &path,
            &[mid_block],
            "reject-parent-slot".to_string(),
        )
        .expect_err("must reject slot-0 (parent) ref as cross-thread edge");
        assert!(
            format!("{err}").contains("not found in proof_block_refs[1..]"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn walker_rejects_missing_ref() {
        let x_id = [4u8; 32];
        let unrelated = [99u8; 32];
        let mid_block = synthetic_block(0x12, vec![unrelated, [77u8; 32]]);

        let path = vec![x_id, mid_block.block_id];
        let sk_u_hex = "0400000000000000000000000000000000000000000000000000000000000000";
        let err = build_bundle_witness_from_blocks(
            sk_u_hex,
            "irrelevant.json",
            &path,
            &[mid_block],
            "reject-missing".to_string(),
        )
        .expect_err("must reject when X is not among refs");
        assert!(
            format!("{err}").contains("not found in proof_block_refs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn walker_rejects_over_capacity_path() {
        let dummy = [5u8; 32];
        // path.len() = 22 = BUNDLE_HOP_SLOTS + 2 → too long.
        let path: Vec<[u8; 32]> = (0..=21u8)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = i;
                b
            })
            .collect();
        let _ = dummy;
        // opening_blocks would need 21 entries; we skip that and let the
        // path-length check trip first.
        let sk_u_hex = "0500000000000000000000000000000000000000000000000000000000000000";
        let err = build_bundle_witness_from_blocks(
            sk_u_hex,
            "irrelevant.json",
            &path,
            &[],
            "over-cap".to_string(),
        )
        .expect_err("must reject path longer than 21");
        assert!(
            format!("{err}").contains("exceeds N_BUNDLE * H_HOPS_PER_PROOF + 1"),
            "unexpected error: {err}"
        );
    }
}
