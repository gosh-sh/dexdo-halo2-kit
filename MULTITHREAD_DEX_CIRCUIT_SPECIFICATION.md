# Multi-Thread Cryptographic Scheme — DEX Circuit

Target embodiment: `dexdo-halo2-kit/dex-halo2-circuit` (DEX voucher circuit).

This document describes the cryptographic mechanism for proving, in zero knowledge, that a `VoucherGenerated` event in **any thread t** of Acki Nacki can be anchored, via cross-thread chaining when `t ≠ 0`, against a layer-N batch hash retained in thread 0's window of `GlobalHistoricalData`, and how the DEX circuit embodies that mechanism.

## 0. Terminology

| Term | Meaning |
|------|---------|
| **BWS** | Batch Window Size = **128**. (`HISTORY_PROOF_WINDOW_SIZE` in `node/libs/history-proof/src/lib.rs`.) |
| **Batch M** (within thread 0) | The contiguous range of blocks at heights `[M·BWS, (M+1)·BWS − 1]` within thread 0. |
| **`#L<N>(M)`** | Layer-N batch hash for batch M of thread 0. Layer-1 is built over the blocks of batch M; layer-(N+1) is built over `BWS` consecutive layer-N hashes. |
| **X** | The **event block** — the block, in some thread t (t may or may not be 0), in which the `VoucherGenerated` event was emitted. Hidden witness. |
| **Y** | The **anchor block** — a block **in thread 0** that lies at the tail of a chain of cross-thread reference edges emanating from X. When t = 0, Y = X (uniformity case). Hidden witness. |
| **X-side / Y-side** | The portions of the DEX proof concerned with block X (event binding, in thread t) and block Y (thread-0 anchor) respectively. When t ≠ 0 they are separate; when t = 0 they collapse onto the same block. |
| **`event_hash`** | 32-byte hash of the voucher event message. Included as a leaf of X's `tracked_ext_out_messages` Merkle tree. |
| **Block leaf** (thread 0, layer-1) | `block_leaf = Poseidon96(block_id ‖ envelope_hash ‖ tracked_ext_out_messages_root)`. Feeds the per-batch layer-1 Poseidon dense-Merkle tree in thread 0. |
| **GlobalHistoricalData** | Node-side per-thread map (`HashMap<ThreadIdentifier, HistoryLayerData>`) of layer-N window hashes queried by the contract via `gosh.check_layer_hash(root, N)`. Under this protocol only thread 0's entry is populated. |
| **`finalLayerHistoricalHashRoot`** | The layer-N batch hash the prover anchors against — exposed as public input `inst[1]` of the DEX proof (see §10 for the full 13-slot layout). Must belong to thread 0's window. |
| **`layerNumber`** | Contract argument naming the layer N that `finalLayerHistoricalHashRoot` belongs to. |
| **L** | True chain length in hops from X to Y. `L = 0` when t = 0 (X = Y); `L > 0` in the multi-thread case. |
| **`L_MAX`** | Circuit-side upper bound on L. **Production target = 300** (specified by the node team as the cross-thread walk-length ceiling under the current threading design). Current prototyping point is **20**; `N_BUNDLE = ceil(L_MAX / H)` scales linearly — moving to prod raises `N_BUNDLE` to 60, no change to per-snark K. |
| **`H`** | Hops packed per `MultiHopProof` snark. Locked at **5**. |
| **`N_BUNDLE`** | Number of `MultiHopProof` snarks per bundle. Currently **4** (prototyping `L_MAX = 20`); production **60** (`L_MAX = 300`). May be made dynamic per §7.5 dispatch. |

**Poseidon input convention (reminder).** Poseidon here operates on BN254 Fr (`|p| ≈ 254 bits`). A byte stream is packed into Fr in **31-byte chunks** (little-endian, high byte implicitly zero) so every chunk is unambiguously `< p` and no modular reduction is needed. An N-byte input consumes `⌈N/31⌉` Fr elements. This applies uniformly to every `Poseidon(...)` in this spec — the tagged L7 leaves, the Poseidon96 block-leaf, dense-Merkle combines, and the salted-endpoint hashes.

---

## 1. Anchor model

### 1.1 Where events happen vs. where they anchor

The `VoucherGenerated` event — declared in `RootPN.sol` as `event VoucherGenerated(uint256 skUCommit, uint voucherNominal, uint32 tokenType)` — may be emitted in **any** thread of Acki Nacki. The event's block X is therefore of arbitrary thread `t`.

The **anchor**, in contrast, must land in **thread 0**. Under this protocol only thread 0 produces layer trees: `history_proofs` are populated exclusively on thread-0 key blocks, and `GlobalHistoricalData[thread 0]` is the sole populated per-thread window. No other thread has a layer-N batch tree the contract can query. It follows that the anchor block Y must itself be a thread-0 block.

When `t = 0`, event and anchor coincide (`X = Y`) and no cross-thread bridging is needed. This is the "single-thread" case. 

When `t ≠ 0`, the proof must chain the event's block X, via cross-thread L7 reference edges (§5), to some thread-0 block Y that transitively references X. Only Y — a thread-0 block — can be anchored to `GlobalHistoricalData[thread 0]`.

### 1.2 The contract-side check

`RootPN.sol` (`acki-nacki/contracts/dex/RootPN.sol`) consumes the DEX proof together with `(finalLayerHistoricalHashRoot, layerNumber)` — the anchor the prover claims to hit — and asks the node whether that anchor exists in the layer-N window of `GlobalHistoricalData`:

```solidity
require(
    gosh.check_layer_hash(finalLayerHistoricalHashRoot, layerNumber),
    ERR_INVALID_HISTORY_PROOF
);
```

Two facts pin the anchor down:

1. **It's a public input of the proof.** `finalLayerHistoricalHashRoot` is exposed as `inst[1]` (see §10 for the full 13-slot layout), so the circuit binds every private witness to *this specific* root.
2. **It must live in thread 0.** `gosh.check_layer_hash` resolves against `GlobalHistoricalData[thread_id]`, and only thread 0's entry is ever populated (§1.1). The check therefore succeeds only when `finalLayerHistoricalHashRoot` is a genuine thread-0 layer-N batch hash — regardless of which thread RootPN itself runs in.

### 1.3 Anchoring simple strategy

The DEX circuit does not anchor against a single fixed layer. It anchors against `#L<N>(M)` for some `(N, M)` chosen by the prover, subject only to the node still retaining that root in `GlobalHistoricalData[thread 0][N]`. The prover for simplicity targets the smallest N (N = 1, cheapest in-circuit) and falls back to higher N if the layer-1 root containing the event has aged out.

In single thread setting (or if we consider what happen in thread 0 when we gonna prove detected block Y) anchoring hides the concrete block in which the voucher event happened — both the block's id / height (which would identify a small anonymity set) and, in the multi-thread case, the thread `t` of that block. The verifier learns the pair `(finalLayerHistoricalHashRoot, layerNumber)`, which subsumes a full batch (N = 1) or higher-layer aggregate (N > 1) of recent thread-0 history. Anchoring at a higher layer N (a larger anonymity set) is sometimes preferable even when a layer-1 anchor is still available. But this is not exhaustive discussion yet about anonymity. See below sections devoted to extra salting of involved block ids. Because in multithreading setting anchoring itself does not provide anonymity at all, only together with extra salt application. 

### 1.4 Uniformity between t = 0 and t ≠ 0

To keep the two cases indistinguishable to any external observer, the bundle shape and public-input schema are identical for both. When t = 0 the L7 walk collapses (all hops are no-ops, X = Y); when t ≠ 0 the walk actually chains blocks. The number of submitted snarks and their public-input layout do not depend on t.

---

## 2. block_id construction — depth-4, 16-leaf SHA-256 tree

Every block has `block_id = root of a 16-leaf SHA-256 Merkle tree of depth 4`. The 16 leaves are:

| Leaf | Definition | Hash family |
|------|------------|-------------|
| L0 | `Poseidon(layer_count ‖ (layer_id ‖ layer_root)×MAX_HISTORY_PROOF_LAYERS)` over the block's `history_proofs` map (populated only on thread-0 key blocks; zero elsewhere) | Poseidon |
| L1 | `SHA-256(bincode(CommonSection))` | SHA-256 |
| L2 | `Poseidon` dense-Merkle commitment to `old_bk_set` — zero if no BK change | Poseidon |
| L3 | `Poseidon` dense-Merkle commitment to `new_bk_set` — zero if no BK change | Poseidon |
| L4 | Poseidon dense-Merkle root over per-DApp TVM sub-block hashes (or tagged empty-block sentinel when the block carries no TVM transactions) | Poseidon |
| L5 | `SHA-256(bincode(DurableThreadAccountsStateDiff))` | SHA-256 |
| L6 | `SHA-256(tx_cnt.to_be_bytes())` (8-byte big-endian `u64`) | SHA-256 |
| L7 | Poseidon dense-Merkle root of `[parent_block_id, refs...]` (see §2.3) | Poseidon |
| **L8** | **`tracked_ext_out_messages_root`** — Poseidon dense-Merkle root of this block's tracked ext-out messages (see §2.4) | Poseidon |
| L9..L15 | `[0u8; 32]` (fixed zero padding) | — |

**Source of truth:** `node/src/types/ackinacki_block/mod.rs:499–567` (`block_merkle_leaves()`, `BLOCK_MERKLE_LEAF_COUNT = 16`); combine rule at `node/src/types/ackinacki_block/merkle.rs:11–37`. Cross-checked against `acki-nacki` HEAD `9f2916946` (2026-09-16). Landed 2026-07-08 in commit `4cd969bf9` ("Expanded Acki Nacki block Merkle leaves from 8 to 16").

Combine rule at every level: `SHA-256(left_32B ‖ right_32B)`. Fifteen SHA-256 invocations total to fold 16 leaves into `block_id`.

```
                                     block_id  (SHA-256, depth 4)
                                    /                          \
                              h0..7                              h8..15
                             /      \                          /        \
                          h0..3     h4..7                   h8..11    h12..15
                          /  \      /  \                    /   \      /   \
                        h01 h23   h45 h67                 h89 h10-11 h12-13 h14-15
                        / \ / \   / \ / \                / \  / \    / \    / \
                       L0 L1L2 L3 L4 L5L6 L7            L8 L9 L10 L11 L12 L13 L14 L15
```

### 2.1 Circuit-side implications of the L8..L15 layout

- **`L8` is the DEX circuit's only opening target on the X-side.** The circuit opens leaf L8 of X's block-id tree, exposing `X.tracked_ext_out_messages_root` as a 32-byte value.
- **The three siblings on the right-hand subtree are protocol-fixed constants.** L9..L15 are all `[0u8; 32]`, hence:
  - `h10-11 = SHA-256(0×32 ‖ 0×32)`  — constant
  - `h12-13 = SHA-256(0×32 ‖ 0×32) = h10-11`  — constant
  - `h14-15 = SHA-256(0×32 ‖ 0×32) = h10-11`  — constant
  - `h12..15 = SHA-256(h12-13 ‖ h14-15) = SHA-256(h10-11 ‖ h10-11)`  — constant
  - `L9 = 0×32`  — constant
  These four constants are hard-coded into the circuit as fixed cells; the prover does not witness them. Only the L8 leaf itself and its left-half cousin `h0..7` are live witnesses when opening L8.
- **Opening any leaf costs 4 SHA-256 compressions** — one per tree level. In particular, opening L8 walks `L8 → h89 → h8..11 → h8..15 → block_id`; three of the four siblings (`L9`, `h10-11`, `h12..15`) are the constants above, one (`h0..7`) is a witness. Opening L7 walks `L7 → h67 → h4..7 → h0..7 → block_id`; all four siblings (`L6`, `h45`, `h0..3`, `h8..15`) are witnesses. In `DexFinalProof` (§7.7), the same circuit also opens L8 for the event block, so `h8..15` there is re-derived at runtime from the block's live `L8` (+2 SHA compressions). In the L7 walk (§5), hops do **not** bind L8, so `h8..15` is left as an opaque witness sibling and no extra SHA is spent.

### 2.2 CommonSection — fields feeding L0, L1, L7, L8

`node/src/types/ackinacki_block/common_section.rs`, declaration order:

```
parent_block_id   : BlockIdentifier              // 32 bytes — fed to L7 (slot 0)
block_height      : BlockHeight
directives        : Directives
block_attestations: Vec<Envelope<AttestationData>>
round, producer_id, thread_id, threads_table
refs              : Vec<BlockIdentifier>          // fed to L7 (slots 1..n)
block_keeper_set_changes : Vec<...>
verify_complexity, acks, nacks, producer_selector
history_proofs    : BTreeMap<LayerNumber, ProofLayerRootHash>   // fed to L0; populated only for thread-0 key blocks
tracked_ext_out_messages_root : [u8; 32]          // = L8 (also feeds L1 via bincode)
tracked_ext_out_messages      : BTreeMap<...>     // preimage of the tree rooted at L8
block_keeper_set_change_proof_data : Option<...>
```

### 2.3 L7 — cross-thread reference tree (variable-depth on the chain side)

L7 is the Poseidon dense-Merkle root of `[parent_block_id, refs[0..n]]`, where each leaf is a tagged Poseidon hash:

```
REFERENCED_PARENT_BLOCK_TAG = b"acki-nacki:referenced-block:parent:v1"   (37 bytes)
REFERENCED_REF_BLOCK_TAG    = b"acki-nacki:referenced-block:ref:v1"     (34 bytes)

leaf[i] = Poseidon( tag_i ‖ proof_block_refs[i] )    (32 bytes out)
```

`proof_block_refs[0] = parent_block_id` (same thread by producer construction — see below); `proof_block_refs[1..1+n] = refs` (cross-thread). The tree width is `leaves.len().next_power_of_two()` — **not** a fixed 256-leaf shape — and is padded with literal `[0u8; 32]` leaves up to that width before folding with `Poseidon(left_32B ‖ right_32B)`. Source: `node/libs/history-proof/src/lib.rs:195–215` (`compute_referenced_block_leaf_hash`, `compute_referenced_blocks_root`) and `dense_merkle_root` in the same file; empty ref-list yields `[0u8; 32]`.

The chain imposes **no hard ref-count ceiling** — `refs` is a plain `Vec<BlockIdentifier>`, so real blocks have variable-depth L7 (observed depths 0..8; e.g. Michael's `test-multithread-cross-thread --threads 2` produces blocks with 1 or 2 L7 leaves → depth 0 or 1). The DEX circuit therefore witnesses the actual per-hop tree depth (`refs_tree_depth`) and walks an 8-step gated fold sized to `MAX_PROOF_BLOCK_REFS = 256` (depth 8); see §5.2 for the depth-witness handling.

**Slot-0 (`parent_block_id`) is same-thread by construction.** The producer for thread `t` selects its parent via `select_thread_last_finalized_block(&thread_id)` and sets the child's block height as `parent_height.next(&thread_id)` (`node/src/block/producer/producer_service/block_producer.rs:534,576,992`). The parent is therefore always in thread `t` itself. The only exception is the *spawn edge* — the first block of a newly-spawned thread T′ has as its parent the split block on the parent thread (`is_spawning_block(...)` at the same file, and `preprocessing.rs:162-190`). Spawn edges are irrelevant to voucher proofs: a producer that wants to witness such an edge for cross-thread anchoring can always add it to `refs`. **Consequence for §5:** the DEX circuit's L7 walk only opens `refs[0..n]` (slots `1..n`), never slot 0.

L7 is populated for **every** block and provides the outgoing edges the L7 walk (§5) follows.

### 2.4 L8 — tracked ext-out messages Merkle tree (the DEX-visible slot)

`L8 = tracked_ext_out_messages_root` is the **Poseidon** dense-Merkle root of the block's tracked outgoing external messages. The `VoucherGenerated` event is emitted as one such message, and its Poseidon-tagged leaf is included in this tree.

**Shape:** identical to L7 — chain-side variable depth via `leaves.len().next_power_of_two()`, `[0u8; 32]` padding, no chain-enforced ceiling. Same `dense_merkle_root` routine as L7 and the layer-N batch trees (source: `node/libs/history-proof/src/lib.rs:162–193` — `compute_ext_out_messages_root`, `compute_ext_message_leaf_hash`). Empty case yields `[0u8; 32]`.

**Leaf format:** `Poseidon(account_dapp_id ‖ account_id ‖ ext_message_hash)` — a **96-byte** preimage, no tag prefix. Exactly the same shape as `DarkDexCircuit`'s `ext_msg_leaf` (§7.7 constraint 4).

**Circuit handling:** the DEX circuit uses the same variable-depth gated fold as L7 (§2.3): pass real siblings to `preprocess_dense_proof_padded`, walk a fixed `MAX_EVENTS_TREE_DEPTH = 8` levels in-circuit (`dark_dex_circuit.rs:43`), and gate each level with a range-checked `num_events_levels` witness (`dark_dex_circuit.rs:576-585`). The 8-level cap bounds L8 to 256 messages per block on the prover side; the chain itself does not enforce this.

### 2.5 L0..L6 and L9..L15 in this design

- **L0, L1, L2, L3, L4, L5, L6** — each defined by the chain per the table above. On the X-side, all seven collectively appear only as the aggregate `h0..7` witness (the sole live sibling required to open L8). The DEX circuit does **not** parse any of L0..L6 individually.
- **L9..L15** — zero-initialised in the chain's `block_merkle_leaves()` and never overwritten (`node/src/types/ackinacki_block/mod.rs:556`). Their contribution to the block-id tree collapses to two SHA-256 constants (§2.1) baked into the circuit.

---

## 3. Per-thread layer-N batch tree (thread 0 only)

The per-layer batch tree is a **Poseidon dense Merkle** of width `BWS = 128`. It is built independently per batch per layer for thread 0 only; thread 0's layer-N tree roots are the values in `GlobalHistoricalData[N]`. **No other thread produces layer trees under this protocol.**

### 3.1 Layer-1 leaf: `block_leaf`

For every block B produced in thread 0, the producer of B's next key block emits a leaf:

```
block_leaf(B) = Poseidon( B.block_id ‖ B.envelope_hash ‖ B.tracked_ext_out_messages_root )
```

Total input: 96 bytes (three 32-byte fields). Single Poseidon invocation.

### 3.2 Layer-1 tree structure

Source: `HistoryBlockData::calculate_root_hash` at `node/src/types/history_proof.rs`.

For batch M of thread 0, the layer-1 tree has exactly `BWS + 2 = 130` real leaves, in this order:

```
leaves[0]         = last #L<2>(...) seen by thread 0 (zero if absent)   // higher-layer back-link
leaves[1]         = #L1(M − 1)                          (zero if M == 0)   // same-layer back-link
leaves[2 .. 130]  = block_leaf(B_{M·BWS + 0 .. M·BWS + BWS − 1})           // 128 block leaves
```

Padded to 256 with `[0u8; 32]`, folded as a Poseidon dense-Merkle of depth 8 with combine rule `Poseidon(left_32B ‖ right_32B)`. Root: `#L1(M)`.

The two prepended back-links create the "chain" property: `#L1(M)` cryptographically commits to `#L1(M−1)` and the most recent higher-layer root, allowing layered fallback without separate chain witnesses.

### 3.3 Layer-N recursion for N ≥ 2

Same shape as §3.2, over `BWS` consecutive layer-(N−1) roots of thread 0, with the same two back-link leaves. Root: `#L<N>(M)`.

### 3.4 What the DEX circuit opens

The DEX circuit's Y-side path opens `block_leaf(Y) → #L1(M_Y) → #L2(...) → ... → #L<N>(...)` via one depth-8 Poseidon dense-Merkle path plus a chained `N`-step dense-chain gadget. Terminal root: `finalLayerHistoricalHashRoot`, exposed as instance [1].

---

## 4. The single-thread anchor path (Y-side)

The Y-side of the proof is exactly the existing single-thread DEX flow. For any Y in thread 0:

1. `block_leaf(Y) = Poseidon96(Y.block_id ‖ Y.envelope_hash ‖ Y.tracked_ext_out_messages_root)`.
2. Depth-8 Poseidon dense-Merkle path from `block_leaf(Y)` to `#L1(M_Y)`.
3. Dense chain of ≤ `MAX_CHAIN_LEN = 11` links from `#L1(M_Y)` up to `#L<N>(...) = finalLayerHistoricalHashRoot`.
4. `layerNumber = target_layer + 1` where `target_layer` is the index of the last active link in the dense chain.

Y's `envelope_hash` and `tracked_ext_out_messages_root` are **unconstrained witnesses** — Y is only used to provide a thread-0 anchor. The event content has already been bound on the X-side.

---

## 5. Cross-thread inclusion proof — the L7 walk

### 5.1 The hop primitive

A **hop** is the atomic cross-thread step. One hop proves:

> *Block A's block_id appears in block B's L7 as one of `refs[0..n]` (slots `1..n`).*

That is, **block B references block A cross-thread** via its `refs` list. The hop's "current" block is B (the one whose L7 we open), the "next" block is A (the one we hop to). Because `refs` point to **older** blocks in other threads, repeated hops walk **into the past across threads**. Starting from X (thread t) and following backward `refs` edges, we land on some block Y in thread 0.

Slot 0 of L7 (`parent_block_id`) is **not** used as a hop edge: per §2.3 it is same-thread by producer construction and therefore never crosses a thread boundary. The circuit consequently only handles the `refs` case, and `ref_index` is range-checked to `1..=MAX_PROOF_BLOCK_REFS`.

### 5.2 What one hop constrains

The hop is a **building block, not a standalone snark** — it has no public inputs of its own. Block IDs and L7 material must stay hidden for DEX anonymity (§10.1); they only leave the circuit boundary through the salted endpoints of the enclosing `MultiHopProof` (see §7.3 — the outer snark exposes `salted_start_block_id` and `salted_end_block_id`, computed as position-tagged `salted_id(block_id, bundle_index·H + h)`).

**Shape-witnessing preamble.** The L7 tree on the chain side is variable-depth (§2.3). Since Halo2 constraints are a fixed circuit, we size the inner path array to the worst case (`MAX_PROOF_BLOCK_REFS_DEPTH = 8`) and carry a per-hop witness `refs_tree_depth ∈ [0, 8]` that tells the circuit how many combine steps of the pre-allocated 8-step fold are *live* for this hop. The remaining steps are gated off. This mirrors the pattern already used in `DarkDexCircuit` for the variable-depth ext-out-messages tree opening (`num_ext_out_levels`).

Inputs for a hop B → A (all private witnesses at the hop level):

```
current_block_id   = B.block_id                          (32 bytes)
next_block_id      = A.block_id                          (32 bytes)
B.L7_root                                                (32 bytes; the L7 root being opened against B.block_id)
outer_siblings     = [L6, h45, h0..3, h8..15]            (4 × 32 bytes; depth-4 SHA path from L7 up to block_id — all opaque, incl. h8..15)
refs_tree_depth    (u8; range-checked to [0, MAX_PROOF_BLOCK_REFS_DEPTH = 8])
ref_index          (u32; range-checked to [1, 2^refs_tree_depth); slot 0 excluded per §5.1)
L7_inner_path      ([[u8; 32]; 8]; fixed-length array — entries beyond refs_tree_depth are padding, ignored)
```

An `is_active` flag also lives at the hop level, but only makes sense inside `MultiHopProof` where a fixed-width array of `H` hops must be padded with no-op hops when the true walk length is shorter than `H`. It is a private witness of `MultiHopProof`, not of the hop primitive as such (see §7.6).

Constraints (single hop; the enclosing `MultiHopProof` gates them by its own `is_active[h]`):

1. **SHA-256 depth-4 Merkle path.** Open `B.L7_root` against `B.block_id` via the 4-step path `L7 → h67 → h4..7 → h0..7 → block_id` using witness siblings `[L6, h45, h0..3, h8..15]`. Total **4 SHA-256 compressions**. `h8..15` is an opaque witness — a hop does not bind `L8`, so no derivation from L8 or from the L9..L15 zero-constants is needed here (that only happens in `DexFinalProof`, §7.7).
2. **Tagged leaf hash for A.** Since only `refs` slots (index ≥ 1) are opened, the tag is fixed:
   ```
   tag_bytes = REFERENCED_REF_BLOCK_TAG
   tag_hash  = Poseidon(tag_bytes ‖ A.block_id)
   ```
3. **Depth-witness sanity.**
   - Range-check `refs_tree_depth ∈ [0, 8]` (a lookup or 4-bit decomposition).
   - Range-check `ref_index ∈ [1, 2^refs_tree_depth)` — i.e. the high `(8 - refs_tree_depth)` bits of `ref_index` are zero. This prevents the prover from opening a padding slot at any depth. Realisation: decompose `ref_index` into 8 bits `b0..b7`; unary-decompose `refs_tree_depth` into `d0..d7` where `dk = 1{k < refs_tree_depth}` (monotone-decreasing); assert `bk · (1 − dk) == 0` for `k = 0..7`.
4. **Variable-depth Poseidon dense-Merkle opening.** Verify `B.L7_root == open(tag_hash, ref_index, L7_inner_path, refs_tree_depth)`. Implemented as an unconditional 8-step fold with per-step live-flag:
   ```
   acc_0     = tag_hash
   for k = 0..8:
       live_k   = 1{k < refs_tree_depth}                        // = d_k above
       bit_k    = k-th LE bit of ref_index                       // sibling-order selector
       combined = bit_k ? Poseidon(L7_inner_path[k] ‖ acc_k)
                        : Poseidon(acc_k ‖ L7_inner_path[k])
       acc_{k+1} = live_k ? combined : acc_k                     // pad steps pass through
   assert acc_8 == B.L7_root
   ```
   This matches the canonical `dense_merkle_verify` algorithm of `node/libs/history-proof/src/lib.rs` when `refs_tree_depth == ceil(log2(leaves.len()))` where `leaves.len() = 1 + refs.len()`.

In `MultiHopProof`, hops carrying `is_active[h] == 0` are no-ops: the four constraints above are disabled by selector multiplication and `next_block_id == current_block_id` is enforced instead (same pattern as `DenseChainLink::inactive`). See §7.6.

**Reversibility.** If acki-nacki ever adopts a fixed-shape L7 (unlikely per current signals), the variable-depth circuit continues to accept it: a chain that always emits 256 leaves simply pins `refs_tree_depth = 8` for every hop. No protocol re-negotiation required to tighten later.

### 5.3 What one hop costs

- **4 SHA-256 compressions per hop** — one per level of the depth-4 outer path from L7 up to `block_id`. Dominant cost.
- **8 Poseidon combines** for the L7 inner fold (unconditional under the variable-depth scheme; pad steps are gated but still assigned). At ~2 K cells per Poseidon: ~16 K cells.
- 1 Poseidon for tagged-leaf construction → negligible.
- Depth-witness gadget (unary decomposition of `refs_tree_depth`, 8-bit decomposition of `ref_index`, per-step live-flag mux over `[u8; 32]` cells): a few thousand cells.
- Range checks + `is_active` selectors → ≈ 100 K cells.

At `gosh-sha256-chip`'s measured ≈ 354 K advice cells per SHA compression: **≈ 1.47 M advice cells per hop** (∼+3–4 % over the old fixed-depth-4 model at ~1.42 M). K stays 17; per-snark margin at H = 5 stays ~48 %.

### 5.4 The full L7 walk

A chain of L hops `[hop_0, hop_1, ..., hop_{L-1}]` collectively proves:

```
X  =  B_0  →  B_1  →  B_2  →  ...  →  B_L  =  Y
       ^                                          ^
       thread t (event block)                     thread 0 (anchor)
```

with the gluing constraint `hop_i.next_block_id == hop_{i+1}.current_block_id` for all i.

**Production bound: `L_MAX = 300`** (specified by the node team as the cross-thread walk-length ceiling under the current threading design). The current design point of `L_MAX = 20` used in the phone-budget sizing of §7 is a **temporary** working target for early prototyping; the multi-proof composition of §7 scales `N_BUNDLE = ceil(L_MAX / H)` linearly with `L_MAX`, so raising it to 300 grows the bundle to `N_BUNDLE = 60` snarks (already stress-tested — see `test_bundle_stress_l300.rs`) without changing the per-snark K.

Reference off-chain implementation: `helpers/proof_helper/src/gql_proof.rs`. In-circuit hop logic mirrors `verify_proof_block_ref_proof` (Poseidon inner) + `verify_block_merkle_leaf_proof` (SHA outer, updated to depth 4).

---

## 6. Full protocol binding scheme

Reading the chain from the event back to the anchor:

```
voucher_event(X)  →  event_hash
   ↓ (Merkle path inside X's ext-out-messages tree, depth ≤ 8, SHA-256)
X.tracked_ext_out_messages_root                       (= X.L8)
   ↓ (Merkle path inside X's block-id tree, depth 4, opening L8; three sibling constants + one witness sibling h0..7)
X.block_id
   ↓ (L7 walk: L hops, L ∈ [0, L_MAX])
Y.block_id                                            (Y in thread 0; when t=0, Y = X and L = 0)
   ↓ (Poseidon96)
block_leaf(Y)  =  Poseidon(Y.block_id ‖ Y.envelope_hash ‖ Y.tracked_ext_out_messages_root)
   ↓ (Poseidon dense-Merkle path, depth 8, thread-0 layer-1 batch tree)
#L1(M_Y)
   ↓ (dense chain, ≤ MAX_CHAIN_LEN = 11 layered steps)
#L<N>(...)  =  finalLayerHistoricalHashRoot           (checked by gosh.check_layer_hash)
```

Key properties:

- **Event binding on the X-side is fully algebraic and self-contained.** No cross-thread history witnesses are consumed on the thread-t side. The prover supplies (a) X's ext-out-messages Merkle path from `event_hash` to L8 and (b) X's block-id-tree opening of L8 (four sibling values: three are protocol-fixed constants, one — `h0..7` — is a witness).
- **The L7 walk is a pure L7 traversal.** Each hop opens the outer depth-4 SHA-256 tree of some block B, extracts B.L7, and opens one slot of L7's inner Poseidon dense-Merkle to reveal an edge to some older block A.
- **Y is a thread-0 block.** Y carries its own `history_proofs` (or does not — Y need not be a key block; only that the batch tree containing `block_leaf(Y)` is anchored). The Y-side follows the single-thread flow of §4 verbatim.
- **`Y.envelope_hash` and `Y.tracked_ext_out_messages_root` are unconstrained witnesses.** The event content is already bound on the X-side.
- **Uniformity for `t = 0`.** When X is in thread 0, X = Y, the L7 walk collapses (all hops `is_active = 0`), and `DexFinalProof` performs both the X-side event binding and the Y-side anchor on the same block. Because each salted endpoint absorbs its **bundle-global position** (see §7.3), `salted_X_start` (position 0) and `salted_Y_end` (position `N_BUNDLE·H`) remain distinct even when `X.block_id == Y.block_id`, so the bundle shape is indistinguishable from the multi-thread case.

---

## 7. DEX circuit embodiment — multi-proof composition with on-chain orchestration

### 7.1 Why not one big circuit

The full scheme of §6 cannot fit in a single Halo2 circuit at smartphone-feasible K. The dominant cost is L7-walk SHA-256: each hop = 4 SHA-256 compressions ≈ 1.42 M advice cells. A chain of 20 hops alone is ≈ 28.4 M cells, past the K ≤ 17 phone ceiling. Two ways to split:

- **(A) In-circuit aggregation** (`AggregationCircuit` from snark-verifier-sdk): rejected — see §9 for a detailed comparison.
- **(B) Multi-proof composition with on-chain orchestration** (this design): produce several independent snarks, each covering a small fixed-size batch of hops, submitted together to `RootPN.sol` which checks their continuity on-chain via salted block-id endpoints exposed as public inputs.

### 7.2 Three circuit definitions

| Circuit | Role | K | Snarks per voucher claim |
|---|---|---|---|
| `HopCircuit` | (helper, not submitted directly) — single hop primitive of §5.2. Used as a building block inside `MultiHopProof`. | n/a | 0 |
| `MultiHopProof` | A chain segment of up to `H = 5` hops, `is_active` per hop, exposes salted endpoints. | **17** | `N = ceil(L / H)`, padded to `N_BUNDLE` |
| `DexFinalProof` | Voucher binding + X-side event binding + Y-side thread-0 anchor. Exposes 5 existing voucher fields + 3 new (salted X, salted Y, salt commitment) + 4 DEX-contract-identity pins (X account dApp ID + account ID, each split into two 128-bit LE halves). | **16** | 1 |

### 7.3 Salted endpoints — on-chain continuity

Every snark of a bundle exposes salted endpoints to allow the contract to chain them without seeing real block_ids. Each endpoint absorbs a **bundle-global position tag** in addition to the salt and block_id (BC-005 fix, 2026-09-20):

```
salted_id( block_id , position )
    :=  Poseidon( [ salt_chunk0 , salt_chunk1 , salt_chunk2 , position ] )
```

Where `salt_chunk{0,1,2}` are the three 31-byte chunks of the byte-flat serialization `fr_to_bytes(salt) ‖ block_id_LE` (32 + 32 = 64 bytes ⇒ chunks `[0..31]`, `[31..62]`, `[62..64]` zero-padded to 31 bytes each — the canonical byte-flat Poseidon convention of memory `dex_phase4_byteflat_migration`). `position` is a `u64` embedded directly as an `Fr` field element.

**Position enumeration** (bundle-global). With `H = H_HOPS_PER_PROOF = 5`:

| Endpoint | Position |
|---|---|
| `DexFinal.salted_X_start` | `0` |
| Snark `b`, hop `h`: `salted_start` | `b·H + h` |
| Snark `b`, hop `h`: `salted_end` | `b·H + h + 1` |
| `DexFinal.salted_Y_end` | `N_BUNDLE · H` |

Cross-snark continuity is automatic: snark `b`'s tail (`(b+1)·H`) equals snark `b+1`'s head (`(b+1)·H`) whenever the underlying block_ids agree, exactly as before position tags were introduced.

**Rationale for the position tag (BC-005).** Without it, `salted_X_start = Poseidon(salt, X.block_id)` and `salted_Y_end = Poseidon(salt, Y.block_id)` collapse to equal values whenever `X.block_id == Y.block_id` (uniform single-thread `t = 0` case). Since both are public, an on-chain observer of `inst[5] == inst[6]` could learn same-thread membership without knowing `salt` — a leak of the anonymity set contradicting §10.1. Position tags force distinct outputs at every bundle-global position, closing this leak.

**Why `bundle_index` is private.** The snark's bundle-slot index `b ∈ [0, N_BUNDLE)` is a **private witness** inside `MultiHopProofCircuit` (range-checked, unconditional). Making it public would let observers correlate a snark with its position, negating the purpose. The on-chain continuity check in `RootPN.sol` still enforces the correct sequence: a snark whose `bundle_index` disagrees with its bundle-slot produces salted endpoints at wrong positions that fail to chain to `DexFinal` — caught by `salted_start` / `salted_end` continuity.

`salt` is a voucher-scoped per-user secret:

```
salt  =  Poseidon( [ DOMAIN_TAG_FR , sk_u ] )

DOMAIN_TAG_BYTES = b"acki-nacki:voucher-hop-salt:v1"   (30 bytes, fixed)
DOMAIN_TAG_FR    = bytes_to_fr( DOMAIN_TAG_BYTES  zero-padded to 32 LE bytes )
```

`salt` is a **private witness** in every proof of the bundle. Two vouchers from the same user produce uncorrelated salted ids (different `sk_u`).

> **Canonical convention.** The constants, chunking, and Poseidon shape are enforced by `DexFinalProof` and defined in `dex-halo2-circuit/src/salt.rs` (`compute_salted_block_id_native` and `salted_block_id_poseidon_circuit`). `RootPN.sol` equality-checks `salt_commitment` across all snarks of a bundle; any divergence between this spec and `salt.rs` breaks the orchestrator. **`salt.rs` is the source of truth.**

#### Per-`MultiHopProof` public inputs (3)

```
inst[0] = salted_start_block_id  =  salted_id( B_0.block_id , bundle_index·H       )
inst[1] = salted_end_block_id    =  salted_id( B_H.block_id , bundle_index·H + H   )
inst[2] = salt_commitment        =  Poseidon( [ salt ] )
```

#### Per-`DexFinalProof` public inputs (13)

```
inst[0]  = depositIdentifierHash                                      // voucher nullifier
inst[1]  = finalLayerHistoricalHashRoot                               // checked by gosh.check_layer_hash
inst[2]  = voucherNominalFr
inst[3]  = tokenTypeFr
inst[4]  = ephemeralPubkey
inst[5]  = salted_X_start  =  salted_id( X.block_id , 0 )             // chain head (event block, thread t)
inst[6]  = salted_Y_end    =  salted_id( Y.block_id , N_BUNDLE·H )    // chain tail (anchor, thread 0)
inst[7]  = salt_commitment                                            // bundle binder
inst[8]  = x_account_dapp_id_lo   =  LE( x_account_dapp_id[ 0..16] )  // DEX contract dApp ID, lo 128 bits
inst[9]  = x_account_dapp_id_hi   =  LE( x_account_dapp_id[16..32] )  // DEX contract dApp ID, hi 128 bits
inst[10] = x_account_id_lo        =  LE( x_account_id     [ 0..16] )  // DEX contract account ID, lo 128 bits
inst[11] = x_account_id_hi        =  LE( x_account_id     [16..32] )  // DEX contract account ID, hi 128 bits
inst[12] = x_ext_out_merkle_proof_position                            // BC-011 replay-protection uniquifier
```

Rationale for the four contract-identity pins (inst[8..12]): on TVM every DEX
event, by design, originates from a single fixed `RootPN` contract, so its
dApp ID and account ID are known constants. Exposing them as publics lets the
on-chain verifier compare them slot-for-slot against hard-coded expected
values, closing off any attempt to forge a `DexFinalProof` from an event
emitted by a different account. Each 32-byte address is split into two
128-bit LE halves (lo = bytes `[0..16]`, hi = bytes `[16..32]`); each half is
strictly `< 2^128 < p` so no `V < p` canonicality gadget is required.

Rationale for `inst[12] = x_ext_out_merkle_proof_position` (BC-011): the L8
`tracked_ext_out_messages` tree slot index of the withdrawal event within the
X block. Two legitimately-distinct events in the same block (same `sk_u`,
same `voucher_nominal`, same `token_type`, hence identical `inst[0..12)`)
occupy distinct L8 slots. Without `inst[12]` the on-chain nullifier keyed on
the instance vector cannot separate a real second event from a replay of the
first — both fold to the same `depositIdentifierHash`. Exposing the position
uniquifies the DexFinal instance vector per-event, while still hiding the
event content (only the tree slot leaks, not the ext-out message hash).

**Soundness of `inst[12]`.** A naïve exposure would let a malicious prover
publish `position = X` while the internal L8 dense-Merkle walker uses
direction bits corresponding to slot `Y` — the upstream
`dense_merkle_root_circuit_padded` accepts free `assert_bit`-only direction
witnesses. `DarkDexCircuit` therefore bit-decomposes the position via
`gate.num_to_bits(MAX_EVENTS_TREE_DEPTH)`, forces `pos_bits[j] == 0` for
`j >= num_active_levels`, and feeds the bound bits into the local
`dense_merkle_root_padded_bound` walker (see
`dex-halo2-circuit/src/dense_merkle_bound.rs`; same fix pattern as BC-004 at
L7 in `multi_hop_proof.rs`).

Source of truth: `dex-halo2-circuit/src/dark_dex_circuit.rs` (`DarkDexCircuit`
type-level doc) and `dex-halo2-circuit/src/bundle_verifier.rs`
(`DEX_FINAL_LEN = 13`, `dexfinal_offset::*`).

### 7.4 RootPN orchestration

Ordering rationale: cheap consistency checks over public inputs first (fail-fast on any structural break — replay, salt mismatch, chain break, anchor mismatch), and only then the expensive Halo2 KZG verifications.

```solidity
function claimVoucher(
    DexFinalProofData calldata dexProof,
    MultiHopProofData[] calldata hopProofs,
    uint8 layerNumber
) external {
    require(!claimed[dexProof.publicInputs[0]], ERR_ALREADY_CLAIMED);
    require(hopProofs.length >= 1, ERR_BUNDLE_TOO_SHORT);

    // === Phase 1: cheap public-input consistency ===============================

    // 1a. salt binding: every proof of the bundle commits to the same salt
    bytes32 saltCommit = dexProof.publicInputs[7];
    for (uint i = 0; i < hopProofs.length; ++i) {
        require(hopProofs[i].publicInputs[2] == saltCommit, ERR_SALT_MISMATCH);
    }

    // 1b. chain continuity: head → hops → tail, all glued via salted endpoints
    require(hopProofs[0].publicInputs[0] == dexProof.publicInputs[5], ERR_X_HEAD_MISMATCH);
    for (uint i = 0; i + 1 < hopProofs.length; ++i) {
        require(
            hopProofs[i].publicInputs[1] == hopProofs[i+1].publicInputs[0],
            ERR_CHAIN_BREAK
        );
    }
    require(
        hopProofs[hopProofs.length - 1].publicInputs[1] == dexProof.publicInputs[6],
        ERR_Y_TAIL_MISMATCH
    );

    // 1c. anchor: thread-0 history-data check (still cheap — a single VM callback)
    require(
        gosh.check_layer_hash(dexProof.publicInputs[1], layerNumber),
        ERR_INVALID_HISTORY_PROOF
    );

    // 1d. DEX contract identity: the event MUST have been emitted by this
    //     RootPN. Compare against the pre-committed dApp ID / account ID
    //     constants (each 32-byte address is split into two 128-bit LE halves).
    require(
        dexProof.publicInputs[8]  == EXPECTED_X_ACCOUNT_DAPP_ID_LO &&
        dexProof.publicInputs[9]  == EXPECTED_X_ACCOUNT_DAPP_ID_HI &&
        dexProof.publicInputs[10] == EXPECTED_X_ACCOUNT_ID_LO      &&
        dexProof.publicInputs[11] == EXPECTED_X_ACCOUNT_ID_HI,
        ERR_WRONG_DEX_CONTRACT
    );

    // === Phase 2: expensive Halo2 KZG verifications ============================
    // Only reached after all public inputs are structurally consistent.

    require(verify_dex_final(dexProof), ERR_INVALID_DEX_PROOF);
    for (uint i = 0; i < hopProofs.length; ++i) {
        require(verify_multi_hop(hopProofs[i]), ERR_INVALID_HOP_PROOF);
    }

    // === Phase 3: settle =======================================================
    _mintAndSendVoucher(dexProof);
    claimed[dexProof.publicInputs[0]] = true;
}
```

Phase 1 is cheap (field comparisons + one VM callback); phase 2 is the only heavy work (N+1 Halo2 KZG verifications).

### 7.5 Uniformity: single-thread and multi-thread proofs look identical

Every voucher claim submits exactly `N_BUNDLE` `MultiHopProof` snarks regardless of true chain length. `N_BUNDLE = 4`, supporting chains up to `4 × H = 20` real hops.

- **t = 0** (X in thread 0): true chain length L = 0. All 4 `MultiHopProof`s are submitted with `is_active = 0` everywhere; each snark's `salted_start_block_id` and `salted_end_block_id` sit at distinct bundle-global positions (`b·H` and `b·H+H`), so they are two distinct pseudo-random field elements — indistinguishable from an active snark by shape. Cross-snark continuity still holds (snark `b`'s end equals snark `b+1`'s start). `DexFinalProof` also has `salted_X_start != salted_Y_end` (positions `0` vs `N_BUNDLE·H`) even though X = Y.
- **t ≠ 0, L ≤ 5**: 1 `MultiHopProof` has up to 5 active hops; the remaining 3 are fully inactive.
- **L up to 20**: up to 4 partially- or fully-active proofs.

The verifier cannot tell from public inputs whether any individual `MultiHopProof` is active or inactive — every hop, in either mode, produces a `salted_start != salted_end` pair (different positions), and each endpoint is a pseudo-random-looking Poseidon output under the `salt` random-oracle model.

### 7.6 `MultiHopProof` circuit detail

`MultiHopProof` is a Halo2 circuit at K = 17. It contains `H = 5` instances of the hop gadget of §5.2, chained internally:

```
witnesses:
  salt                                              (1 Fr)
  voucher_secret_seed                               (1 Fr; sk_u = voucher_secret_seed, for salt derivation)
  bundle_index ∈ [0, N_BUNDLE)                      (u32; private; range-checked)
  for h in 0..H:
    is_active[h]                                    (bool)
    hop_current_block_id[h], hop_next_block_id[h]   (32 bytes each)
    B_h.L0..B_h.L7_root, B_h.L8                     (9 × 32 bytes; full leaf set needed to reconstruct B_h.block_id)
    ref_index[h], ref_count[h]
    L7_inner_path[h]                                (≤ 8 × 32 bytes)

constraints:
  1. salt_commitment_check:
        salt_commitment_pub == Poseidon([salt])
        salt                == Poseidon([DOMAIN_TAG_FR, voucher_secret_seed])
  2. salted_endpoint_check (position-tagged, BC-005; see §7.3):
        position_base := bundle_index * H
        salted_start_block_id_pub ==
            salted_id(hop_current_block_id[0],   position_base)
        salted_end_block_id_pub   ==
            salted_id(hop_next_block_id[H-1],    position_base + H)
        Additionally, for each h in 0..H the per-hop salted endpoints
        salted_id(hop_current_block_id[h], position_base + h) and
        salted_id(hop_next_block_id[h],    position_base + h + 1)
        are computed unconditionally (used for internal-glue check 4).
  3. for each hop h in 0..H:
        when is_active[h]: full hop constraints of §5.2 (depth-4 outer opening)
        when !is_active[h]: byte-equality
            ref_block_id_bytes[h] == block_id_bytes[h]
            (i.e. the reference at slot `ref_index[h]` equals the hop's
            current block_id — under position tags, salted_start !=
            salted_end even for inactive hops, so the pre-BC-005
            propagation rule `hop_next_block_id[h] == hop_current_block_id[h]`
            no longer suffices; byte-equality on the ref combined with the
            padding convention `pad_bid = block_ids[k_hops]` still forces
            the inactive tail to propagate a single block_id).
  4. for each h in 0..H-1:
        hop_current_block_id[h+1] == hop_next_block_id[h]        (internal chain glue)
```

Cell budget at H = 5: 20 SHA-256 compressions × 354 K ≈ **7.1 M advice cells**. K = 17 with ~110 advice columns provides ≈ 14 M cells → ~49 % margin. Estimated phone proving time: 3–5 minutes per snark (margin now leaves headroom to grow H before the K = 17 ceiling bites).

### 7.7 `DexFinalProof` circuit detail

`DexFinalProof` is the extended voucher circuit at K = 16.

**Two disjoint cryptographic subcircuits, glued by salt + voucher payload.** Reading constraints 1–5 below:

- **X-side** (constraints 1–4): event BOC → `X.block_id`. Raw BOC preimage bytes witnessed; SHA-256 in-circuit reconstructs `event_hash` (2 SHA), field extraction by byte-slice, Poseidon96 forms `ext_msg_leaf`, Poseidon dense-Merkle to L8, then depth-4 SHA opening (4 SHA) to `X.block_id`.
- **Y-side** (constraint 5): `Y.block_id` → `finalLayerHistoricalHashRoot`. Poseidon-based (Poseidon96 `block_leaf` + depth-8 Poseidon dense-Merkle to `#L1(M_Y)` + ≤ 11 dense-chain links).

The two sides share no block-side witness when `t ≠ 0`. When `t = 0` (X = Y), the same `block_id` value feeds both sides — but the sides still perform distinct work: X-side binds *event to block*, Y-side binds *block to anchor*. **No crypto is repeated.** What matters for uniformity (§7.5) is that the *shape* is identical in both cases: an observer cannot tell from the proof whether X = Y or X ≠ Y.

Witnesses and constraints:

```
witnesses:
  salt                                              (1 Fr)
  voucher_secret_seed                               (1 Fr)

  # X-side (event block; thread t; may equal Y when t=0)
  #
  # The event BOC is passed in as raw preimage bytes for its two cells
  # (root event cell + child voucher-payload cell). Prover-side
  # `parse_voucher_boc` only flattens the BOC; every hash on the X-side
  # is recomputed in-circuit.
  x_root_cell_repr_data                             (variable length; SHA-256 preimage of root event cell)
  x_child_cell_repr_data                            (variable length; SHA-256 preimage of child voucher-payload cell)
  x_child_hash_offset_in_root                       (usize; structural constant per BOC layout)
  x_account_dapp_id, x_account_id                   (32 bytes each; ext-out-message endpoint identity)
  X.block_id                                        (32 bytes)
  X.L8_tracked_ext_out_messages_root                (32 bytes)
  X_block_id_h07_sibling                            (32 bytes)          // the one live sibling of L8
  X_event_leaf_index                                (u32, range-checked)
  X_ext_out_merkle_path                             (≤ EXT_OUT_DEPTH_MAX × 32 bytes; Poseidon siblings)

  # Y-side (anchor block; thread 0; equals X when t=0)
  Y.block_id                                        (32 bytes)
  Y.envelope_hash                                   (32 bytes; unconstrained content)
  Y.tracked_ext_out_messages_root                   (32 bytes; unconstrained content)
  Y_block_leaf_path                                 (depth-8 Poseidon-dense siblings + leaf index)
  Y_dense_chain_links                               (≤ MAX_CHAIN_LEN = 11)

  # Voucher payload (unchanged from single-thread DEX)
  sk_u_commit, voucher_nominal, token_type, deposit_identifier_hash, ephemeral_pubkey, ...

constraints:
  1. X.block_id reconstruction (depth-4 SHA-256 tree, opening L8; 4 SHA compressions):
        h89     = SHA(L8   ‖ 0×32)                                      // sibling: L9 = 0×32
        h8_11   = SHA(h89  ‖ H10_11_CONST)                              // sibling: h10..11 constant
        h8_15   = SHA(h8_11 ‖ H12_15_CONST)                             // sibling: h12..15 constant
        X.block_id == SHA(X_block_id_h07_sibling ‖ h8_15)               // sibling: h0..7 witness

  2. BOC hash reconstruction + parent-child link (2 SHA compressions):
        event_hash   =  SHA(x_root_cell_repr_data)                       // in-circuit
        child_hash   =  SHA(x_child_cell_repr_data)                      // in-circuit
        x_root_cell_repr_data[offset .. offset+32]  ==  child_hash        // root cell embeds child's repr_hash

  3. BOC descriptor sanity + voucher-field extraction (byte-sliced from x_child_cell_repr_data):
        d1 bits of root cell  ⇒  refs_count == 1
        d1 bits of child cell ⇒  refs_count == 0
        sk_u_commit           =  LE(x_child_cell_repr_data[6..38])
        voucher_nominal       =  BE(x_child_cell_repr_data[38..70])
        token_type            =  BE(x_child_cell_repr_data[70..74])
        (sk_u_commit is also re-derived from sk_u via Poseidon and constrained equal
        — inherited unchanged from single-thread DarkDexCircuit.)

  4. Event → ext_out_tree leaf, then Poseidon-Merkle open to L8:
        ext_msg_leaf =  Poseidon96( x_account_dapp_id ‖ x_account_id ‖ event_hash )    // byte-flat, §7.3
        ext_out_tree_open(ext_msg_leaf, X_event_leaf_index, X_ext_out_merkle_path)
            == X.L8_tracked_ext_out_messages_root                                       // Poseidon dense-Merkle

  5. Y-side anchor (existing single-thread flow):
        block_leaf(Y)  =  Poseidon96( Y.block_id ‖ Y.envelope_hash ‖ Y.tracked_ext_out_messages_root )
        block_leaf(Y) -- depth-8 Poseidon dense-Merkle path --> #L1(M_Y)
        #L1(M_Y)      -- dense chain (≤ 11 links)          --> finalLayerHistoricalHashRoot

  6. Salt + salted endpoints (position-tagged, BC-005; see §7.3):
        salt                   == Poseidon([DOMAIN_TAG_FR, voucher_secret_seed])
        salt_commitment_pub    == Poseidon([salt])                                // instance [7]
        salted_X_start_pub     == salted_id(X.block_id, 0)                        // instance [5]
        salted_Y_end_pub       == salted_id(Y.block_id, N_BUNDLE * H)             // instance [6]

  7. Public voucher fields at instances [0..4] (unchanged from single-thread DEX).

  8. DEX contract identity pins at instances [8..12]:
        x_account_dapp_id_lo_pub  == LE(x_account_dapp_id[ 0..16])       // instance [8]
        x_account_dapp_id_hi_pub  == LE(x_account_dapp_id[16..32])       // instance [9]
        x_account_id_lo_pub       == LE(x_account_id     [ 0..16])       // instance [10]
        x_account_id_hi_pub       == LE(x_account_id     [16..32])       // instance [11]
        Each half is < 2^128 < p, so no canonicality gadget is needed;
        the on-chain verifier compares each half against a hard-coded
        expected value (see §7.4).

  8. Uniformity for t=0: the prover passes X = Y as identical witness bytes. All X-side and Y-side gates hold simultaneously; the bundle's MultiHopProofs are all inactive. Under position tags (§7.3), salted_X_start (position 0) and salted_Y_end (position N_BUNDLE·H) remain distinct even though X.block_id == Y.block_id — the shape of the DexFinal publics is indistinguishable from the multi-thread case.
```

Cell budget: X-side is **2 SHA (BOC hash reconstruction) + 4 SHA (L8 depth-4 opening) = 6 SHA compressions**, plus the ext-out Poseidon dense-Merkle walk (up to `EXT_OUT_DEPTH_MAX` Poseidon nodes, ≤ 1 M cells) and byte-slice field extraction (negligible). Adds ≈ +2.1 M SHA cells + ≈ 1 M Poseidon cells over the existing K = 14 single-thread DEX baseline (≈ 1.7 M cells). Total ≈ 5 M cells. K = 16 provides ≈ 7 M cells with 110 advice columns → ~30 % margin. Estimated phone proving time: 2–3 minutes.

### 7.8 Bundle size and proving time on phone

| True chain length L | Active `MultiHopProof`s | Inactive `MultiHopProof`s | Total snarks | Phone proving time (estim.) |
|---|---|---|---|---|
| 0 (event in thread 0) | 0 | 4 | 5 | ≈ 15–20 min |
| 1–5 | 1 | 3 | 5 | ≈ 15–20 min |
| 6–10 | 2 | 2 | 5 | ≈ 15–20 min |
| 11–15 | 3 | 1 | 5 | ≈ 15–20 min |
| 16–20 | 4 | 0 | 5 | ≈ 15–20 min |

Wall time is constant in L — every claim submits the same 5 snarks (1 `DexFinalProof` + 4 `MultiHopProof`s). Required for uniformity (§7.5). If worst-case anonymity is not needed, `N_BUNDLE` can be made dynamic at the cost of a small chain-length leak (§10).

### 7.9 Verifying-key set

Two distinct VKs: `VK_DexFinal`, `VK_MultiHop`. No aggregation, no universal VK, no recursion.

---

## 8. Synthetic test data generator

A binary in `dexdo-halo2-kit/dex-halo2-circuit/examples/` produces fixtures for every supported configuration:

| Case | t | L (real hops) | Active `MultiHopProof`s | Notes |
|------|---|---|---|---|
| S0 | 0 | 0 | 0 | Pure single-thread; X = Y; all hop proofs inactive |
| S1 | t ≠ 0 | 1 | 1 (1 active hop) | Shortest cross-thread |
| S5 | t ≠ 0 | 5 | 1 (5 active hops) | Single fully-active hop proof |
| S6 | t ≠ 0 | 6 | 2 (5+1 active hops) | Boundary into 2-proof regime |
| S15 | t ≠ 0 | 15 | 3 (5+5+5) | Mid-range |
| S20 | t ≠ 0 | 20 | 4 (5+5+5+5) | Worst case for `L_MAX = 20` |

Each fixture emits:
1. Witnesses + native proof for `DexFinalProof`.
2. Witnesses + native proofs for all 4 `MultiHopProof`s.
3. Native bundle verification (replays the RootPN orchestration in Rust).

All fixtures use one fixed `VK_DexFinal` and one fixed `VK_MultiHop` — the cross-case uniformity guarantee.

---

## 9. Why not `AggregationCircuit`

Rejection rationale summary. Full analysis at `docs/aggregation_analysis.md` (if elaboration needed):

1. **Smartphone budget.** In-circuit KZG verification is ≈ 0.5–1.5 M cells per snark verified; aggregating 20 hop snarks lands at K ≈ 21 (~4 GB SRS), with the outer DEX at K ≈ 23. Fundamentally outside the phone budget (K ≤ 17 ceiling per §9.1 below).
2. **SRS + toolchain cost.** K ≥ 21 requires 4–16 GB SRS, multi-GB working memory, and pulls in snark-verifier-sdk + axiom-eth. Multi-proof reuses the existing halo2-base / halo2-ecc stack unchanged.
3. **Parallelism.** Aggregator proving is serial-dominant; multi-proof's 4 `MultiHopProof`s can prove concurrently.
4. **EVM verification cost.** Aggregation: 1 verification ≈ 700–800 K gas. Multi-proof: 5 verifications ≈ 3.5–4 M gas. ~5× overhead, judged acceptable for the smartphone constraint.
5. **Anonymity equivalence.** Salted endpoints of §7.3 compensate for the lack of an in-circuit verifier; anonymity strength is comparable. Bundle-size uniformity is preserved via fixed `N_BUNDLE = 4` (§7.5).
6. **Operational simplicity.** Multi-proof: 3 circuit definitions, 2 VKs, plain Solidity continuity. Aggregation: recursive composition, universal-VK hash chaining, in-circuit transcript matching, KZG accumulator unpacking.
7. **Scaling.** Multi-proof scales linearly in `N_BUNDLE` on phone. Aggregation scales exponentially in SRS size for larger K.

### 9.1 Smartphone K ceiling

We estimate the practical phone ceiling at **K ≤ 17** (≈ 250 MB SRS, 1–3 GB working set, a few minutes proving). All circuits in this design fit under that ceiling: `MultiHopProof` at K=17, `DexFinalProof` at K=16.

---

## 10. Anonymity analysis

### 10.1 What is hidden

- **`X.block_id`, `X.height`, X's thread `t`** — fully hidden behind the voucher binding and the salted endpoints. (Requires the BC-005 position-tag fix of §7.3; without it, `t = 0` would be publicly distinguishable via `salted_X_start == salted_Y_end`.)
- **All intermediate block_ids `B_1 .. B_{L-1}`** — private witnesses inside `MultiHopProof`s.
- **`Y.block_id`** — only `salted_Y_end = salted_id(Y.block_id, N_BUNDLE·H)` is exposed. Pseudo-random without `salt`.
- **`bundle_index`** — the private per-snark witness `b ∈ [0, N_BUNDLE)` that drives the position tag. Observers see only the salted endpoints, which are pseudo-random.
- **`Y.envelope_hash`, `Y.tracked_ext_out_messages_root`** — unconstrained witnesses inside `DexFinalProof`.
- **True chain length L** — hidden by fixed `N_BUNDLE = 4`.
- **The salt itself** — private witness in every proof of the bundle.
- **X.tracked_ext_out_messages_root** — witness; only its opening to L8 of X.block_id is proved, and X.block_id is itself hidden.

### 10.2 What leaks

- **Bundle existence** — 5 proofs submitted together with one `claimVoucher` call; unavoidable and inherent to the voucher claim being public.
- **Bundle size = 5** — by design, identical for every claim.
- **A `voucher_secret_seed` is used** — already voucher-private in the single-thread case; no new leakage.

### 10.3 What is *not* a leak

- **Cross-voucher linkability** — each voucher has its own `voucher_secret_seed`, hence its own `salt` and its own `salted_id(·, ·)` outputs. Two vouchers from the same physical user are not linkable via salted endpoints under the Poseidon random-oracle model.
- **`salted_X_start == salted_Y_end`** (the pre-BC-005 t=0 tell). Under position tags (§7.3), `salted_X_start` sits at position 0 and `salted_Y_end` at position `N_BUNDLE·H`, so the two are distinct Poseidon outputs even when `X.block_id == Y.block_id`. On-chain observers can no longer read same-thread membership off the DexFinal publics.
- **Inactive hops** — every hop, active or padded, produces a `salted_start != salted_end` pair (different positions). Whether a specific `MultiHopProof` is active or padded is not distinguishable from public inputs without knowing `salt`.

### 10.4 Threats

- **Salt re-use across vouchers** — would let an adversary correlate two bundles. Blocked by the voucher-secret-seed already being fresh per voucher, and by `DOMAIN_TAG_FR` domain separation. Wallet-software discipline required.
- **Relayer / wallet metadata side channels** — the phone submits all 5 snarks. If a relayer broadcasts the transaction, the relayer sees the bundle but not the salt. Standard relayer-anonymity considerations apply.

### 10.5 Hash strength

`salted_id(block_id, position) = Poseidon([salt_chunk0, salt_chunk1, salt_chunk2, position])` (see §7.3) — 4-input Poseidon over BN254 scalar field with ~127-bit collision security and pseudo-randomness under the random-oracle model. Sufficient for salting; the added position input does not weaken the primitive.

---

## 11. Locked parameters and open questions

### 11.1 Locked

| Parameter | Value | Source / rationale |
|---|---|---|
| BWS | 128 | `HISTORY_PROOF_WINDOW_SIZE` (canonical) |
| Layer-1 batch tree depth (thread 0) | 8 (130 leaves padded to 256) | `HistoryBlockData::calculate_root_hash` |
| Block-id tree depth | **4** (16 leaves) | This spec |
| L9..L15 padding value | `[0u8; 32]` | This spec (Open Q §11.2.4) |
| L8 semantics | `tracked_ext_out_messages_root` (32 B, SHA-256 dense-Merkle root) | This spec |
| Ext-out-messages tree combine | SHA-256(left ‖ right), depth ≤ 8, `[0u8;32]` pad, raw-hash leaf | Assumed (Open Q §11.2.1–3) |
| L7 outer opening depth (per hop) | **4** SHA-256 sibling combines (`h8..15` is opaque witness in hops — no L8 re-derivation) ⇒ **4 SHA compressions / hop** | §5.3 |
| `MAX_PROOF_BLOCK_REFS` (L7 inner depth bound) | **256** leaves padded, depth 8 | Protocol cap |
| `H` (hops per `MultiHopProof`) | **5** | Phone budget at K=17 |
| `N_BUNDLE` (fixed proofs per claim) | **4** + 1 `DexFinalProof` = 5 (prototyping); **60** + 1 = 61 for production (`L_MAX = 300`) | Anonymity uniformity |
| `L_MAX` (max real chain length) | **20** (prototyping) → **300** (production, per node team) | Multi-proof design target |
| `MAX_CHAIN_LEN` (thread-0 dense chain) | **11** | `gosh-dense-balanced-tree` |
| `MultiHopProof` K | **17** | Cell-budget sizing (~24 % margin) |
| `DexFinalProof` K | **16** | Cell-budget sizing (~30 % margin — 6 SHA + Poseidon ext-out walk + Y-side, see §7.7) |
| `DOMAIN_TAG_BYTES` | `b"acki-nacki:voucher-hop-salt:v1"` (30 B) | `dex-halo2-circuit/src/salt.rs` |
| SHA-256 chip | `gosh-sha256-chip` | Existing dependency |
| Phone K ceiling | ≤ 17 | §9.1 |
| On-chain verifier | per-snark Halo2 KZG | No aggregation |
| Public inputs (`DexFinalProof`, 12) | see §7.3 | Preserves 5-field prefix; adds salted X / Y / commitment; pins DEX contract identity (dApp ID + account ID, each split into two 128-bit LE halves) |
| Public inputs (`MultiHopProof`, 3) | see §7.3 | New artifact |

### 11.2 Open questions

Must be answered with the team before circuit-side implementation begins.

1. ~~**Ext-out-messages tree combine rule.**~~ **Resolved:** chain uses **Poseidon** dense-Merkle (`node/libs/history-proof/src/lib.rs:174–193`, `compute_ext_out_messages_root`). `DarkDexCircuit`'s ext-out walk already matches. See §2.4.
2. ~~**Ext-out-messages tree depth bound.**~~ **Resolved:** chain-side unbounded (`BTreeMap`), circuit imposes `EXT_OUT_DEPTH_MAX = 8`. See §2.4.
3. ~~**Ext-out-messages leaf format.**~~ **Resolved:** `Poseidon(account_dapp_id ‖ account_id ‖ ext_message_hash)`, 96-byte preimage, no tag (`node/libs/history-proof/src/lib.rs:162–172`). See §2.4.
4. ~~**L9..L15 padding value.**~~ **Resolved:** chain uses literal `[0u8; 32]` (`node/src/types/ackinacki_block/mod.rs:556`). Circuit constants in §2.1 are correct.
5. **Salted-endpoint direction.** `inst[5] = salted_X_start`, `inst[6] = salted_Y_end` (chain head → tail). Confirm the on-chain contract expects this order and not the reverse.
6. **Real chain-length distribution on the testnet.** Production ceiling `L_MAX = 300` is set by the node team; measured p50/p99 distributions on real deployment are still open — informs how conservatively to size `N_BUNDLE` vs. batch dispatch cadence.
7. **L7 walk direction in practice.** Spec assumes hops walk **into the past** (parent + refs both point backward). Confirm this matches canonical L7-walk direction in the multi-thread design.
8. **Single-thread bundle shape.** Spec mandates that single-thread (t = 0) claims still submit 5 snarks for anonymity uniformity — a ~5× per-claim gas increase over today's single-thread DEX. Confirm this trade-off is acceptable.
9. **Salt derivation domain.** `salt = Poseidon(DOMAIN_TAG_FR, voucher_secret_seed)`. Confirm `voucher_secret_seed` is collision-resistant and not reused for any non-voucher purpose in existing wallet code.
10. **Re-merge of history-proof code into mainline.** Circuit work depends on helpers (`compute_block_leaf_hash`, `compute_referenced_blocks_root`, `HistoryBlockData::calculate_root_hash`, `proof_block_refs_root`, `proof_block_ref_proof`, and the widened `block_merkle_leaves()` producing the depth-4 tree). Confirm timeline.


---

## 12. Circuit implementation status

All in-circuit modules of `dex-halo2-circuit` are **DONE** as of 2026-09-20 (variable-depth L7 landed in commit `22bb07b`). §12.1 records the K / column / proof-size envelope; §12.2 lists the remaining off-tree work.

Open Question §11.2.1 (SHA-vs-Poseidon for the ext-out-messages tree) landed as **Poseidon** (see §2.4). No follow-on blocks remain from the original Open-Q list except §11.2.6 (phone-side wall-time confirmation for `N_BUNDLE = 60`).

### 12.1 K-budget & performance envelope — **PARTIALLY DONE**

- **K = 16** for `DarkDexCircuit`; **K = 17** for `MultiHopProofCircuit`. Both leave healthy row headroom on real-KZG stress runs.
- **Column footprint after variable-depth L7**: `num_advice_per_phase = 200`, `num_lookup_advice_per_phase = 14` (measured — up from 110 / 8 for the old fixed depth-4 fold; the padded gated fold performs ~2× the SHA-work per hop). Proof size, VK layout, and public-input shapes are unchanged.
- **Real-KZG stress runs at L = 50 / 100 / 300** exist as `#[ignore]` tests (`tests/test_bundle_stress_l{50,100,300}.rs`); linear-in-`L_MAX` scaling confirmed empirically at `N_BUNDLE = 60`.
- **§11.1 (K, H, N_BUNDLE) triple** locked at **(17, 5, 60)** for production; prototyping still uses `N_BUNDLE = 4` (`L_MAX = 20`).
- **Follow-up.** Re-run the L=300 stress fixture after any future circuit change to confirm the per-snark cell count still fits comfortably at K = 17.

### 12.2 Off-tree work — **OPEN**

- **`RootPN.sol` orchestration.** Register `VK_DexFinal`, `VK_MultiHop`; implement §7.4 phase order (public-input consistency → KZG verification → settle). Solidity test harness against native-Rust bundle fixtures.
- **Phone-side prover integration.** WASM / native build of all snarks; parallel proving where possible. Given `L_MAX = 300` in production and `N_BUNDLE = 60`, quantify phone-side worst-case wall time before locking the prod dispatch policy (§11.2.6).

### 12.3 Known P2 items — **DEFERRED**

- **BC-010 — upstream 4-bit hardcode in `gosh-dense-balanced-tree::dense_merkle_root_circuit_padded`.** The `is_less_than(j_const, num_active_levels, 4)` call inside the padded walker hard-codes a 4-bit range for the depth witness. Values in `[8, 16)` collapse to "all levels active" via that comparison, so there is no cheating window at the current `MAX_PROOF_BLOCK_REFS_DEPTH = 8`, but the hardcode couples the upstream helper to an assumption of the consumer. A cross-repo fix in `gosh-halo2-crypto-lib` should either parameterise the bit-width or accept it as an argument. **Not landed in this session.** Track separately when the upstream is next touched. All other P2 items in the bug batch (BC-002/003/005/006/008/004/009) are fixed on `feature/multithreading`; BC-007 (L9..L15 padding value) is verified against the acki-nacki source (see §11.2.4).