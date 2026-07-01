# Multi-Thread Cryptographic Scheme — DEX Circuit

Target embodiment: `dexdo-halo2-kit/dex-halo2-circuit` (DEX voucher circuit).

This document describes the cryptographic mechanism for proving, in zero knowledge, that a voucher-generation event in **any thread t** of Acki Nacki can be anchored, via cross-thread chaining when `t ≠ 0`, against a layer-N batch hash retained in thread 0's window of `GlobalHistoricalData`, and how the DEX circuit embodies that mechanism.

The canonical branch for this design is `poseidon_dex` on `acki-nacki`. All field names and helpers below refer to that branch.

## 0. Terminology

| Term | Meaning |
|------|---------|
| **BWS** | Batch Window Size = **128**. (`HISTORY_PROOF_WINDOW_SIZE` in `node/libs/history-proof/src/lib.rs`.) |
| **Batch M** (within thread 0) | The contiguous range of blocks at heights `[M·BWS, (M+1)·BWS − 1]` within thread 0. |
| **`#L<N>(M)`** | Layer-N batch hash for batch M of thread 0. Layer-1 is built over the blocks of batch M; layer-(N+1) is built over `BWS` consecutive layer-N hashes. |
| **X** | The **event block** — the block, in some thread t (t may or may not be 0), in which the voucher-generation event was emitted. Hidden witness. |
| **Y** | The **anchor block** — a block **in thread 0** that lies at the tail of a chain of cross-thread reference edges emanating from X. When t = 0, Y = X (uniformity case). Hidden witness. |
| **X-side / Y-side** | The portions of the DEX proof concerned with block X (event binding, in thread t) and block Y (thread-0 anchor) respectively. When t ≠ 0 they are separate; when t = 0 they collapse onto the same block. |
| **`event_hash`** | 32-byte hash of the voucher event message. Included as a leaf of X's `tracked_ext_out_messages` Merkle tree. |
| **Block leaf** (thread 0, layer-1) | `block_leaf = Poseidon96(block_id ‖ envelope_hash ‖ tracked_ext_out_messages_root)`. Feeds the per-batch layer-1 Poseidon dense-Merkle tree in thread 0. |
| **GlobalHistoricalData** | Node-side per-thread map (`HashMap<ThreadIdentifier, HistoryLayerData>`) of layer-N window hashes queried by the contract via `gosh.check_layer_hash(root, N)`. Under this protocol only thread 0's entry is populated. |
| **`finalLayerHistoricalHashRoot`** | Instance 1 of the DEX proof; the layer-N batch hash the prover anchors against. Must belong to thread 0's window. |
| **`layerNumber`** | Contract argument naming the layer N that `finalLayerHistoricalHashRoot` belongs to. |
| **L** | True chain length in hops from X to Y. `L = 0` when t = 0 (X = Y); `L > 0` in the multi-thread case. |
| **`L_MAX`** | Circuit-side upper bound on L. **Production target = 300** (specified by the node team as the cross-thread walk-length ceiling under the current threading design). Current prototyping point is **20**; `N_BUNDLE = ceil(L_MAX / H)` scales linearly — moving to prod raises `N_BUNDLE` to 60, no change to per-snark K. |
| **`H`** | Hops packed per `MultiHopProof` snark. Locked at **5**. |
| **`N_BUNDLE`** | Number of `MultiHopProof` snarks per bundle. Currently **4** (prototyping `L_MAX = 20`); production **60** (`L_MAX = 300`). May be made dynamic per §7.5 dispatch. |

**Poseidon input convention (reminder).** Poseidon here operates on BN254 Fr (`|p| ≈ 254 bits`). A byte stream is packed into Fr in **31-byte chunks** (little-endian, high byte implicitly zero) so every chunk is unambiguously `< p` and no modular reduction is needed. An N-byte input consumes `⌈N/31⌉` Fr elements. This applies uniformly to every `Poseidon(...)` in this spec — the tagged L7 leaves, the Poseidon96 block-leaf, dense-Merkle combines, and the salted-endpoint hashes.

---

## 1. Anchor model

### 1.1 Where events happen vs. where they anchor

The voucher-generation event may be emitted in **any** thread of Acki Nacki. The event's block X is therefore of arbitrary thread `t`.

The **anchor**, in contrast, must land in **thread 0**. Under this protocol only thread 0 produces layer trees: `history_proofs` are populated exclusively on thread-0 key blocks, and `GlobalHistoricalData[thread 0]` is the sole populated per-thread window. No other thread has a layer-N batch tree the contract can query. It follows that the anchor block Y must itself be a thread-0 block.

When `t = 0`, event and anchor coincide (`X = Y`) and no cross-thread bridging is needed. This is the "single-thread" case. 

When `t ≠ 0`, the proof must chain the event's block X, via cross-thread L7 reference edges (§5), to some thread-0 block Y that transitively references X. Only Y — a thread-0 block — can be anchored to `GlobalHistoricalData[thread 0]`.

### 1.2 The contract-side check

`RootPN.sol` (`acki-nacki/contracts/dex/RootPN.sol`) consumes the proof together with `(finalLayerHistoricalHashRoot, layerNumber)` and gates verification by:

```solidity
require(
    gosh.check_layer_hash(finalLayerHistoricalHashRoot, layerNumber),
    ERR_INVALID_HISTORY_PROOF
);
```

`finalLayerHistoricalHashRoot` is exposed as instance 1 of the DEX proof's public-input vector. The callback must resolve the query against thread 0's window regardless of which thread RootPN itself executes in — the layer-tree data lives only there. (Concretely: the node's `check_history_proof_hash` callback looks up `GlobalHistoricalData[thread_id]`; only thread 0's entry is populated, so verification succeeds only when the anchored root belongs to thread 0.)

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
| L0 | Poseidon of the block's thread layer-root snapshot | Poseidon |
| L1 | `SHA-256(bincode(CommonSection))` | SHA-256 |
| L2 | `Poseidon(old_bk_set_hash)` — zero if no BK change | Poseidon |
| L3 | `Poseidon(new_bk_set_hash)` — zero if no BK change | Poseidon |
| L4 | TVM block representation hash | SHA-256 / TVM |
| L5 | `SHA-256(bincode(durable_state_update))` | SHA-256 |
| L6 | `SHA-256(tx_cnt.to_be_bytes())` | SHA-256 |
| L7 | Poseidon dense-Merkle root of `[parent_block_id, refs...]` | Poseidon |
| **L8** | **`tracked_ext_out_messages_root`** — SHA-256 root of this block's ext-out messages tree | SHA-256 |
| L9..L15 | `[0u8; 32]` (fixed zero padding) | — |

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

### 2.3 L7 — cross-thread reference tree (unchanged)

L7 is the Poseidon dense-Merkle root of `[parent_block_id, refs[0..n]]`, where each leaf is a tagged Poseidon hash:

```
REFERENCED_PARENT_BLOCK_TAG = b"acki-nacki:referenced-block:parent:v1"   (37 bytes)
REFERENCED_REF_BLOCK_TAG    = b"acki-nacki:referenced-block:ref:v1"     (34 bytes)

leaf[i] = Poseidon( tag_i ‖ proof_block_refs[i] )    (32 bytes out)
```

`proof_block_refs[0] = parent_block_id` (same thread by producer construction — see below); `proof_block_refs[1..1+n] = refs` (cross-thread). The tree is padded with literal `[0u8; 32]` leaves to the next power of two and folded with `Poseidon(left_32B ‖ right_32B)`. Depth ≤ 8 (`MAX_PROOF_BLOCK_REFS = 256`).

**Slot-0 (`parent_block_id`) is same-thread by construction.** In `poseidon_dex`, the producer for thread `t` selects its parent via `select_thread_last_finalized_block(&thread_id)` and sets the child's block height as `parent_height.next(&thread_id)` (`node/src/block/producer/producer_service/block_producer.rs:534,576,992`). The parent is therefore always in thread `t` itself. The only exception is the *spawn edge* — the first block of a newly-spawned thread T′ has as its parent the split block on the parent thread (`is_spawning_block(...)` at the same file, and `preprocessing.rs:162-190`). Spawn edges are irrelevant to voucher proofs: a producer that wants to witness such an edge for cross-thread anchoring can always add it to `refs`. **Consequence for §5:** the DEX circuit's L7 walk only opens `refs[0..n]` (slots `1..n`), never slot 0.

L7 is populated for **every** block and provides the outgoing edges the L7 walk (§5) follows.

### 2.4 L8 — tracked ext-out messages Merkle tree (the DEX-visible slot)

`L8 = tracked_ext_out_messages_root` is the SHA-256 dense-Merkle root of the block's outgoing external messages. The voucher-generation event is emitted as one such message, and its `event_hash` is a leaf of this tree.

Tree parameters (to be confirmed with the producer team — see Open Q §11.2.1/2/3):

- Combine rule: `SHA-256(left_32B ‖ right_32B)` (assumed; matches the block-id outer tree family).
- Padding: literal `[0u8; 32]` leaves to next power of 2.
- Depth cap: `EXT_OUT_DEPTH_MAX = 8` (256 messages / block max; matches L7's cap).
- Leaf format: raw `event_hash` (32 bytes); no tag prefix (assumed).

The DEX circuit opens one Merkle path `event_hash → L8`.

### 2.5 L0..L6 and L9..L15 in this design

- **L0, L1, L2, L3, L4, L5, L6** — semantically unchanged from the base protocol. On the X-side, all seven collectively appear only as the aggregate `h0..7` witness (the sole live sibling required to open L8). The DEX circuit does **not** parse any of L0..L6 individually.
- **L9..L15** — protocol-fixed as `[0u8; 32]`. Their contribution to the block-id tree collapses to two SHA-256 constants (§2.1) baked into the circuit.

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

The hop is a **building block, not a standalone snark** — it has no public inputs of its own. Block IDs and L7 material must stay hidden for DEX anonymity (§10.1); they only leave the circuit boundary through the salted endpoints of the enclosing `MultiHopProof` (see §7.3 — the outer snark exposes `salted_start_block_id` and `salted_end_block_id`, computed as `Poseidon(salt ‖ block_id)`).

Inputs for a hop B → A (all private witnesses at the hop level):

```
current_block_id  = B.block_id                          (32 bytes)
next_block_id     = A.block_id                          (32 bytes)
B.L7_root                                               (32 bytes; the L7 root being opened against B.block_id)
outer_siblings    = [L6, h45, h0..3, h8..15]            (4 × 32 bytes; depth-4 SHA path from L7 up to block_id — all opaque, incl. h8..15)
ref_index         (u16; range-checked to 1..=MAX_PROOF_BLOCK_REFS; slot 0 excluded — see §5.1)
ref_count         (u16; range-checked to ≤ MAX_PROOF_BLOCK_REFS + 1)
L7_inner_path     (≤ 8 Poseidon sibling hashes; depth bounded by MAX_PROOF_BLOCK_REFS = 256)
```

An `is_active` flag also lives at the hop level, but only makes sense inside `MultiHopProof` where a fixed-width array of `H` hops must be padded with no-op hops when the true walk length is shorter than `H`. It is a private witness of `MultiHopProof`, not of the hop primitive as such (see §7.6).

Constraints (single hop; the enclosing `MultiHopProof` gates them by its own `is_active[h]`):

1. **SHA-256 depth-4 Merkle path.** Open `B.L7_root` against `B.block_id` via the 4-step path `L7 → h67 → h4..7 → h0..7 → block_id` using witness siblings `[L6, h45, h0..3, h8..15]`. Total **4 SHA-256 compressions**. `h8..15` is an opaque witness — a hop does not bind `L8`, so no derivation from L8 or from the L9..L15 zero-constants is needed here (that only happens in `DexFinalProof`, §7.7).
2. **Tagged leaf hash for A.** Since only `refs` slots (index ≥ 1) are opened, the tag is fixed:
   ```
   tag_bytes = REFERENCED_REF_BLOCK_TAG
   tag_hash  = Poseidon(tag_bytes ‖ A.block_id)
   ```
3. **Poseidon dense-Merkle opening.** Verify `B.L7_root == open(tag_hash, ref_index, L7_inner_path)` using the canonical dense-Merkle algorithm of `dense_merkle_verify` (`node/libs/history-proof/src/lib.rs`).

In `MultiHopProof`, hops carrying `is_active[h] == 0` are no-ops: the three constraints above are disabled by selector multiplication and `next_block_id == current_block_id` is enforced instead (same pattern as `DenseChainLink::inactive`). See §7.6.

### 5.3 What one hop costs

- **4 SHA-256 compressions per hop** — one per level of the depth-4 outer path from L7 up to `block_id`.
- ≤ 8 Poseidon hashes for the L7 inner path → a few thousand cells, negligible.
- 1 Poseidon for tagged-leaf construction → negligible.
- Range checks + selectors → ≈ 100 K cells.

At `gosh-sha256-chip`'s measured ≈ 354 K advice cells per SHA compression: **≈ 1.42 M advice cells per hop**.

### 5.4 The full L7 walk

A chain of L hops `[hop_0, hop_1, ..., hop_{L-1}]` collectively proves:

```
X  =  B_0  →  B_1  →  B_2  →  ...  →  B_L  =  Y
       ^                                          ^
       thread t (event block)                     thread 0 (anchor)
```

with the gluing constraint `hop_i.next_block_id == hop_{i+1}.current_block_id` for all i.

**Production bound: `L_MAX = 300`** (specified by the node team as the cross-thread walk-length ceiling under the current threading design). The current design point of `L_MAX = 20` used in the phone-budget sizing of §7 is a **temporary** working target for early prototyping; the multi-proof composition of §7 scales `N_BUNDLE = ceil(L_MAX / H)` linearly with `L_MAX`, so raising it to 300 grows the bundle to `N_BUNDLE = 60` snarks (already stress-tested — see `test_bundle_stress_l300.rs`) without changing the per-snark K.

Reference off-chain implementation: `helpers/proof_helper/src/gql_proof.rs` on `poseidon_dex`. In-circuit hop logic mirrors `verify_proof_block_ref_proof` (Poseidon inner) + `verify_block_merkle_leaf_proof` (SHA outer, updated to depth 4).

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
- **Uniformity for `t = 0`.** When X is in thread 0, X = Y, the L7 walk collapses (all hops `is_active = 0`), and `DexFinalProof` performs both the X-side event binding and the Y-side anchor on the same block. The public inputs then satisfy `salted_X_start == salted_Y_end`; the bundle shape is indistinguishable from the multi-thread case.

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
| `DexFinalProof` | Voucher binding + X-side event binding + Y-side thread-0 anchor. Exposes 5 existing voucher fields + 3 new (salted X, salted Y, salt commitment). | **16** | 1 |

### 7.3 Salted endpoints — on-chain continuity

Every snark of a bundle exposes salted endpoints to allow the contract to chain them without seeing real block_ids:

```
salted_id  :=  Poseidon( salt , block_id )    // one Poseidon, 64 bytes input, 32 bytes out
```

`salt` is a voucher-scoped per-user secret:

```
salt  =  Poseidon( [ DOMAIN_TAG_FR , sk_u ] )

DOMAIN_TAG_BYTES = b"acki-nacki:voucher-hop-salt:v1"   (30 bytes, fixed)
DOMAIN_TAG_FR    = bytes_to_fr( DOMAIN_TAG_BYTES  zero-padded to 32 LE bytes )
```

`salt` is a **private witness** in every proof of the bundle. Two vouchers from the same user produce uncorrelated salted ids (different `sk_u`).

> **Canonical convention.** The constants and Poseidon shape are enforced by `DexFinalProof` and defined in `dex-halo2-circuit/src/salt.rs`. `RootPN.sol` equality-checks `salt_commitment` across all snarks of a bundle; any divergence between this spec and `salt.rs` breaks the orchestrator. **`salt.rs` is the source of truth.**

#### Per-`MultiHopProof` public inputs (3)

```
inst[0] = salted_start_block_id  =  Poseidon( [ salt , B_0.block_id ] )
inst[1] = salted_end_block_id    =  Poseidon( [ salt , B_H.block_id ] )
inst[2] = salt_commitment        =  Poseidon( [ salt ] )
```

#### Per-`DexFinalProof` public inputs (8)

```
inst[0] = depositIdentifierHash                                       // voucher nullifier
inst[1] = finalLayerHistoricalHashRoot                                // checked by gosh.check_layer_hash
inst[2] = voucherNominalFr
inst[3] = tokenTypeFr
inst[4] = ephemeralPubkey
inst[5] = salted_X_start  =  Poseidon( [ salt , X.block_id ] )        // chain head (event block, thread t)
inst[6] = salted_Y_end    =  Poseidon( [ salt , Y.block_id ] )        // chain tail (anchor, thread 0)
inst[7] = salt_commitment                                             // bundle binder
```

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

- **t = 0** (X in thread 0): true chain length L = 0. All 4 `MultiHopProof`s are submitted with `is_active = 0` everywhere; each is constrained to `salted_start_block_id == salted_end_block_id`. `DexFinalProof` has `salted_X_start == salted_Y_end` (X = Y).
- **t ≠ 0, L ≤ 5**: 1 `MultiHopProof` has up to 5 active hops; the remaining 3 are fully inactive.
- **L up to 20**: up to 4 partially- or fully-active proofs.

The verifier cannot tell from public inputs whether any individual `MultiHopProof` is active or inactive — `salted_start == salted_end` is one of many possible combinations of two pseudo-random-looking field values.

### 7.6 `MultiHopProof` circuit detail

`MultiHopProof` is a Halo2 circuit at K = 17. It contains `H = 5` instances of the hop gadget of §5.2, chained internally:

```
witnesses:
  salt                                              (1 Fr)
  voucher_secret_seed                               (1 Fr; sk_u = voucher_secret_seed, for salt derivation)
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
  2. salted_endpoint_check:
        salted_start_block_id_pub == Poseidon([salt, hop_current_block_id[0]])
        salted_end_block_id_pub   == Poseidon([salt, hop_next_block_id[H-1]])
  3. for each hop h in 0..H:
        when is_active[h]: full hop constraints of §5.2 (depth-4 outer opening)
        when !is_active[h]: hop_next_block_id[h] == hop_current_block_id[h]
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
        — inherited unchanged from single-thread DarkDexCircuitNew.)

  4. Event → ext_out_tree leaf, then Poseidon-Merkle open to L8:
        ext_msg_leaf =  Poseidon96( x_account_dapp_id ‖ x_account_id ‖ event_hash )    // byte-flat, §7.3
        ext_out_tree_open(ext_msg_leaf, X_event_leaf_index, X_ext_out_merkle_path)
            == X.L8_tracked_ext_out_messages_root                                       // Poseidon dense-Merkle

  5. Y-side anchor (existing single-thread flow):
        block_leaf(Y)  =  Poseidon96( Y.block_id ‖ Y.envelope_hash ‖ Y.tracked_ext_out_messages_root )
        block_leaf(Y) -- depth-8 Poseidon dense-Merkle path --> #L1(M_Y)
        #L1(M_Y)      -- dense chain (≤ 11 links)          --> finalLayerHistoricalHashRoot

  6. Salt + salted endpoints:
        salt                   == Poseidon([DOMAIN_TAG_FR, voucher_secret_seed])
        salt_commitment_pub    == Poseidon([salt])                                // instance [7]
        salted_X_start_pub     == Poseidon([salt, X.block_id])                     // instance [5]
        salted_Y_end_pub       == Poseidon([salt, Y.block_id])                     // instance [6]

  7. Public voucher fields at instances [0..4] (unchanged from single-thread DEX).

  8. Uniformity for t=0: the prover passes X = Y as identical witness bytes. All X-side and Y-side gates hold simultaneously; the bundle's MultiHopProofs are all inactive; salted_X_start == salted_Y_end trivially.
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

- **`X.block_id`, `X.height`, X's thread `t`** — fully hidden behind the voucher binding and the salted endpoints.
- **All intermediate block_ids `B_1 .. B_{L-1}`** — private witnesses inside `MultiHopProof`s.
- **`Y.block_id`** — only `salted_Y_end = Poseidon(salt, Y.block_id)` is exposed. Pseudo-random without `salt`.
- **`Y.envelope_hash`, `Y.tracked_ext_out_messages_root`** — unconstrained witnesses inside `DexFinalProof`.
- **True chain length L** — hidden by fixed `N_BUNDLE = 4`.
- **The salt itself** — private witness in every proof of the bundle.
- **X.tracked_ext_out_messages_root** — witness; only its opening to L8 of X.block_id is proved, and X.block_id is itself hidden.

### 10.2 What leaks

- **Bundle existence** — 5 proofs submitted together with one `claimVoucher` call; unavoidable and inherent to the voucher claim being public.
- **Bundle size = 5** — by design, identical for every claim.
- **A `voucher_secret_seed` is used** — already voucher-private in the single-thread case; no new leakage.

### 10.3 What is *not* a leak

- **Cross-voucher linkability** — each voucher has its own `voucher_secret_seed`, hence its own `salt` and its own `Poseidon(salt, *)` outputs. Two vouchers from the same physical user are not linkable via salted endpoints under the Poseidon random-oracle model.
- **`salted_start == salted_end`** inside a `MultiHopProof` (indicating an inactive proof) is not distinguishable from an active proof whose chain happens to loop, without knowing `salt`.

### 10.4 Threats

- **Salt re-use across vouchers** — would let an adversary correlate two bundles. Blocked by the voucher-secret-seed already being fresh per voucher, and by `DOMAIN_TAG_FR` domain separation. Wallet-software discipline required.
- **Relayer / wallet metadata side channels** — the phone submits all 5 snarks. If a relayer broadcasts the transaction, the relayer sees the bundle but not the salt. Standard relayer-anonymity considerations apply.

### 10.5 Hash strength

`Poseidon([salt, block_id])` collision resistance and pseudo-randomness over BN254 scalar field (~127-bit collision security). Sufficient for salting.

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
| Public inputs (`DexFinalProof`, 8) | see §7.3 | Preserves 5-field prefix; adds salted X / Y / commitment |
| Public inputs (`MultiHopProof`, 3) | see §7.3 | New artifact |

### 11.2 Open questions

Must be answered with the team before circuit-side implementation begins.

1. **Ext-out-messages tree combine rule.** SHA-256 dense-Merkle assumed. Alternatives: Poseidon dense-Merkle (much cheaper in circuit), or a bespoke rule. Impacts `DexFinalProof` cell budget by ≈ 2–4 SHA blocks.
2. **Ext-out-messages tree depth bound.** Assumed ≤ 8 (256 messages / block). Confirm with the producer team.
3. **Ext-out-messages leaf format.** Raw `event_hash` (32 B) vs tagged leaf (e.g. `Poseidon(tag ‖ event_hash)` analogous to L7). Impacts leaf-computation gadget in `DexFinalProof`.
4. **L9..L15 padding value.** Assumed `[0u8; 32]`. If the producer's widened `block_merkle_leaves()` uses non-zero constants (e.g. `SHA-256(b"padding")` or a version-tagged constant), the circuit's hard-coded sibling constants (§2.1) must be updated to match.
5. **Salted-endpoint direction.** `inst[5] = salted_X_start`, `inst[6] = salted_Y_end` (chain head → tail). Confirm the on-chain contract expects this order and not the reverse.
6. **Real chain-length distribution on the poseidon_dex testnet.** Production ceiling `L_MAX = 300` is set by the node team; measured p50/p99 distributions on real deployment are still open — informs how conservatively to size `N_BUNDLE` vs. batch dispatch cadence.
7. **L7 walk direction in practice.** Spec assumes hops walk **into the past** (parent + refs both point backward). Confirm this matches canonical L7-walk direction in the multi-thread design.
8. **Single-thread bundle shape.** Spec mandates that single-thread (t = 0) claims still submit 5 snarks for anonymity uniformity — a ~5× per-claim gas increase over today's single-thread DEX. Confirm this trade-off is acceptable.
9. **Salt derivation domain.** `salt = Poseidon(DOMAIN_TAG_FR, voucher_secret_seed)`. Confirm `voucher_secret_seed` is collision-resistant and not reused for any non-voucher purpose in existing wallet code.
10. **Re-merge of history-proof code into mainline.** Circuit work depends on `poseidon_dex`-branch helpers (`compute_block_leaf_hash`, `compute_referenced_blocks_root`, `HistoryBlockData::calculate_root_hash`, `proof_block_refs_root`, `proof_block_ref_proof`, and the widened `block_merkle_leaves()` producing the depth-4 tree). Confirm timeline.


---

## 12. Circuit implementation plan

Work packages that realise the spec in `dex-halo2-circuit`. §12.1 (constants) and §12.2 (ext-out gadget) unblock §12.3 (`DarkDexCircuitV2`). §12.4 (`MultiHopProofCircuit`) is independent and can proceed in parallel. §12.5 (`bundle_verifier`) and §12.6 (test helpers) sit downstream of §§12.3–12.4 and are prerequisites for the on-chain harness in §12.8.

Open Questions §11.2.1–5 must be answered before landing; the SHA-vs-Poseidon choice for the ext-out-messages tree (§11.2.1) is the primary blocker for §12.2/§12.3.

### 12.1 Protocol constants module

**Files:** new `dex-halo2-circuit/src/block_id_tree.rs`.

Shared by `DexFinalProof` and `MultiHopProof`:

- Depth-4 shape: `BLOCK_ID_TREE_DEPTH = 4`, `BLOCK_ID_TREE_LEAVES = 16`, `L8_INDEX = 8`, `L7_INDEX = 7`, `ZERO_LEAF = [0u8; 32]`.
- Native helper `compute_block_id_depth4(leaves: &[[u8;32];16]) -> [u8;32]` — used by test fixtures on both sides.

Consumed only by `DexFinalProof` (§12.3) — hops never touch these:

- `H10_11_CONST = sha256(ZERO_LEAF ‖ ZERO_LEAF)`
- `H12_15_CONST = sha256(H10_11_CONST ‖ H10_11_CONST)`

Unit test: round-trip against a hand-computed 15-SHA reference.

### 12.2 Ext-out-messages Merkle gadget

**Files:** new `dex-halo2-circuit/src/ext_out_merkle.rs`.

- Depends on Open Q §11.2.1. Implement one variant per resolution outcome; commit only the chosen shape.
- Interface:
  ```rust
  pub fn verify_ext_out_merkle_path<F: PrimeField>(
      ctx: &mut Context<F>,
      hasher: &Sha256Chip<F>,          // or PoseidonChip
      event_hash: &[AssignedValue<F>; 32],
      leaf_index: AssignedValue<F>,
      siblings: &[[AssignedValue<F>; 32]],
      root: &[AssignedValue<F>; 32],
  );
  ```
- Byte-level Merkle walk, dense-tree with power-of-2 padding, opening `event_hash → L8`. The implementation pattern (dense byte-Merkle with `leaf_index`-driven sibling order) can be lifted from the existing dense-Merkle gadget in `dark_dex_circuit_new.rs`, but this gadget lives entirely on the X-side and is unrelated to the Y-side layer-1 batch tree.
- MockProver test at K=15 with a synthetic 4-leaf tree.

### 12.3 `DexFinalProof` — new circuit `DarkDexCircuitV2`

**Files:** `dex-halo2-circuit/src/dark_dex_circuit_new.rs` (add sibling `DarkDexCircuitV2` alongside `DarkDexCircuitNew`; do not modify — feedback `add-don't-modify`).

Circuit is organised as two structurally independent subcircuits glued by `salt` and voucher-payload publics (§7.7):

**X-side witness / gates** (SHA family, event BOC → `X.block_id`):

The BOC is *not* condensed to an opaque `event_hash` before entering the circuit. Its two cells (root event cell + child voucher-payload cell) are passed in as **raw preimage bytes** and every hash on the X-side is recomputed in-circuit. Prover-side, `parse_voucher_boc` only flattens the BOC into two `cell_repr_data` byte vectors and records the child-hash byte offset inside the root preimage; no crypto is trusted from that step.

- Witnesses (X-side BOC + tree openings):
  - `x_root_cell_repr_data: [u8; len_root]` — root event cell preimage bytes.
  - `x_child_cell_repr_data: [u8; len_child]` — child voucher-payload cell preimage bytes.
  - `x_child_hash_offset_in_root: usize` (structural constant per BOC layout).
  - `x_account_dapp_id: [u8; 32]`, `x_account_id: [u8; 32]` (ext-out-message endpoint identity).
  - `x_ext_out_merkle_siblings`, `x_ext_out_merkle_position`, `x_num_ext_out_levels` (padded to `MAX_EVENTS_TREE_DEPTH`).
  - `x_block_id: [u8; 32]`, `x_l8_tracked_ext_out_messages_root: [u8; 32]`, `x_block_id_h07_sibling: [u8; 32]`.
- Gate 1 (**BOC hash reconstruction**, 2 SHA compressions): compute `event_hash = SHA(x_root_cell_repr_data)` and `child_hash = SHA(x_child_cell_repr_data)` via `Sha256Chip::digest_bytes`; constrain the 32 bytes of `x_root_cell_repr_data[offset .. offset+32]` equal to `child_hash` (this is the BOC parent→child link, exactly as done today in `dark_dex_circuit_new.rs:454-467`).
- Gate 2 (**BOC descriptor sanity**): decompose d1 byte of each cell to 8 bits, assert `refs_count == 1` for the root and `refs_count == 0` for the child (as in `dark_dex_circuit_new.rs:516-564`).
- Gate 3 (**voucher-field extraction**, byte-sliced from `x_child_cell_repr_data`):
  - `x_sk_u_commit` — bytes `[6..38]`, LE-Fr recombine (32 B).
  - `x_voucher_nominal` — bytes `[38..70]`, BE recombine (32 B).
  - `x_token_type` — bytes `[70..74]`, BE recombine (4 B).
  - Range-checks and inner-product reconstructions match the existing `EVENT_*_START/END` constants (`dark_dex_circuit_new.rs:469-514`).
- Gate 4 (**`ext_msg_leaf` Poseidon96**): `ext_msg_leaf = Poseidon96(x_account_dapp_id, x_account_id, event_hash)` (byte-flat convention, §7.3 / `poseidon_hash_96_circuit_bytes`).
- Gate 5 (**ext-out Merkle opening** from `ext_msg_leaf` to `x_l8_tracked_ext_out_messages_root`, using the §12.2 gadget; `num_ext_out_levels` witnessed and range-checked in `[0, MAX_EVENTS_TREE_DEPTH]`).
- Gate 6 (**depth-4 L8 opening** — reconstruct `x_block_id` from `x_l8_tracked_ext_out_messages_root`; **4 SHA compressions**, one per level, using constants from §12.1):
  ```
  h89     = SHA(x_l8_tracked_ext_out_messages_root ‖ ZERO_LEAF)
  h8_11   = SHA(h89   ‖ H10_11_CONST)
  h8_15   = SHA(h8_11 ‖ H12_15_CONST)
  x_block_id == SHA(x_block_id_h07_sibling ‖ h8_15)
  ```
- Gate 7 (**voucher public glue**): the four voucher publics at `inst[0..4]` (voucher_nominal, token_type, sk_u_commit, plus the fourth entry that today is the Poseidon of the tuple) are wired from the extracted / recomputed cells above — no free-standing witness bypass.

X-side SHA budget: **2 (BOC) + 4 (L8 opening) = 6 SHA compressions**, plus the ext-out Merkle walk (Poseidon, §12.2). Byte-slice extraction is nearly free (a handful of inner products).

**Y-side witness / gates** (Poseidon family, `Y.block_id` → `finalLayerHistoricalHashRoot`):
- Witnesses: `y_block_id`, `y_envelope_hash`, `y_tracked_ext_out_messages_root`, `y_block_leaf_path` (depth-8 dense-Merkle siblings + leaf index), `y_dense_chain_links` (≤ `MAX_CHAIN_LEN = 11`).
- Gate 4: identical to today's single-thread `DarkDexCircuitNew` — reuse byte-for-byte after renaming.

**Glue** (§7.3 salted-endpoints module, `dex-halo2-circuit/src/salt.rs`):
- Gate 5:
  - `salt == Poseidon([DOMAIN_TAG_FR, voucher_secret_seed])`
  - `salt_commitment` at `inst[7] = Poseidon([salt])`
  - `salted_X_start` at `inst[5] = Poseidon([salt, x_block_id])`
  - `salted_Y_end`   at `inst[6] = Poseidon([salt, y_block_id])`
- Gate 6: public voucher fields at `inst[0..4]` — unchanged from single-thread DEX.

**Uniformity (t = 0)** — no branching in the circuit. The prover simply passes `x_block_id == y_block_id`; both sub-proofs still run and both publics collapse (`inst[5] == inst[6]`). See §7.5.

Target K = 16; fallback K = 17 if the ext-out gadget cell count blows the margin.

MockProver tests: (a) t = 0 with `X = Y`; (b) t ≠ 0 with `X ≠ Y`.

### 12.4 `MultiHopProofCircuit` — depth-4 outer opening and slot-0 pruning

**Files:** `dex-halo2-circuit/src/multi_hop_proof.rs`.

Two changes lift the existing circuit to the current spec:

**(a) Depth-3 → depth-4 outer opening** (§5.3):
- Extend `MultiHopWitness` with a 4-entry outer-siblings array `[L6, h45, h0..3, h8..15]` (32 bytes each). **No `l8` field per hop** — hops do not bind L8, so `h8..15` is carried as an opaque witness (§5.2, §5.3).
- Outer-tree reconstruction gains exactly **1 SHA compression per hop** (one extra sibling combine at the new top level). Total per hop = 4 SHA (was 3 in the old depth-3 shape). `h8..15` is NOT re-derived from L8 here — that's a `DexFinalProof`-only cost.
- Reuse the depth-4 constants from §12.1 (`H10_11_CONST` / `H12_15_CONST` are irrelevant here — hops don't open L8).

**(b) Slot-0 pruning** (§5.1):
- Drop the `ref_index == 0` branch in tag selection: the L7 tagged leaf is always `Poseidon(REFERENCED_REF_BLOCK_TAG ‖ A.block_id)`. Slot 0 (`parent_block_id`) is same-thread by producer construction and never traversed by a hop.
- Change `ref_index` range-check from `0..=MAX_PROOF_BLOCK_REFS` to `1..=MAX_PROOF_BLOCK_REFS`. This is the "later simplification" flagged when §5 was rewritten.

Budget & K:
- K = 17 (unchanged). Expected cell budget at H = 5: 20 SHA × 354 K ≈ **7.1 M cells** → ~49 % margin (was ~24 % under the old 6-SHA/hop model).
- Update MockProver tests + real-KZG tests (`test_bundle_e2e.rs`, `test_bundle_stress*.rs`) with the new witness layout and pruned tag logic.

### 12.5 `bundle_verifier.rs` — tail-link check + fail-fast ordering

**Files:** `dex-halo2-circuit/src/bundle_verifier.rs`.

Bring the native-Rust verifier into byte-for-byte parity with §7.4's fail-fast Solidity ordering, so any bundle rejection in Solidity has an identical local counterpart:

- **Phase 1 (public-input consistency, cheap):**
  - Replay + `BundleTooShort` guards.
  - `SaltCommitmentMismatch` — unchanged.
  - Rename `HeadLinkBreak` → `XHeadLinkBreak` (asserts `MultiHop[0].salted_start == DexFinal.inst[5]`).
  - **New:** `TailLinkBreak { last_hop_end: Fr, dex_final_tail: Fr }` — asserts `MultiHop[N-1].salted_end == DexFinal.inst[6]`. Fixes a pre-existing bundle-verifier bug (independent of the protocol update).
  - `ContinuityBreak` (mid-chain) — unchanged.
  - `DexFinalNotFirst`, `DuplicateDexFinal` — unchanged.
- **Phase 2 (KZG verification, expensive):** only reached if phase 1 passes.
- **Phase 3 (settle):** N/A off-chain, but the ordering makes the Solidity port trivial.

Extend `test_bundle_negative.rs` with a `TailLinkBreak` scenario.

### 12.6 Synthetic chain helpers

**Files:** `dex-halo2-circuit/src/test_helpers.rs`.

- `synth_chain*` returns both `bundle_head_salted` (matches `DexFinal.inst[5]`) and `bundle_tail_salted` (matches `DexFinal.inst[6]`).
- `synthetic_dex_final(salt_commitment, salted_x_start, salted_y_end)` — new 3-arg signature (was `(salt_commitment, bundle_head_salted)`).
- Update all bundle tests (`test_bundle_e2e.rs`, `test_bundle_negative.rs`, `test_bundle_stress*.rs`) to the new helper signatures.

### 12.7 K-budget final sizing

Real-KZG runs after §12.1–6 land, on the reference laptop (release profile):

1. `MultiHopProof` at K = 17, H = 5, depth-4 outer, slot-0 pruned — target ≤ 45 s prove / snark. With the revised 49 % cell margin, H = 5 has meaningful headroom; if bench comfortably beats target, evaluate H = 6 (would reduce `N_BUNDLE` at fixed `L_MAX`).
2. `DexFinalProof` at K = 16 (2 disjoint sub-proofs + salt gates) — target ≤ 90 s prove.
3. Bundle stress: replay `test_bundle_stress_l300.rs` (already exercises `N_BUNDLE = 60`) to confirm the linear-in-`L_MAX` scaling still holds at the new per-snark cell count.
4. Lock the `(K, H, N_BUNDLE)` triple in §11.1 once measured.

### 12.8 Off-tree work

- **`RootPN.sol` orchestration.** Register `VK_DexFinal`, `VK_MultiHop`; implement §7.4 in phase order (public-input consistency → KZG verification → settle). Solidity test harness against native-Rust bundle fixtures from §12.6 — every rejection path in `bundle_verifier.rs` must have a matching Solidity revert.
- **Phone-side prover integration.** WASM / native build of all snarks; parallel proving where possible (`tvm-sdk` + phone wallet). Given the raised `L_MAX = 300` production ceiling, quantify the phone-side worst-case wall time at `N_BUNDLE = 60` before locking the prod dispatch policy (§11.2.6).

---

*End of specification.*
