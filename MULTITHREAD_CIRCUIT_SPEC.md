# Multi-Thread Cryptographic Scheme — DEX Circuit

Target embodiment: `dexdo-halo2-kit/dex-halo2-circuit` (DEX voucher circuit).

This document describes the cryptographic mechanism for proving, in zero knowledge, that a voucher-generation event in **any thread t** of Acki Nacki is anchored against a layer-N batch hash that the node still retains in its **global historical data** for thread 0, and how the DEX circuit embodies that mechanism.

### Anchor model

On-chain contract `RootPN.sol` (`acki-nacki/contracts/dex/RootPN.sol`) consumes the proof together with a pair `(finalLayerHistoricalHashRoot, layerNumber)` and gates verification by:

```solidity
require(
    gosh.check_layer_hash(finalLayerHistoricalHashRoot, layerNumber),
    ERR_INVALID_HISTORY_PROOF
);
```

`gosh.check_layer_hash(root, N)` asks the node whether `root` is currently present in `GlobalHistoricalData[N]` — the node's window of recent layer-N batch hashes for **thread 0**. The proof itself exposes `finalLayerHistoricalHashRoot` as instance 1 of its public-input vector.

Therefore the DEX circuit does **not** anchor against a single fixed layer. It anchors against `#L<N>(M)` for some `(N, M)` chosen by the prover, subject only to the node still retaining that root in `GlobalHistoricalData[N]`. The prover normally targets the smallest N (N=1, cheapest in-circuit) and falls back to higher N if the layer-1 root containing the event has aged out (see `generate_vouchers_with_live_event_proving.py`).

**Anonymity is the primary purpose of this anchoring.** The DEX circuit must hide the concrete block in which the user's voucher-generation event happened — both the block's id / height (which would identify a small anonymity set) and, in the multi-thread case, the thread `t` of that block. The verifier learns only the pair `(finalLayerHistoricalHashRoot, layerNumber)`, which subsumes a full batch (N=1) or higher-layer aggregate (N>1) of recent thread-0 history; the witness — concrete block id, thread id, layer-1 batch path, and all cross-thread chain hops — stays inside the proof and is never revealed. This is also why anchoring at a higher layer N (a larger anonymity set) is sometimes preferable even when a layer-1 anchor is still available.

Multi-thread refinement: in the multi-thread design `GlobalHistoricalData` is maintained for thread 0 only. Events in thread t ≠ 0 must therefore be chained to a thread-0 batch hash via cross-thread reference edges before they can be anchored against `GlobalHistoricalData[N]`. The thread id `t` itself is part of the hidden witness — the verifier cannot distinguish proofs originating in thread 0 from proofs originating in any other thread.

The canonical multi-thread design lives on the `poseidon_dex` branch of `acki-nacki`. All field names and helpers below refer to that branch.

## 0. Terminology

Adopted from `History proofs proposal.docx` and the `poseidon_dex` implementation. Use these terms consistently throughout this document.

| Term | Meaning |
|------|---------|
| **BWS** | Batch Window Size = **128**. (`HISTORY_PROOF_WINDOW_SIZE` in `node/libs/history-proof/src/lib.rs`.) |
| **Batch M** (within a thread) | The contiguous range of blocks at heights `[M·BWS, (M+1)·BWS − 1]` within one thread. |
| **`#L<N>(M)`** | Layer-N batch hash for batch M. Layer-1 is built over the blocks of batch M; layer-(N+1) is built over `BWS` consecutive layer-N hashes. |
| **Key block** (layer-1) | The **first** block of a batch — block at height `(M+1)·BWS` in some thread. It is the block whose `common_section.history_proofs[1]` carries `#L1(M)`. |
| **Key block at layer N** | A block whose height is a multiple of `BWS^N`. It carries `#L<N>(...)` (and `#L<n>(...)` for all `n ≤ N` whose boundaries coincide) in its `common_section.history_proofs`. |
| **Non-key block** | Any block that is not layer-1 key. `common_section.history_proofs` is empty (default-built). |
| **Block leaf** (layer-1) | `block_leaf = Poseidon96(block_id, envelope_hash, tracked_ext_out_messages_root)` — what gets put into the per-thread layer-1 batch tree by the producer of the next key block. |
| **GlobalHistoricalData** | Node-side, per-thread (in multi-thread: thread 0 only) windows of layer-N batch hashes, queried by the contract via `gosh.check_layer_hash(root, N)`. |
| **`finalLayerHistoricalHashRoot`** | Instance 1 of the DEX proof; the layer-N batch hash the prover anchors against. |
| **`layerNumber`** | Contract argument naming the layer N that `finalLayerHistoricalHashRoot` belongs to. |

---

## 1. block_id construction (recap)

Every block has `block_id = root of an 8-leaf SHA-256 Merkle tree`. The 8 leaves are produced by `block_merkle_leaves()` at `node/src/types/ackinacki_block/mod.rs:261`.

```
                          block_id  (SHA-256, depth 3)
                       /            \
                   h0123             h4567
                  /     \           /     \
               h01      h23       h45      h67
              /  \     /  \      /  \     /  \
             L0  L1   L2  L3    L4  L5   L6  L7
```

Combine rule at every level of the outer tree: `SHA-256(left_32B || right_32B)`. Seven SHA-256 invocations total to fold 8 leaves into `block_id`.

Note the distinction between **leaf construction** and **outer combine**:
- The 8 leaf values themselves are produced by different hash functions depending on the slot (see "Leaves at a glance" below). Slots L0, L2, L3, L7 use Poseidon to derive the leaf value; L1, L5, L6 use SHA-256; L4 is the TVM block hash.
- The outer Merkle tree that combines those 8 leaves into `block_id` is always SHA-256.

### Leaves at a glance

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

L1..L6 are opaque to the DEX circuit. **L0 and L7 carry all the multi-thread linkage** and are detailed in §1.2 and §1.3.

### 1.1 CommonSection — fields that feed L0, L7, L1

`node/src/types/ackinacki_block/common_section.rs:85`, declaration order:

```
parent_block_id   : BlockIdentifier              // 32 bytes — fed to L7 (slot 0)
block_height      : BlockHeight
directives        : Directives
block_attestations: Vec<Envelope<AttestationData>>
round, producer_id, thread_id, threads_table
refs              : Vec<BlockIdentifier>          // fed to L7 (slots 1..n)
block_keeper_set_changes : Vec<...>
verify_complexity, acks, nacks, producer_selector
history_proofs    : BTreeMap<LayerNumber, ProofLayerRootHash>   // fed to L0
tracked_ext_out_messages_root : [u8; 32]          // committed via L1 only
tracked_ext_out_messages      : BTreeMap<...>
block_keeper_set_change_proof_data : Option<...>
```

`refs` is the cross-thread reference list — pointers to blocks in **other** threads this block depends on. `parent_block_id` is the same-thread parent. These two together form L7.

`history_proofs` is the per-layer batch-hash snapshot for **this block's thread**. It feeds L0 and is non-empty only for key blocks.

`tracked_ext_out_messages_root` does not appear in L0 or L7. It is committed only via L1 (bincode + SHA-256) and via the per-thread layer-1 batch tree (Poseidon96, see §2).

### 1.2 L0 in detail

Helper: `history_proofs_l0` at `node/libs/history-proof/src/lib.rs:175`.

L0 commits to **this block's thread** layer-batch-hash snapshot. **It is only meaningful for key blocks.** For non-key blocks, `common_section.history_proofs` is empty (default), so L0 is `Poseidon` of a preimage with `count = 0` and all layer slots zero-filled — it does not carry any usable batch hash.

#### Which blocks populate which layers

The producer of a layer-1 key block (height `≡ 0 (mod BWS)` within its thread, i.e. the first block of batch M+1) writes `#L1(M)` into `history_proofs[1]`. If that same height is also `≡ 0 (mod BWS^N)` for N > 1, the block additionally writes `#L<N>(...)` into `history_proofs[N]` for every N where the boundary coincides. Non-key blocks: `history_proofs` stays empty.

#### Preimage layout

Helper `history_proofs_l0` builds a **fixed-width 331-byte buffer P**:

```
P[0]        = count                       (u8 — number of layers present in the BTreeMap)
P[1]        = 0x01                        (layer tag 1)
P[2 .. 34]  = #L1(M)  if layer 1 present  // else 32 zero bytes
P[34]       = 0x02                        (layer tag 2)
P[35 .. 67] = #L2(...) if present         // else 32 zero bytes
P[67]       = 0x03
P[68 .. 100]= #L3(...) if present
...
P[297]      = 0x0A                        (layer tag 10)
P[298..331] = #L10(...) if present
```

Total length: `1 + 10 * (1 + 32) = 331` bytes. Layer slots are at **constant byte offsets** regardless of which layers are present (absent layers contribute 32 zero bytes, but the slot still exists).

```
L0 = Poseidon(P)            // one Poseidon hash, fixed-width input
```

`#L<N>(M)` is the Poseidon dense-Merkle root of the appropriate batch-M tree for this thread and layer (see §2).

#### Why L0 matters for multi-thread

On the **thread-t side**, the circuit only ever needs to extract `#L1(M_X)` — the layer-1 batch hash of the batch containing the event block X. Higher-layer fallback (anonymity / aging) happens on the thread-0 side of the proof, not here.

Let `C` be the **layer-1 key block of thread t** at height `(M_X + 1) · BWS` — i.e. the **first** block of the batch immediately following X's batch in thread t. C is the block whose `history_proofs[1]` carries `#L1(M_X)`, by definition of the layer-1 key-block construction.

The circuit extracts `#L1(M_X)` from C with:

1. one SHA-256 depth-3 path inside C's 8-leaf tree, opening leaf 0 → exposes `L0(C)` as 32 bytes,
2. one Poseidon hash over the 331-byte preimage P → verifies that `L0(C) == Poseidon(P)`,
3. byte-slice of P at the layer-1 slot: `#L1(M_X) = P[2 .. 34]`.

Constant byte offsets. No variable-length parsing.

C is uniquely determined by X: it is the next layer-1 key block of thread t after X's batch. There is no choice of "which C to pick" on the thread-t side; the witness commits the prover to exactly one.

### 1.3 L7 in detail

Helpers: `compute_referenced_blocks_root` and `compute_referenced_block_leaf_hash` at `node/libs/history-proof/src/lib.rs:147-170`.

L7 commits to this block's full backward-pointer set: parent (same-thread) + refs (cross-thread). The leaf list is

```
proof_block_refs[0]      = parent_block_id           (same thread as this block)
proof_block_refs[1..1+n] = refs[0..n]                (other threads, CommonSection declaration order)
```

There is no hard upper bound on `n` in the protocol code. The circuit-side bound `MAX_PROOF_BLOCK_REFS` is **256**, chosen as a power of 2.

Each leaf is a tagged Poseidon hash:

```
tag_i = REFERENCED_PARENT_BLOCK_TAG   if i == 0
      = REFERENCED_REF_BLOCK_TAG      if i >= 1

REFERENCED_PARENT_BLOCK_TAG = b"acki-nacki:referenced-block:parent:v1"   (37 bytes)
REFERENCED_REF_BLOCK_TAG    = b"acki-nacki:referenced-block:ref:v1"     (34 bytes)

leaf[i] = Poseidon( tag_i || proof_block_refs[i] )    (32 bytes out)
```

The tag distinguishes slot-0 (parent) from slots 1..n (refs) so a forged ref cannot be placed at the parent slot without breaking the leaf hash.

L7 is then the **Poseidon dense-Merkle root** of `leaf[0..len]`:

- Tree width is padded to the next power of 2 with literal `[0u8; 32]` leaves (NOT zero-tagged).
- Combine rule: `Poseidon(left_32B || right_32B)`.
- Depth: `ceil(log2(len))`. With `MAX_PROOF_BLOCK_REFS = 256`, depth ≤ 8 (and `len = 1 + n` where `n` is the number of refs).

Source for the dense-tree builder: `dense_merkle_tree` / `dense_merkle_root` at `node/libs/history-proof/src/lib.rs:51-78`.

**Why L7 matters for multi-thread:** L7 is the Poseidon-friendly slot exposing the parent and ref edges. Opening L7 of a block A and then opening one slot of its inner dense Merkle gives the circuit one outgoing edge from A — the basic hop of the cross-thread chain. L7 is populated for **every** block (key and non-key alike), since every block has a parent and may have refs.

### 1.4 L1..L6 (less interesting for multi-thread)

- **L1 = SHA-256(bincode(CommonSection))** — algebraically commits `tracked_ext_out_messages_root` (it's a CommonSection field), but the preimage is variable-length, so in-circuit extraction would require SHA over the whole bincode plus offset arithmetic past several length-prefixed collections. We do **not** use L1 for binding; we use the layer-1 batch leaf (§2) instead.
- **L2, L3** — BK set commitments. Used by Circuit 3; opaque here.
- **L4** — TVM block hash. Opaque to the DEX circuit.
- **L5** — durable state diff bincode + SHA-256. Opaque.
- **L6** — `SHA-256(tx_cnt.to_be_bytes())`. Opaque.

---

## 2. Per-thread layer-N batch tree

The per-layer batch tree is a **Poseidon dense Merkle** of width BWS = 128. It is built independently per thread per batch per layer; thread 0's layer-N tree roots are the values in `GlobalHistoricalData[N]`.

### 2.1 Layer-1 leaf: `block_leaf`

Helper: `compute_block_leaf_hash` at `node/libs/history-proof/src/lib.rs`.

For every block B (key or non-key) produced in a thread, the producer of B's next key block emits a leaf:

```
block_leaf(B) = Poseidon( B.block_id  ||  B.envelope_hash  ||  B.tracked_ext_out_messages_root )
```

Total input: 96 bytes (three 32-byte fields). Single Poseidon invocation. **This is the only place where `tracked_ext_out_messages_root` is committed in a Poseidon-friendly way** — the L1 SHA-256 path is opaque for in-circuit use.

### 2.2 Layer-1 tree leaves and prepended roots

Source: `HistoryBlockData::calculate_root_hash` at `node/src/types/history_proof.rs:163`.

For batch M of a given thread, the layer-1 tree has exactly **`BWS + 2 = 130` real leaves**, in this order:

```
leaves[0]         = last #L<2>(...) seen by this thread (zero if absent)   // higher-layer back-link
leaves[1]         = #L1(M − 1)                          (zero if M == 0)   // same-layer back-link
leaves[2 .. 130]  = block_leaf(B_{M·BWS + 0 .. M·BWS + BWS − 1})           // 128 block leaves
```

The tree is then padded with literal `[0u8; 32]` to the next power of two (= 256) and folded as a **dense Poseidon Merkle of depth 8** with combine rule `Poseidon(left_32B || right_32B)`. The root is `#L1(M)` for that thread.

Two prepended back-links create the "chain" property: `#L1(M)` cryptographically commits to `#L1(M−1)` and to the most recent higher-layer root, allowing layered fallback (§3.2) without separate chain witnesses.

### 2.3 Layer-N recursion for N ≥ 2

A layer-N batch is the range of `BWS` consecutive layer-(N−1) batches. The layer-N tree is built over their `BWS + 2 = 130` entries:

```
leaves[0]         = last #L<N+1>(...) seen (zero if absent)
leaves[1]         = #L<N>(M − 1)
leaves[2 .. 130]  = #L<N−1>(M·BWS), #L<N−1>(M·BWS + 1), ..., #L<N−1>(M·BWS + BWS − 1)
```

Padded to 256, depth 8, same combine rule. Root: `#L<N>(M)`.

### 2.4 Where each layer's batch-tree path goes in the DEX circuit

- Thread-t side: open `block_leaf(X) → #L1(M_X)` via one dense-Merkle path of depth 8 (8 Poseidon hashes).
- Thread-0 side: open `block_leaf(Y) → #L1(M_Y) → #L2(...) → ... → #L<N>(...)` via the same primitive, chained `N` times. This is exactly the existing single-thread DEX flow (§3).

---

## 3. Single-thread baseline (what the DEX circuit does today)

For events in thread 0, the current DEX circuit (commit at `dexdo-halo2-kit/dex-halo2-circuit` HEAD) proves:

```
voucher_event(X) is committed by block_leaf(X) which is committed by #L1(M_X)
which is committed by #L<N>(...) = finalLayerHistoricalHashRoot still present in GlobalHistoricalData[N].
```

Concrete steps inside the circuit:

1. **BOC parsing.** Witness contains a TVM BOC for block X. The circuit recomputes `X.block_id`, `X.envelope_hash`, `X.tracked_ext_out_messages_root` from raw cells.
2. **Event extraction.** Parse `tracked_ext_out_messages` to expose the user's voucher event and its `(depositIdentifierHash, voucherNominalFr, tokenTypeFr, ephemeralPubkey)`.
3. **Block-leaf reconstruction.** `block_leaf(X) = Poseidon96(X.block_id || X.envelope_hash || X.tracked_ext_out_messages_root)` — one Poseidon over 96 bytes.
4. **Layer-1 batch path.** One Poseidon dense-Merkle path of depth 8 from `block_leaf(X)` to `#L1(M_X)`. Witness: the 8 sibling hashes + leaf index (range-checked to `[0, 256)`).
5. **Dense chain to higher layers.** `verify_chain_of_dense_proofs` from `gosh-dense-balanced-tree` walks `MAX_CHAIN_LEN ≤ 11` dense links: `#L1(M_X) → #L1(M_X+1) → ... → #L<N>(...)`. `is_active` selectors gate each link; inactive links are constrained to `prev == curr`. The terminal root is `finalLayerHistoricalHashRoot`.
6. **`layerNumber` semantics.** Public input `layerNumber` equals `target_layer + 1` where `target_layer` is the index of the last active link in the dense chain. On-chain `gosh.check_layer_hash(finalLayerHistoricalHashRoot, layerNumber)` looks the root up in `GlobalHistoricalData[layerNumber]`.
7. **Voucher binding.** Existing single-thread DEX logic for `depositIdentifierHash` and ECDSA-related fields.

**Public-input vector (5 fields, current contract):**

| idx | name | meaning |
|-----|------|---------|
| 0 | `depositIdentifierHash` | voucher nullifier |
| 1 | `finalLayerHistoricalHashRoot` | anchor; checked by `gosh.check_layer_hash` |
| 2 | `voucherNominalFr` | voucher denomination |
| 3 | `tokenTypeFr` | token type |
| 4 | `ephemeralPubkey` | one-shot pubkey |

The multi-thread extension preserves this layout and adds two more fields (§6.4).

---

## 4. Cross-thread inclusion proof — the L7 walk

### 4.1 The hop primitive

A **hop** is the atomic cross-thread step. One hop proves:

> *Block A's block_id appears in block B's L7 (either as `parent_block_id` at slot 0, or as one of `refs[0..n]` at slots 1..n).*

That is, **block B references block A** via L7. The hop's "current" block is B (the one whose L7 we open), the "next" block is A (the one we hop to).

Because parent + refs both point to **older** blocks (parent = previous in same thread; refs = other-thread cross-references), repeated hops walk **into the past**. Reachability claim: starting from C (the next layer-1 key block of thread t after X's batch), by walking parent/ref edges into the past, we land on some block Y in thread 0.

### 4.2 What one hop constrains

Inputs / witnesses for a hop B → A:

```
public:
  current_block_id  = B.block_id        (32 bytes, LE-packed to 1 Fr for circuit transport)
  next_block_id     = A.block_id
  is_active         = bool

private witness:
  B.L0, B.L1, B.L2, B.L3, B.L4, B.L5, B.L6, B.L7_root   (the 7 sibling leaves + L7 itself)
  ref_index       (u16; 0 = parent slot, 1..n = ref slot)
  ref_count       (u16; range-checked to ≤ MAX_PROOF_BLOCK_REFS + 1)
  L7_inner_path   (≤ 8 Poseidon sibling hashes — depth bounded by max ref count, §1.3)
```

Constraints (when `is_active == 1`):

1. **SHA-256 depth-3 outer path.** Recompute `B.block_id` from `[L0, L1, L2, L3, L4, L5, L6, L7_root]` via the canonical 8-leaf SHA-256 Merkle (3 compressions on the path from leaf 7 to root, given the structure of §1).
2. **Tagged leaf hash for A.**
   ```
   tag_bytes = REFERENCED_PARENT_BLOCK_TAG  if ref_index == 0
             = REFERENCED_REF_BLOCK_TAG     otherwise
   tag_hash  = Poseidon(tag_bytes || A.block_id)
   ```
3. **Poseidon dense-Merkle opening.** Verify `B.L7_root == open(tag_hash, ref_index, L7_inner_path)` using the canonical dense-Merkle algorithm of `dense_merkle_verify` (`node/libs/history-proof/src/lib.rs`).

When `is_active == 0`: the hop is a no-op, constrained to `next_block_id == current_block_id` and all witness validity constraints disabled by selector multiplication (same pattern as `DenseChainLink::inactive`).

### 4.3 What one hop costs

- 3 SHA-256 compressions (the dominant cost) ≈ **3 × 354 K = 1.06 M advice cells** with `gosh-sha256-chip` at K ≥ 14.
- ≤ 8 Poseidon hashes for the L7 inner path → a few thousand cells, negligible.
- 1 Poseidon for tagged-leaf construction → negligible.
- Range checks + selectors → ≈ 100 K cells.

### 4.4 The full L7 walk

A chain of K hops `[hop_0, hop_1, ..., hop_{K-1}]` collectively proves a path:

```
C  =  B_0  →  B_1  →  B_2  →  ...  →  B_K  =  Y
       ^                                          ^
       thread t, layer-1 key block                thread 0
```

with the gluing constraint `hop_i.next_block_id == hop_{i+1}.current_block_id` for all i. K is the chain length, bounded in this design by `L_MAX = 20` (see §6.5).

Reference off-chain implementation: `helpers/proof_helper/src/gql_proof.rs` on the `poseidon_dex` branch. The in-circuit hop logic mirrors `verify_proof_block_ref_proof` (Poseidon inner) + `verify_block_merkle_leaf_proof` for slot 7 (SHA outer).

---

## 5. Full multi-thread binding scheme

Reading the chain from the event back to the anchor, the proof must establish:

```
voucher_event(X)
   ↓ (BOC parse + Poseidon)
block_leaf(X)
   ↓ (Poseidon dense-Merkle path, depth 8, batch tree of thread t)
#L1(M_X)
   ↓ (byte-slice of P[2..34])
P  (331-byte L0 preimage of C)
   ↓ (one Poseidon: L0 = Poseidon(P))
L0(C)
   ↓ (SHA-256 depth-3 path opening leaf 0 of C's 8-leaf block-id tree)
C.block_id
   ↓ (L7 walk: K hops, K ∈ [0, L_MAX])
Y.block_id                                    (Y is in thread 0)
   ↓ (Poseidon96, identical to thread-t side step 1)
block_leaf(Y)
   ↓ (Poseidon dense-Merkle path of depth 8, batch tree of thread 0)
#L1(M_Y)
   ↓ (dense chain, ≤ MAX_CHAIN_LEN = 11 layered steps)
#L<N>(...) = finalLayerHistoricalHashRoot   (anchor, checked by gosh.check_layer_hash)
```

Two crucial properties:

- **C is uniquely determined by X**: C is the next layer-1 key block of thread t after X's batch. The witness commits the prover to exactly that C; the circuit verifies it.
- **Y's event content is opaque**: Y's `envelope_hash` and `tracked_ext_out_messages_root` are unconstrained witnesses. Y's only role is to provide a thread-0 anchor; the event-binding has already been done on the thread-t side via X.

When `t == 0` (single-thread case), the L7 walk has `K = 0` active hops and C-extraction is a no-op — the proof collapses to a thread-0 block_leaf binding directly. See §6.3 for the uniformity construction that keeps the public-input layout indistinguishable between single-thread and multi-thread proofs.

---

## 6. DEX circuit embodiment — multi-proof composition with on-chain orchestration

### 6.1 Why not one big circuit

The full scheme of §5 cannot fit in a single Halo2 circuit at smartphone-feasible K. The dominant cost is L7-walk SHA-256: each hop = 3 SHA-256 compressions = ≈ 1.06 M advice cells. A chain of 20 hops alone is ≈ 21 M cells, well past the K ≤ 17 budget realistic on phone hardware.

Two ways to split the work — both keep the circuit primitives unchanged but differ in composition:

- **(A) In-circuit aggregation via `AggregationCircuit`** (snark-verifier-sdk / axiom-eth): produce one hop snark per hop, aggregate them into one snark by verifying all hop snarks inside a new circuit, then verify that aggregator snark inside the DEX outer. **Rejected for this design** — see §8 for a detailed comparison.
- **(B) Multi-proof composition with on-chain orchestration** (this design): produce several independent snarks, each covering a small fixed-size batch of hops, and submit them together to `RootPN.sol` which checks their continuity on-chain via salted block-id endpoints exposed as public inputs. This is the approach specified below.

### 6.2 Three circuit definitions

The design uses **three** Halo2 circuit definitions and produces a variable number of snarks per voucher claim:

| Circuit | Role | K | Snarks per voucher claim |
|---|---|---|---|
| `HopCircuit` | (helper, not submitted directly) — single hop primitive of §4.2. Used as a building block inside `MultiHopProof`. | n/a | 0 |
| `MultiHopProof` | A chain segment of up to `H = 5` hops, with `is_active` selectors per hop, exposing salted endpoints. | **16** | `N = ceil(K / H)`, padded to ≥ 1 |
| `DexFinalProof` | Voucher binding + C extraction + thread-0 anchor. Exposes existing 5 public inputs + 2 salted endpoints. | **15** | 1 |

`HopCircuit` is included as a Rust module / Halo2 gadget inside `MultiHopProof` rather than producing standalone snarks of its own. There is no on-chain artifact corresponding to a single hop.

### 6.3 Salted endpoints — the on-chain continuity mechanism

To chain `MultiHopProof` snarks together on-chain without revealing real block_ids, every snark exposes salted endpoints:

```
salted_id := Poseidon( salt , block_id )    // one Poseidon, 64 bytes input, 32 bytes out
```

`salt` is a voucher-scoped per-user secret derived from the existing voucher secret seed:

```
salt = Poseidon( DOMAIN_TAG , voucher_secret_seed )

DOMAIN_TAG = b"dex-multithread-salt-v1"   (24 bytes, fixed)
```

`salt` is a **private witness** in every proof of the bundle. The voucher-scoping ensures that two vouchers from the same user produce uncorrelated salted ids (different `voucher_secret_seed`s).

#### Per-`MultiHopProof` public inputs (3)

```
inst[0] = salted_start = Poseidon( salt , B_0.block_id )
inst[1] = salted_end   = Poseidon( salt , B_H.block_id )
inst[2] = salt_commitment = Poseidon( DOMAIN_TAG, salt )      // binds the salt across snarks
```

Inside the circuit:
- The same `salt` witness is used for `salted_start`, `salted_end`, `salt_commitment`.
- `salt_commitment` is identical across **all** proofs of the same bundle. RootPN checks this equality on-chain (cheap field comparison), which prevents an adversary from splicing proofs from different bundles together.

#### Per-`DexFinalProof` public inputs (5 existing + 3 new)

```
inst[0] = depositIdentifierHash             (existing — voucher nullifier)
inst[1] = finalLayerHistoricalHashRoot      (existing — thread-0 anchor)
inst[2] = voucherNominalFr                  (existing)
inst[3] = tokenTypeFr                       (existing)
inst[4] = ephemeralPubkey                   (existing)
inst[5] = salted_C_start = Poseidon(salt, C.block_id)   // start of L7 walk
inst[6] = salted_Y_end   = Poseidon(salt, Y.block_id)   // end of L7 walk
inst[7] = salt_commitment                                 // bundle binder, must match all MultiHopProof[*].inst[2]
```

The contract preserves the existing 5-field public-input prefix; the 3 new fields are appended. This minimizes contract-side reorganization.

### 6.4 RootPN orchestration

Pseudocode for the multi-proof verification flow, extending the existing single-thread DEX claim path:

```solidity
function claimVoucher(
    DexFinalProofData calldata dexProof,
    MultiHopProofData[] calldata hopProofs,
    uint8 layerNumber
) external {
    // 1. existing checks: not yet claimed, voucher data sane, etc.
    require(!claimed[dexProof.depositIdentifierHash], ERR_ALREADY_CLAIMED);

    // 2. verify each Halo2 snark independently (no aggregation)
    require(verify_dex_final(dexProof), ERR_INVALID_DEX_PROOF);
    for (uint i = 0; i < hopProofs.length; ++i) {
        require(verify_multi_hop(hopProofs[i]), ERR_INVALID_HOP_PROOF);
    }

    // 3. salt binding: every proof of the bundle must commit to the same salt
    bytes32 saltCommit = dexProof.publicInputs[7];     // salt_commitment
    for (uint i = 0; i < hopProofs.length; ++i) {
        require(hopProofs[i].publicInputs[2] == saltCommit, ERR_SALT_MISMATCH);
    }

    // 4. chain continuity: salted endpoints must thread together
    require(hopProofs.length >= 1, ERR_BUNDLE_TOO_SHORT);          // see §6.5 uniformity
    require(hopProofs[0].publicInputs[0] == dexProof.publicInputs[5], ERR_C_MISMATCH);
    for (uint i = 0; i + 1 < hopProofs.length; ++i) {
        require(
            hopProofs[i].publicInputs[1] == hopProofs[i+1].publicInputs[0],
            ERR_CHAIN_BREAK
        );
    }
    require(
        hopProofs[hopProofs.length - 1].publicInputs[1] == dexProof.publicInputs[6],
        ERR_Y_MISMATCH
    );

    // 5. anchor: thread-0 history-data check (unchanged from today)
    require(
        gosh.check_layer_hash(dexProof.publicInputs[1], layerNumber),
        ERR_INVALID_HISTORY_PROOF
    );

    // 6. settle voucher (existing logic)
    _mintAndSendVoucher(dexProof);
    claimed[dexProof.depositIdentifierHash] = true;
}
```

All five checks are cheap on EVM (field comparisons + N+1 Halo2 KZG verifications).

### 6.5 Uniformity: single-thread and multi-thread proofs look identical

To prevent the verifier from distinguishing thread-0 events from thread-t events by bundle shape, **every** voucher claim submits exactly `N_BUNDLE` `MultiHopProof` snarks regardless of true chain length. For phone-budget reasons we choose `N_BUNDLE = 4`, supporting chains of up to `4 × H = 20` real hops.

Cases:

- **t == 0** (event in thread 0): true chain length K = 0. All 4 `MultiHopProof`s are submitted with `is_active = 0` everywhere. Each is constrained to `salted_start == salted_end`. The DexFinalProof has `salted_C_start == salted_Y_end` (i.e. C == Y, since "C" is then just X's own block).
- **t ≠ 0, K ≤ 5**: 1 `MultiHopProof` has up to 5 active hops; the remaining 3 are fully inactive (start == end at each).
- **K up to 20**: up to 4 partially-or-fully active proofs.

The verifier cannot tell from the public inputs whether any individual `MultiHopProof` is active or inactive — `salted_start == salted_end` is just one possible combination of two pseudo-random-looking field values.

### 6.6 `MultiHopProof` circuit detail

`MultiHopProof` is a Halo2 circuit at K = 16. It contains `H = 5` instances of the hop gadget of §4.2, chained together internally:

```
witnesses:
  salt                                                 (1 Fr)
  voucher_secret_seed                                  (1 Fr, only for salt derivation)
  for h in 0..H:
    is_active[h]                                       (bool)
    hop_current_block_id[h], hop_next_block_id[h]      (32 bytes each)
    B_h.L0..L6, B_h.L7_root                            (7 × 32 + 32 bytes)
    ref_index[h], ref_count[h]
    L7_inner_path[h]                                   (≤ 8 × 32 bytes)

constraints:
  1. salt_commitment_check:
        salt_commitment_pub == Poseidon(DOMAIN_TAG, salt)
        salt == Poseidon(DOMAIN_TAG, voucher_secret_seed)
  2. salted_endpoint_check:
        salted_start_pub == Poseidon(salt, hop_current_block_id[0])
        salted_end_pub   == Poseidon(salt, hop_next_block_id[H-1])
  3. for each hop h in 0..H:
        when is_active[h]: full hop constraints of §4.2
        when !is_active[h]: hop_next_block_id[h] == hop_current_block_id[h]
  4. for each h in 0..H-1:
        hop_current_block_id[h+1] == hop_next_block_id[h]   (internal chain glue)
```

Cell-count budget at H = 5: 15 SHA-256 compressions × 354 K ≈ **5.3 M advice cells**. K = 16 with ~110 columns provides ≈ 7.2 M cells → ~25 % margin. Proving time on a high-end phone: estimated 3–4 minutes per snark.

### 6.7 `DexFinalProof` circuit detail

`DexFinalProof` is the extended voucher circuit at K = 15. It contains the existing single-thread DEX logic plus C-extraction:

```
new witnesses (over today's K=14 DEX):
  salt                                                  (1 Fr; same as in MultiHopProof)
  voucher_secret_seed                                   (already a witness today)
  C.L1, C.L2, C.L3, C.L4, C.L5, C.L6, C.L7              (the 7 non-L0 leaves of C)
  C.L0                                                  (= Poseidon(P))
  C_L0_preimage P                                       (331 bytes)
  C.block_id                                            (committed by SHA-256 reconstruction)
  Y.block_id                                            (already in current DEX logic)

new constraints (over today's K=14 DEX):
  1. C.block_id reconstruction:
        sha256_tree([C.L0, C.L1, ..., C.L7]) == C.block_id     (3 SHA-256 compressions on the L0-side path)
  2. C.L0 verification:
        Poseidon(P) == C.L0                                     (one Poseidon over 331-byte fixed-width input)
  3. Layer-1 slot extraction:
        L1_M_X := P[2 .. 34]                                    (byte-slice, no extraction cost)
  4. Thread-t batch path:
        block_leaf(X) -- depth-8 Poseidon dense-Merkle path --> L1_M_X
  5. Salt and salted endpoints:
        salt == Poseidon(DOMAIN_TAG, voucher_secret_seed)
        salt_commitment_pub == Poseidon(DOMAIN_TAG, salt)
        salted_C_start_pub  == Poseidon(salt, C.block_id)
        salted_Y_end_pub    == Poseidon(salt, Y.block_id)
  6. existing single-thread logic unchanged:
        block_leaf(Y), thread-0 dense-Merkle path to #L1(M_Y), dense chain to finalLayerHistoricalHashRoot,
        depositIdentifierHash binding, ECDSA / voucher fields, layerNumber semantics.
```

Cell budget: today's DEX at K=14 sits roughly at ≈ 1.7 M cells (5 SHA blocks plus Poseidon work). Adding 3 SHA blocks (≈ 1.06 M) + ≈ 20 Poseidons (negligible) → ≈ 2.8 M cells. K = 15 provides ≈ 3.5 M cells → ~20 % margin. Proving time on phone: estimated 1.5–2 minutes.

### 6.8 Bundle size and proving time on phone

| True chain length K | Active `MultiHopProof`s | Inactive `MultiHopProof`s | Total snarks submitted | Phone proving time (estim.) |
|---|---|---|---|---|
| 0 (event in thread 0) | 0 | 4 | 5 | ≈ 14–18 min |
| 1–5 | 1 | 3 | 5 | ≈ 14–18 min |
| 6–10 | 2 | 2 | 5 | ≈ 14–18 min |
| 11–15 | 3 | 1 | 5 | ≈ 14–18 min |
| 16–20 | 4 | 0 | 5 | ≈ 14–18 min |

Wall time is constant in K — every claim submits the same fixed 5 snarks (1 DexFinalProof + 4 MultiHopProofs). This is required for uniformity (§6.5). The trade-off: phones always pay the worst-case proving time, but the verifier never learns the true chain length.

If a worst-case anonymity guarantee is not required, `N_BUNDLE` can be made dynamic and we save proving time at the cost of a small chain-length leak (§9).

### 6.9 Public-input vectors recap

```
DexFinalProof (8 fields):
  [0] depositIdentifierHash
  [1] finalLayerHistoricalHashRoot       ← consumed by gosh.check_layer_hash(.,layerNumber)
  [2] voucherNominalFr
  [3] tokenTypeFr
  [4] ephemeralPubkey
  [5] salted_C_start
  [6] salted_Y_end
  [7] salt_commitment

MultiHopProof (3 fields):
  [0] salted_start
  [1] salted_end
  [2] salt_commitment
```

### 6.10 Verifying-key set

Three distinct VKs total: `VK_DexFinal`, `VK_MultiHop`, none-of-them-aggregated. All are bundled with the contract and the phone app. No universal VK machinery, no agg_vk_hash, no recursion. See §8 for why this matters.

---

## 7. Synthetic test data generator

A separate Rust binary in `dexdo-halo2-kit/dex-halo2-circuit/examples/` (analogous to `gen_synthetic_voucher.rs` in the current single-thread setup) produces fixtures for every supported configuration:

| Case | t | K (real hops) | Active `MultiHopProof`s | Notes |
|------|---|---|---|---|
| S0 | 0 | 0 | 0 | Pure single-thread, all hop proofs inactive |
| S1 | t≠0 | 1 | 1 (1 active hop) | Shortest cross-thread |
| S5 | t≠0 | 5 | 1 (5 active hops) | Single fully-active hop proof |
| S6 | t≠0 | 6 | 2 (5+1 active hops) | Boundary into 2-proof regime |
| S15 | t≠0 | 15 | 3 (5+5+5) | Mid-range |
| S20 | t≠0 | 20 | 4 (5+5+5+5) | Worst case for L_MAX = 20 |

Each fixture emits:
1. Witnesses + native proof for `DexFinalProof`.
2. Witnesses + native proofs for all 4 `MultiHopProof`s in the bundle.
3. Native bundle verification (replays the RootPN orchestration logic in Rust to catch any continuity bug before circuit-side debugging).

The generator must also include a **single VK** check: it produces all fixtures using one fixed `VK_DexFinal` and one fixed `VK_MultiHop`. The verifier (contract test harness + Halo2 native test) accepts all fixtures with the same pair of VKs — this is the cross-case uniformity guarantee.

---

## 8. Why not `AggregationCircuit` (axiom-eth / snark-verifier-sdk)?

The "natural" zk-engineering answer to a 20-hop chain is to use `AggregationCircuit::new::<SHPLONK>(...)` from snark-verifier-sdk: produce one snark per hop, then verify all hop snarks inside one outer aggregator circuit (yielding one combined snark), and finally embed that aggregator into the DEX outer. This is the pattern used by `axiom-eth/axiom-query` (SubqueryAggregation → AxiomAggregation1 → AxiomAggregation2).

We considered it carefully and rejected it for this design. Reasons:

### 8.1 Smartphone budget

In-circuit verification of one Halo2 KZG snark costs ≈ 0.5–1.5 M advice cells per snark verified (limb-level EC arithmetic over BN254 dominates). For 20 hop snarks aggregated flat, this lands the aggregator at K ≈ 21 (~4 GB KZG SRS, several GB of working memory during proving). The DEX outer that consumes the aggregator snark rides ~2 K above → K ≈ 23 (~16 GB SRS). This is **fundamentally outside** a smartphone budget; we estimate the practical phone ceiling at K ≤ 17 (≈ 250 MB SRS, 1–3 GB working set, a few minutes proving).

The multi-proof scheme of §6, by contrast, sits comfortably at K = 16 (`MultiHopProof`) and K = 15 (`DexFinalProof`), each provable on phone in a few minutes.

### 8.2 SRS and toolchain cost

`AggregationCircuit` at K ≈ 21–23 requires:
- a KZG SRS file of 4–16 GB, which the app cannot reasonably ship or generate on device,
- working memory during proving in the multi-GB range,
- snark-verifier-sdk + axiom-eth + the `aggregation` feature flag enabled in the prover build → a substantial chunk of new code on the prover path.

The multi-proof scheme requires only the **existing** Halo2-base / Halo2-ecc stack already used by the single-thread DEX. No snark-verifier-sdk, no in-circuit verifier of any kind, no universal-VK machinery, no Poseidon transcript matching, no recursive accumulator handling.

### 8.3 Parallelism

`AggregationCircuit` proving is serial-dominant: the aggregator must verify all inner snarks together in one circuit pass, and that pass cannot be parallelized across cores in any meaningful way at the SRS scale we're talking about. On a phone with 2–3 fast cores, a K = 21 proof takes tens of minutes to hours.

In the multi-proof scheme, the 4 `MultiHopProof` snarks can in principle be generated concurrently if the phone has multiple cores available, since they are independent. Even strictly serial, the total wall time (≈ 14–18 min) is competitive with the aggregator-only path's serial cost.

### 8.4 Verification cost on EVM

EVM verification cost is roughly proportional to the number of snarks verified:
- `AggregationCircuit` path: 1 snark verification on-chain → ≈ 700–800 K gas.
- Multi-proof path: 5 snark verifications → ≈ 3.5–4 M gas.

The multi-proof path pays a **~5× higher** on-chain gas cost. For Acki Nacki / TVM-side and L2 deployments this is negligible; for Ethereum L1 at peak gas it is noticeable but still tolerable. We judge the gas overhead acceptable given the smartphone proving constraint, which is non-negotiable.

### 8.5 Anonymity equivalence

Both schemes provide the same intrinsic anonymity: intermediate block_ids are private witnesses in either case. The salted-endpoint mechanism of §6.3 is the multi-proof scheme's compensation for not having an in-circuit verifier to hide endpoint identifiers. With voucher-scoped salt, the cryptographic strength is comparable.

The one place where `AggregationCircuit` would have a marginal anonymity advantage is **bundle-size uniformity**: a single aggregated snark obviously has size 1, regardless of true chain length. The multi-proof scheme handles this via fixed `N_BUNDLE = 4` (§6.5), padding with inactive `MultiHopProof`s. This matches the aggregator's uniformity at a constant proving-time cost.

### 8.6 Operational simplicity

- Multi-proof: 3 circuit definitions, 2 distinct VKs (`VK_MultiHop` and `VK_DexFinal`). The contract handles continuity in plain Solidity field comparisons.
- AggregationCircuit: 3 circuit definitions plus the aggregator and the DEX outer, 4 distinct VKs at minimum, recursive proof composition in Rust, snark-verifier-sdk feature flags, universal-VK hash chaining if we want to keep one aggregator across chain lengths, in-circuit Poseidon transcript matching, KZG accumulator unpacking.

The multi-proof design is meaningfully simpler to ship, audit, and debug.

### 8.7 Future-compatibility

If chain lengths in practice turn out larger than `L_MAX = 20`, both schemes scale, with different cost shapes:

- Multi-proof: bump `N_BUNDLE` and `H` modestly, accept a bit more on-chain gas and proving time.
- AggregationCircuit: bump aggregator K, accept exponentially-growing SRS and proving cost.

The multi-proof path scales more gracefully on smartphone for chain lengths up to ~50. Past that, an aggregation step might become attractive — but it would be added in a separate workstream once we have empirical data from the testnet on real chain-length distributions.

---

## 9. Anonymity analysis

### 9.1 What is hidden

- **`X.block_id`, `X.height`, X's thread `t`** — fully hidden behind the voucher binding and the salted endpoints. No public input reveals which block, which thread, or which batch X belongs to.
- **`C.block_id`** — only `salted_C_start = Poseidon(salt, C.block_id)` is exposed. Without `salt`, this is pseudo-random.
- **All intermediate block_ids `B_1 .. B_{K-1}`** — pure private witnesses inside `MultiHopProof`s, never leave the prover.
- **`Y.block_id`** — only `salted_Y_end = Poseidon(salt, Y.block_id)` is exposed. Same pseudo-randomness as C.
- **`Y.envelope_hash`, `Y.tracked_ext_out_messages_root`** — unconstrained witnesses inside `DexFinalProof`.
- **True chain length K** — hidden by the fixed `N_BUNDLE = 4` padding (§6.5).
- **The salt itself** — private witness in every proof of the bundle.

### 9.2 What leaks

- The **bundle exists at all** — bundle is observable on-chain (5 proofs submitted together with a single `claimVoucher` call). This is unavoidable and inherent to the voucher claim being a public event.
- The **bundle size is exactly 5** — fixed, identical for every voucher claim. This is by design (uniformity); it does not vary, hence leaks nothing about chain length.
- The **bundle uses some `voucher_secret_seed`** — but this is already a voucher-private witness in the single-thread case. No new leakage.

### 9.3 What is *not* a leak (subtle cases)

- Two bundles by the same physical user are **not linkable** via salted endpoints, because each voucher has its own `voucher_secret_seed` → its own `salt` → its own `Poseidon(salt, *)` outputs. Two different vouchers' `salted_C_start`s are uncorrelated under the random-oracle model for Poseidon.
- A proof's `salted_start == salted_end` (indicating an inactive `MultiHopProof`) is **not distinguishable** from an active proof where the chain happens to wrap or loop, *unless* an adversary computes `Poseidon(salt, ?)` for some specific block_id. Without the salt, the equality is just two pseudo-random field values that happen to coincide.

### 9.4 Threat: salt re-use across vouchers

If a user accidentally re-uses a `voucher_secret_seed` (which would also let them claim the same voucher twice, blocked by `depositIdentifierHash` nullifier), salt re-use would let an adversary correlate two bundles. This is a wallet-software discipline issue, not a circuit-level one. The DOMAIN_TAG in salt derivation ensures no accidental reuse from any other voucher-related Poseidon hash.

### 9.5 Threat: relayer / wallet metadata side-channels

The phone proves and submits all 5 snarks. If the user uses a relayer to broadcast the on-chain transaction, the relayer sees the bundle but not the salt. Standard relayer-anonymity considerations apply; no new attack surface introduced by this design.

### 9.6 Hash strength sufficiency

`Poseidon(salt, block_id)` collision resistance and pseudo-randomness over the BN254 scalar field are sufficient for the salting purpose (BN254 ≈ 254-bit field, ≈ 127-bit collision security). For voucher-scoping uniqueness, the salt domain is `Poseidon(DOMAIN_TAG, voucher_secret_seed)` where `voucher_secret_seed` already has full collision security in the existing DEX. No primitive change needed.

---

## 10. Locked parameters and open questions

### 10.1 Locked

| Parameter | Value | Source / rationale |
|---|---|---|
| BWS | 128 | `HISTORY_PROOF_WINDOW_SIZE` (canonical) |
| Layer-1 batch tree depth | 8 (130 leaves padded to 256) | `HistoryBlockData::calculate_root_hash` |
| L7 outer SHA-256 depth | 3 (8-leaf block-id tree) | `block_merkle_leaves` |
| `MAX_PROOF_BLOCK_REFS` (L7 inner depth bound) | **256** leaves padded, depth 8 | Protocol cap reported by team |
| `H` (hops per `MultiHopProof`) | **5** | Phone budget at K=16 |
| `N_BUNDLE` (fixed proofs per claim) | **4** + 1 DexFinalProof = 5 | Anonymity uniformity |
| `L_MAX` (max real chain length) | **20** (= H × N_BUNDLE) | Multi-proof design target |
| `MAX_CHAIN_LEN` (thread-0 dense chain) | **11** (unchanged) | `gosh-dense-balanced-tree` |
| `MultiHopProof` K | **16** | Cell-budget sizing |
| `DexFinalProof` K | **15** | Cell-budget sizing |
| `DOMAIN_TAG` | `b"dex-multithread-salt-v1"` | Per-version domain separation |
| SHA-256 chip | `gosh-sha256-chip` (unchanged) | Existing dependency |
| On-chain verifier | per-snark Halo2 KZG verification | No aggregation |
| Public-input layout (`DexFinalProof`) | existing 5 + `salted_C_start` + `salted_Y_end` + `salt_commitment` | Preserves contract compatibility |
| Public-input layout (`MultiHopProof`) | `salted_start`, `salted_end`, `salt_commitment` | New artifact |

### 10.2 Open questions

These must be answered with the team before circuit-side implementation begins.

1. **Real chain-length distribution on the poseidon_dex testnet.**
   We are designing for `L_MAX = 20` based on the colleagues-reported worst-case cap of 300 being judged unrealistic. We assume typical chains are 3–5 hops and worst-case ≤ 20. If real testnet data shows p99 > 20, we must either raise `N_BUNDLE` (more proving time) or add a recursive aggregation fallback path (separate workstream).

2. **Partial-batch semantics for `#L1(M_X)`.**
   When X's batch M_X is not yet fully closed (i.e., fewer than `BWS = 128` blocks finalized), does the node compute `#L1(M_X)` over a padded leaf set, or refuse to produce it? The spec assumes the latter — the prover waits for batch closure. Confirm with the team.

3. **`MAX_PROOF_BLOCK_REFS` semantics.**
   The protocol code does not enforce a hard cap on `refs.len()`. We have set the in-circuit cap to 8 (depth-8 inner L7 tree, 256 leaves). Confirm with the team that real chains never produce blocks with more than ~250 refs. If they can, we widen the inner tree depth (cheap — one extra Poseidon per hop per depth level).

4. **L7 walk direction in practice.**
   Spec assumes hops walk **into the past** (parent + refs both point backward). Reachability from C (thread t) to Y (thread 0) is established by repeatedly following these backward edges. Confirm this is the canonical L7-walk direction in the multi-thread design.

5. **First-hop ownership.**
   We have placed every hop, including the C → B_1 first hop, inside `MultiHopProof`s. `DexFinalProof` is "hop-free" — it only extracts C and anchors Y. Confirm this split is acceptable, or whether the team prefers `DexFinalProof` to absorb the first hop (would push `DexFinalProof` to K = 16).

6. **Single-thread bundle shape.**
   Spec mandates that single-thread (t=0) claims still submit 5 snarks for anonymity uniformity. This roughly **5×s** the per-claim gas cost relative to today's single-thread DEX, even for events in thread 0. Confirm this trade-off is acceptable for the protocol economics, or whether a dynamic `N_BUNDLE` (with a small chain-length leak) is preferred.

7. **Salt derivation domain.**
   `salt = Poseidon(DOMAIN_TAG, voucher_secret_seed)`. Confirm `voucher_secret_seed` is collision-resistant and not reused for any non-voucher purpose in the existing wallet code.

8. **Re-merge of history-proof code into mainline.**
   This spec depends on the `poseidon_dex`-branch helpers (`compute_block_leaf_hash`, `compute_referenced_blocks_root`, `history_proofs_l0`, `HistoryBlockData::calculate_root_hash`, `proof_block_refs_root`, `proof_block_ref_proof`, etc.). Confirm with the team the timeline for these landing on `dev` so circuit work and protocol work can converge.

### 10.3 Out of scope for this document

- Recursive aggregation (`AggregationCircuit`) — see §8 for rejection rationale.
- Off-device proving — explicitly excluded per smartphone requirement.
- Circuit 4 / bridge-event-prove-circuit changes — handled separately.
- Changes to `Circuit 1A/2/3` (bridge bk-set / attestation circuits) — out of scope.

---

## 11. Implementation phases

| Phase | Goal | Crates / files touched |
|---|---|---|
| 1 | `HopCircuit` Halo2 gadget (single hop, no proving). Tests against `gql_proof.rs` fixtures. | `dex-halo2-circuit/src/gadgets/hop.rs` |
| 2 | `MultiHopProof` circuit at K = 16. Witness builder. Native-prover end-to-end test for 1, 3, 5 active hops + uniformity check (all inactive). | `dex-halo2-circuit/src/circuits/multi_hop.rs` |
| 3 | `DexFinalProof` extension: add C-reconstruction + `#L1(M_X)` extraction + batch-tree path + salt outputs. Reuses existing single-thread DEX logic for everything else. | `dex-halo2-circuit/src/circuits/dex_final.rs` |
| 4 | RootPN.sol multi-proof orchestration. Verifier-contract updates: register `VK_MultiHop`, extend `claimVoucher` per §6.4. | `acki-nacki/contracts/dex/RootPN.sol` and Solidity test harness |
| 5 | Synthetic E2E generator (§7). Chains of length 0, 1, 3, 5, 6, 15, 20. End-to-end on local devnet. | `dex-halo2-circuit/examples/gen_multithread_voucher.rs` |
| 6 | Phone-side prover integration: WASM / native build of all 5 snarks, parallel proving where possible. | `tvm-sdk` + phone wallet integration |

Phase 1–5 are the in-tree circuit and contract work. Phase 6 is the wallet integration and may run partially in parallel.

---

*End of specification. Reviewers: please direct comments on locked parameters (§10.1) and open questions (§10.2) to the spec author before circuit-side implementation begins.*
