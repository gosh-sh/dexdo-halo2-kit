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

The per-layer batch tree is a **Poseidon dense Merkle** of width BWS = 128. Layer-1 leaves are `block_leaf` values, with the previous batch's `#L1(M−1)` prepended at index 0. All hashes in `block_merkle_leaves` slots L0 / L2 / L3 / L7 are Poseidon.

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

Combine rule at every level: `SHA-256(left_32B || right_32B)`. Seven SHA-256 invocations total.

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

L0 of a **layer-N key block C of thread t** exposes `#L<N>(M_C − 1)` at constant byte offset `P[1 + 33·(N−1) + 1 .. 1 + 33·N]`, where `M_C` is the batch number of C at layer N. The circuit can extract any `#L<N>(...)` carried by C with:
1. one SHA-256 depth-3 path inside C's 8-leaf tree → exposes L0 (32 bytes),
2. one Poseidon hash over the 331-byte preimage → verifies L0,
3. byte-slice at the constant offset for layer N → yields `#L<N>(M_C − 1)`.

No offset arithmetic, no variable-length parsing.

This works only when C is a key block of thread t **at the layer N being extracted**. If the prover picks any other thread-t block, L0 carries no usable batch hash for that layer.

### 1.3 L7 in detail

Helpers: `compute_referenced_blocks_root` and `compute_referenced_block_leaf_hash` at `node/libs/history-proof/src/lib.rs:147-170`.

L7 commits to this block's full backward-pointer set: parent (same-thread) + refs (cross-thread). The leaf list is

```
proof_block_refs[0]      = parent_block_id           (same thread as this block)
proof_block_refs[1..1+n] = refs[0..n]                (other threads, CommonSection declaration order)
```

There is no hard upper bound on `n` in the protocol code. The circuit-side bound `MAX_PROOF_BLOCK_REFS` is chosen as a power of 2 (initially 8).

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
- Depth: `ceil(log2(len))`. With `MAX_PROOF_BLOCK_REFS = 8`, depth ≤ 3 (and `len = 1 + n` where `n` is the number of refs).

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

(To be filled in — covers `block_leaf = Poseidon96(...)`, layer-1 BWS=128 dense Poseidon Merkle of `block_leaf` values with `#L1(M−1)` prepended at index 0, recursive layer-N construction over BWS consecutive layer-(N−1) hashes.)

---

## 3. Single-thread baseline (what the DEX circuit does today)

(To be filled in — current single-thread DEX flow: BOC parsing → event extraction → block_leaf reconstruction → dense Poseidon Merkle path to `#L1(M)` → dense chain steps stepping `#L1(M) → #L1(M+1) → … → finalLayerHistoricalHashRoot`; `target_layer + 1 = layerNumber` semantics.)

---

## 4. Cross-thread inclusion proof — the chain

(To be filled in — Y → Z₁ → … → C via L7 hops; canonical-design provenance from `helpers/proof_helper/src/gql_proof.rs`.)

---

## 5. Binding `tracked_ext_out_messages_root` and reaching `GlobalHistoricalData` in multi-thread

(To be filled in — chain anchors a **key block C of thread t** at a layer that the prover can chain into thread-0's `GlobalHistoricalData[N]`; circuit unpacks C.L0 → reads `#L<N>(M_C−1)` at the layer-N byte offset → walks the batch tree to `block_leaf(X)` → chain into thread 0 via L7 refs → land on `finalLayerHistoricalHashRoot` retained in node's `GlobalHistoricalData[N]`.)

---

## 6. DEX circuit embodiment

(To be filled in — new sub-circuits, witness layout, public-input vector with `finalLayerHistoricalHashRoot` at instance 1, single-VK strategy across thread-0 and thread-t cases.)

---

## 7. Synthetic test data generator

(To be filled in — single VK must cover X ∈ thread 0 (no chain, no L0 unpack) and X ∈ thread t ≠ 0 (full chain + L0 unpack), at every supported layer N.)
