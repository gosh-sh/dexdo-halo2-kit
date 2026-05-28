use std::collections::HashSet;
use std::collections::VecDeque;
use std::fmt;

use tvm_types::cell::DEPTH_SIZE;
use tvm_types::cell::SHA256_SIZE;
use tvm_types::Cell;
use tvm_types::CellType;
use tvm_types::LevelMask;
use tvm_types::Result;

/// Flat representation of a single cell from a serialized BOC tree.
#[derive(Debug, Clone)]
pub struct BocFlattenData {
    /// The cell's `repr_hash` (SHA-256, 32 bytes).
    pub repr_hash: [u8; 32],
    /// Number of child references.
    pub refs_count: u8,
    /// For each child, the byte offset of that child's `repr_hash` within
    /// `cell_repr_data`. `None` when `refs_count == 0`.
    pub childs_repr_hashes_offset: Option<Vec<u16>>,
    /// The SHA-256 preimage whose hash equals `repr_hash`.
    pub cell_repr_data: Vec<u8>,
}

impl fmt::Display for BocFlattenData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "BocFlattenData {{")?;
        writeln!(f, "  repr_hash: {}", hex_str(&self.repr_hash))?;
        writeln!(f, "  refs_count: {}", self.refs_count)?;
        match &self.childs_repr_hashes_offset {
            None => writeln!(f, "  childs_repr_hashes_offset: None")?,
            Some(offsets) => {
                write!(f, "  childs_repr_hashes_offset: [")?;
                for (i, off) in offsets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", off)?;
                }
                writeln!(f, "]")?;
            }
        }
        writeln!(
            f,
            "  cell_repr_data ({} bytes): {}",
            self.cell_repr_data.len(),
            hex_str(&self.cell_repr_data)
        )?;
        write!(f, "}}")
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl BocFlattenData {
    pub fn pretty_print(&self) {
        println!("{}", self);
    }

    /// Serializes back to the original flat byte layout:
    ///   `repr_hash (32B) || refs_count (1B) || child_offsets (2*R B) || data_len (2B BE) || cell_repr_data`
    pub fn to_bytes(&self) -> Vec<u8> {
        let r = self.refs_count as usize;
        let mut buf = Vec::with_capacity(32 + 1 + 2 * r + 2 + self.cell_repr_data.len());
        buf.extend_from_slice(&self.repr_hash);
        buf.push(self.refs_count);
        if let Some(offsets) = &self.childs_repr_hashes_offset {
            for off in offsets {
                buf.extend_from_slice(&off.to_be_bytes());
            }
        }
        buf.extend_from_slice(&(self.cell_repr_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.cell_repr_data);
        buf
    }
}

/// Extracts the number of cell references from `cell_repr_data` produced by
/// [`build_cell_repr_data`]. Reads the lower 3 bits of the `d1` descriptor byte.
///
/// Returns `None` for empty input (e.g. big cells with no data).
pub fn refs_count_from_repr_data(repr_data: &[u8]) -> Option<usize> {
    let d1 = repr_data.first()?;
    Some((d1 & 0x07) as usize)
}

/// Extracts the cell level from `cell_repr_data` produced by
/// [`build_cell_repr_data`]. Reads the level mask from bits 5-7 of the `d1`
/// descriptor byte and returns the highest set bit position (0 for ordinary
/// cells).
///
/// Returns `None` for empty input.
pub fn level_from_repr_data(repr_data: &[u8]) -> Option<usize> {
    let d1 = repr_data.first()?;
    let level_mask = (d1 >> 5) & 0x07;
    if level_mask == 0 {
        Some(0)
    } else {
        Some(8 - level_mask.leading_zeros() as usize)
    }
}

/// Returns the byte offset within `cell_repr_data` at which the cell's payload
/// data bytes begin, along with the byte length of that data section.
///
/// `cell_repr_data` for an ordinary / exotic (non-big) cell is laid out as:
///
/// ```text
/// offset      size    field
/// 0           1       d1  – level_mask(3b) | exotic(1b) | refs_count(3b)
/// 1           1       d2  – (bit_len / 8) * 2  |  (bit_len % 8 != 0)
/// 2           N       payload data bytes        ← returned offset
/// 2 + N       R * 2   child depths (big-endian u16 each)
/// 2 + N + R*2 R * 32  child repr-hashes (SHA-256 each)
/// ```
///
/// where `N = (d2 >> 1) + (d2 & 1)` = ⌈bit_len / 8⌉  and  `R = d1 & 0x07`.
///
/// Returns `None` if `repr_data` is too short to contain both descriptor bytes.
pub fn data_range_in_repr_data(repr_data: &[u8]) -> Option<(usize, usize)> {
    if repr_data.len() < 2 {
        return None;
    }
    let d2 = repr_data[1];
    let data_len = (d2 >> 1) as usize + (d2 & 1) as usize;
    Some((2, data_len))
}

/// Builds the SHA256 preimage (`cell_repr_data`) whose hash equals the cell's
/// `repr_hash`. The data follows the same layout used in `DataCell::finalize`:
///
/// For ordinary / exotic (non-big) cells:
///   `d1 || d2 || data_or_prev_hash || child_depths || child_hashes`
///
/// For big cells:
///   `raw_data`
pub fn build_cell_repr_data(cell: &Cell) -> Result<Vec<u8>> {
    let cell_type = cell.cell_type();

    // Big cells: repr_hash = SHA256(data), no descriptors or references
    if cell_type == CellType::Big {
        return Ok(cell.data().to_vec());
    }

    let bit_len = cell.bit_length();
    let refs_count = cell.references_count();
    let is_merkle = cell_type == CellType::MerkleProof || cell_type == CellType::MerkleUpdate;
    let is_pruned = cell_type == CellType::PrunedBranch;
    let mask = cell.level_mask().mask();

    // Determine which iteration `i` of finalize() produces the repr_hash.
    let repr_i: usize = if is_pruned || mask == 0 {
        0
    } else {
        8 - mask.leading_zeros() as usize
    };

    // d1: level_mask used in hash computation
    let hash_level_mask = if is_pruned {
        cell.level_mask()
    } else {
        LevelMask::with_level(repr_i as u8)
    };
    let d1 = (hash_level_mask.mask() << 5)
        | ((cell_type != CellType::Ordinary) as u8 * 8)
        | refs_count as u8;

    // d2: encodes data bit length
    let d2 = ((bit_len / 8) << 1) as u8 + (bit_len % 8 != 0) as u8;

    // Pre-calculate total size for the buffer
    let data_part_len = if repr_i == 0 {
        (bit_len / 8) + usize::from(bit_len % 8 != 0)
    } else {
        SHA256_SIZE // previous-level hash
    };
    let total = 2 + data_part_len + refs_count * (DEPTH_SIZE + SHA256_SIZE);
    let mut repr_data = Vec::with_capacity(total);

    // Descriptor bytes
    repr_data.push(d1);
    repr_data.push(d2);

    // Data portion
    if repr_i == 0 {
        let data_size = (bit_len / 8) + usize::from(bit_len % 8 != 0);
        repr_data.extend_from_slice(&cell.data()[..data_size]);
    } else {
        // Higher-level repr_hash includes the previous-level hash as data
        let prev_hash = cell.hash(repr_i - 1);
        repr_data.extend_from_slice(prev_hash.as_slice());
    }

    // Child depths (big-endian u16 each)
    let child_level = repr_i + is_merkle as usize;
    for i in 0..refs_count {
        let child = cell.reference(i)?;
        repr_data.extend_from_slice(&child.depth(child_level).to_be_bytes());
    }

    // Child hashes (32 bytes each)
    for i in 0..refs_count {
        let child = cell.reference(i)?;
        repr_data.extend_from_slice(child.hash(child_level).as_slice());
    }

    Ok(repr_data)
}

/// Walks a bag-of-cells tree starting from `root` and returns a flat
/// representation as `Vec<Vec<u8>>`, ordered root-first (parents before
/// children).
///

/// Ordering: the root is the first element. For every parent cell, its
/// children are sorted by ascending reference count (fewer refs first)
/// before being enqueued, so leaf-like children appear closer to
/// their parent in the output.
pub fn serialize_cells_tree_root_first(root: &Cell) -> Result<Vec<BocFlattenData>> {
    let mut visited = HashSet::new();
    let mut result: Vec<BocFlattenData> = Vec::new();
    let mut queue = VecDeque::new();

    visited.insert(root.repr_hash());
    queue.push_back(root.clone());

    while let Some(cell) = queue.pop_front() {
        let hash = cell.repr_hash();
        let repr_data = build_cell_repr_data(&cell)?;
        let refs_count = cell.references_count();

        // Compute offset of each child's repr_hash within cell_repr_data.
        // cell_repr_data layout: d1 || d2 || data || child_depths || child_hashes
        // Child hashes occupy the last `refs_count * SHA256_SIZE` bytes.
        let child_hashes_start = repr_data.len() - refs_count * SHA256_SIZE;

        let childs_repr_hashes_offset = if refs_count == 0 {
            None
        } else {
            Some(
                (0..refs_count)
                    .map(|i| (child_hashes_start + i * SHA256_SIZE) as u16)
                    .collect(),
            )
        };

        let mut repr_hash = [0u8; 32];
        repr_hash.copy_from_slice(hash.as_slice());

        result.push(BocFlattenData {
            repr_hash,
            refs_count: refs_count as u8,
            childs_repr_hashes_offset,
            cell_repr_data: repr_data,
        });

        // Collect children and sort by ascending reference count
        let mut children = Vec::with_capacity(refs_count);
        for i in 0..refs_count {
            children.push(cell.reference(i)?);
        }
        children.sort_by_key(|c| c.references_count());

        for child in children {
            if visited.insert(child.repr_hash()) {
                queue.push_back(child);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
use tvm_block::Deserializable;
#[cfg(test)]
use tvm_block::Message;
#[cfg(test)]
use tvm_block::Serializable;
#[test]
fn test_parse_ext_out_event_message_from_base64_boc() {
    const BOC: &str = "te6ccgEBAgEAnQABn+AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAAAAAAAA81mmcc6JgAQCQY4DCGqurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADuaygAAAAAC";

    let msg = Message::construct_from_base64(BOC).unwrap();

    println!("msg : {:?}", msg);

    //println!("msg.body : {:?}", msg.body);

    //let t = msg.clone().body.unwrap();

    //println!("t: {:?}", t);

    let rr = msg.serialize().unwrap();
    println!("Msg cell {:#.2222}", rr);

    // Contract events are external outbound messages.
    /*let header = msg
        .ext_out_header()
        .expect("expected ExtOutMsgInfo for a contract event");

    // The emitting contract address is the source.
    let src = header.src().expect("event source address must be set");
    println!("event src: {}", src);

    // Events have no real destination; they use addr_none.
    assert_eq!(header.dst, MsgAddressExt::AddrNone);

    // Logical time and unix timestamp are set by the block builder.
    println!("created_lt: {}, created_at: {}", header.created_lt, header.created_at.as_u32());
    assert_ne!(header.created_lt, 0);
    assert_ne!(header.created_at.as_u32(), 0);*/

    // The body contains the ABI-encoded event payload.
    assert!(msg.has_body(), "event message must have a body");
    let mut body = msg.body().unwrap();

    // First 32 bits are the ABI v2 function ID identifying the event.
    let function_id = body.get_next_u32().unwrap();

    let cc = body.cell();
    println!("Child {:#.2222}", cc);
    println!("event function_id: 0x{:08x}", function_id);
    assert_ne!(
        function_id, 0,
        "function_id should be non-zero for a real event"
    );
}

#[test]
fn test_parse_event_boc() {
    const BOC: &str = "te6ccgEBAgEAnQABn+AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcAAAAAAAA81mmcc6JgAQCQY4DCGqurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADuaygAAAAAC";

    let msg = Message::construct_from_base64(BOC).unwrap();

    println!("msg : {:?}", msg);

    let msg_cell = msg.serialize().unwrap();
    println!("Msg cell {:#.2222}", msg_cell);

    let flattened = serialize_cells_tree_root_first(&msg_cell).unwrap();
    println!(
        "\n=== serialize_cells_tree_root_first ({} cells) ===",
        flattened.len()
    );
    for (i, entry) in flattened.iter().enumerate() {
        println!("--- Cell {} ---", i);
        entry.pretty_print();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tvm_types::BuilderData;

    fn create_cell(bytes: &[u8], refs: &[&Cell]) -> Cell {
        let mut b = BuilderData::new();
        b.append_raw(bytes, bytes.len() * 8).unwrap();
        for child in refs {
            b.checked_append_reference((*child).clone()).unwrap();
        }
        b.into_cell().unwrap()
    }

    #[test]
    fn test_serialize_cells_tree_root_first_depth2() {
        // Build a tree of depth 2:
        //   root (data: [0xFF]) -> child_a (data: [0xAA]) -> grandchild (data: [0x11, 0x22])
        //                       -> child_b (data: [0xBB])
        let grandchild = create_cell(&[0x11, 0x22], &[]);
        let child_a = create_cell(&[0xAA], &[&grandchild]);
        let child_b = create_cell(&[0xBB], &[]);
        let root = create_cell(&[0xFF], &[&child_a, &child_b]);

        let serialized = serialize_cells_tree_root_first(&root).unwrap();

        // BFS order, children sorted by ascending refs_count:
        // root (2 refs), child_b (0 refs, sorted before child_a), child_a (1 ref), grandchild (0 refs)
        assert_eq!(serialized.len(), 4);

        // --- Entry 0: root (2 refs: child_a, child_b) ---
        let e0 = &serialized[0];
        assert_eq!(&e0.repr_hash[..], root.repr_hash().as_slice());
        assert_eq!(e0.refs_count, 2);
        let offsets0 = e0.childs_repr_hashes_offset.as_ref().unwrap();
        assert_eq!(offsets0.len(), 2);
        // cell_repr_data for root: d1(1) + d2(1) + data(1) + 2*depth(4) + 2*hash(64) = 71
        assert_eq!(
            e0.cell_repr_data.len(),
            2 + 1 + 2 * DEPTH_SIZE + 2 * SHA256_SIZE
        );
        // Verify offsets point to child hashes inside cell_repr_data
        let child_a_hash_in_crd =
            &e0.cell_repr_data[offsets0[0] as usize..offsets0[0] as usize + 32];
        assert_eq!(child_a_hash_in_crd, child_a.repr_hash().as_slice());
        let child_b_hash_in_crd =
            &e0.cell_repr_data[offsets0[1] as usize..offsets0[1] as usize + 32];
        assert_eq!(child_b_hash_in_crd, child_b.repr_hash().as_slice());

        // --- Entry 1: child_b (0 refs, sorted first because fewer refs) ---
        let e1 = &serialized[1];
        assert_eq!(&e1.repr_hash[..], child_b.repr_hash().as_slice());
        assert_eq!(e1.refs_count, 0);
        assert!(e1.childs_repr_hashes_offset.is_none());
        // cell_repr_data for leaf: d1(1) + d2(1) + data(1) = 3
        assert_eq!(e1.cell_repr_data.len(), 3);

        // --- Entry 2: child_a (1 ref: grandchild) ---
        let e2 = &serialized[2];
        assert_eq!(&e2.repr_hash[..], child_a.repr_hash().as_slice());
        assert_eq!(e2.refs_count, 1);
        let offsets2 = e2.childs_repr_hashes_offset.as_ref().unwrap();
        assert_eq!(offsets2.len(), 1);
        // cell_repr_data: d1(1) + d2(1) + data(1) + 1*depth(2) + 1*hash(32) = 37
        assert_eq!(e2.cell_repr_data.len(), 2 + 1 + DEPTH_SIZE + SHA256_SIZE);
        let gc_hash_in_crd = &e2.cell_repr_data[offsets2[0] as usize..offsets2[0] as usize + 32];
        assert_eq!(gc_hash_in_crd, grandchild.repr_hash().as_slice());

        // --- Entry 3: grandchild (0 refs) ---
        let e3 = &serialized[3];
        assert_eq!(&e3.repr_hash[..], grandchild.repr_hash().as_slice());
        assert_eq!(e3.refs_count, 0);
        assert!(e3.childs_repr_hashes_offset.is_none());
        // cell_repr_data: d1(1) + d2(1) + data(2) = 4
        assert_eq!(e3.cell_repr_data.len(), 4);

        // --- Verify cell_repr_data hashes match repr_hash ---
        // SHA256(cell_repr_data) should equal the cell's repr_hash
        use sha2::{Digest, Sha256};
        for entry in &serialized {
            let computed = Sha256::digest(&entry.cell_repr_data);
            assert_eq!(&entry.repr_hash[..], computed.as_slice());
        }
    }
}
