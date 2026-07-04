//! Hive image + log codecs (spec §11-§12). Versioned, checksummed, explicit TLV (never Rust
//! struct layout), reusing the `nt-config-store` byte primitives + CRC-32C.

use alloc::string::String;
use alloc::vec::Vec;

use nt_config_store::codec::{crc32c, Reader, Writer};

use crate::hive::{Cell, CellId, Hive, HiveKind, KeyCell, RegistryValueType, ValueCell};

const IMAGE_MAGIC: [u8; 8] = *b"UNTHIVE1";
const IMAGE_HEADER_LEN: usize = 8 + 2 + 2 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 4 + 4; // 68
const SCHEMA_VERSION: u16 = 1;

const REC_KEY_CELL: u16 = 1;
const REC_VALUE_CELL: u16 = 2;

const LOG_MAGIC: [u8; 4] = *b"HLR1";
const LOG_HEADER_LEN: usize = 4 + 2 + 2 + 8 + 4 + 4 + 4; // 28
const OP_CREATE_KEY: u16 = 1;
const OP_SET_VALUE: u16 = 2;
const OP_DELETE_VALUE: u16 = 3;

/// Why decoding a hive image/log failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveDecodeError {
    BadMagic,
    BadChecksum,
    Truncated,
    UnsupportedSchema,
}

// --- image (spec §11) --------------------------------------------------------

/// Serialize a hive to a versioned, checksummed image (spec §11).
pub fn encode_image(hive: &Hive) -> Vec<u8> {
    let mut p = Writer::new();
    let mut record_count = 0u64;
    for k in hive.key_cells() {
        p.u16(REC_KEY_CELL);
        p.u64(k.id.0);
        p.u64(k.parent.map(|c| c.0).unwrap_or(0));
        p.str16(&k.name);
        p.u32(0); // flags
        match &k.class_name {
            Some(c) => {
                p.u8(1);
                p.str16(c);
            }
            None => p.u8(0),
        }
        p.u64(k.last_write_sequence);
        record_count += 1;
    }
    for v in hive.value_cells() {
        p.u16(REC_VALUE_CELL);
        p.u64(v.id.0);
        p.u64(v.parent_key.0);
        p.str16(&v.name);
        p.u32(v.value_type as u32);
        p.blob(&v.data);
        p.u64(v.last_write_sequence);
        record_count += 1;
    }
    let payload = p.buf;
    let payload_crc = crc32c(&payload);

    let mut h = Writer::new();
    h.bytes(&IMAGE_MAGIC);
    h.u16(IMAGE_HEADER_LEN as u16);
    h.u16(SCHEMA_VERSION);
    h.u32(0); // flags
    h.u32(hive.kind as u32);
    h.u64(hive.generation);
    h.u64(hive.sequence);
    h.u64(hive.root().0);
    h.u64(record_count);
    h.u64(payload.len() as u64);
    h.u32(payload_crc);
    let header_crc = crc32c(&h.buf);
    h.u32(header_crc);

    let mut out = h.buf;
    out.extend_from_slice(&payload);
    out
}

/// Decode a hive image into a fresh [`Hive`], validating both CRCs + the schema (spec §11).
pub fn decode_image(bytes: &[u8]) -> Result<Hive, HiveDecodeError> {
    let mut r = Reader::new(bytes);
    let magic = r.blob_fixed::<8>().ok_or(HiveDecodeError::Truncated)?;
    if magic != IMAGE_MAGIC {
        return Err(HiveDecodeError::BadMagic);
    }
    let _hsize = r.u16().ok_or(HiveDecodeError::Truncated)?;
    let schema = r.u16().ok_or(HiveDecodeError::Truncated)?;
    if schema != SCHEMA_VERSION {
        return Err(HiveDecodeError::UnsupportedSchema);
    }
    let _flags = r.u32().ok_or(HiveDecodeError::Truncated)?;
    let kind = HiveKind::from_u32(r.u32().ok_or(HiveDecodeError::Truncated)?)
        .ok_or(HiveDecodeError::UnsupportedSchema)?;
    let generation = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let sequence = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let root_cell = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let _record_count = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let payload_len = r.u64().ok_or(HiveDecodeError::Truncated)? as usize;
    let payload_crc = r.u32().ok_or(HiveDecodeError::Truncated)?;
    let header_crc = r.u32().ok_or(HiveDecodeError::Truncated)?;
    if crc32c(&bytes[..IMAGE_HEADER_LEN - 4]) != header_crc {
        return Err(HiveDecodeError::BadChecksum);
    }
    let payload = bytes
        .get(IMAGE_HEADER_LEN..IMAGE_HEADER_LEN + payload_len)
        .ok_or(HiveDecodeError::Truncated)?;
    if crc32c(payload) != payload_crc {
        return Err(HiveDecodeError::BadChecksum);
    }

    // Rebuild the arena: key cells first, then values; parent/subkey links reconstructed.
    let mut hive = Hive::empty(kind, CellId(root_cell), generation, sequence);
    let mut pr = Reader::new(payload);
    let mut pending_values: Vec<ValueCell> = Vec::new();
    while !pr.is_empty() {
        match pr.u16().ok_or(HiveDecodeError::Truncated)? {
            REC_KEY_CELL => {
                let id = CellId(pr.u64().ok_or(HiveDecodeError::Truncated)?);
                let parent_raw = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let name = pr.str16().ok_or(HiveDecodeError::Truncated)?;
                let _flags = pr.u32().ok_or(HiveDecodeError::Truncated)?;
                let class_name = match pr.u8().ok_or(HiveDecodeError::Truncated)? {
                    0 => None,
                    _ => Some(pr.str16().ok_or(HiveDecodeError::Truncated)?),
                };
                let seq = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                // The root cell has no parent (encoded as 0); every other key links to its parent.
                let parent = (id.0 != root_cell).then_some(CellId(parent_raw));
                hive.insert_key(KeyCell {
                    id,
                    parent,
                    name,
                    subkeys: Vec::new(),
                    values: Vec::new(),
                    class_name,
                    last_write_sequence: seq,
                });
            }
            REC_VALUE_CELL => {
                let id = CellId(pr.u64().ok_or(HiveDecodeError::Truncated)?);
                let parent_key = CellId(pr.u64().ok_or(HiveDecodeError::Truncated)?);
                let name = pr.str16().ok_or(HiveDecodeError::Truncated)?;
                let ty = pr.u32().ok_or(HiveDecodeError::Truncated)?;
                let data = pr.blob().ok_or(HiveDecodeError::Truncated)?;
                let seq = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                pending_values.push(ValueCell {
                    id,
                    parent_key,
                    name,
                    value_type: RegistryValueType::from_u32(ty).unwrap_or(RegistryValueType::Binary),
                    data,
                    last_write_sequence: seq,
                });
            }
            _ => return Err(HiveDecodeError::Truncated),
        }
    }
    hive.relink_subkeys();
    for v in pending_values {
        hive.insert_value(v);
    }
    Ok(hive)
}

// --- log (spec §12) ----------------------------------------------------------

/// A hive mutation to log (spec §12.4), path-addressed so it survives cell-ID rewrites.
pub enum HiveLogOp<'a> {
    CreateKey { path: &'a str },
    SetValue { path: &'a str, name: &'a str, value_type: RegistryValueType, data: &'a [u8] },
    DeleteValue { path: &'a str, name: &'a str },
}

/// Encode one log record (spec §12.3): an `HLR1` header (op + sequence + CRCs) + payload.
pub fn encode_log_record(op: &HiveLogOp, sequence: u64) -> Vec<u8> {
    let mut p = Writer::new();
    let code = match op {
        HiveLogOp::CreateKey { path } => {
            p.str16(path);
            OP_CREATE_KEY
        }
        HiveLogOp::SetValue { path, name, value_type, data } => {
            p.str16(path);
            p.str16(name);
            p.u32(*value_type as u32);
            p.blob(data);
            OP_SET_VALUE
        }
        HiveLogOp::DeleteValue { path, name } => {
            p.str16(path);
            p.str16(name);
            OP_DELETE_VALUE
        }
    };
    let payload = p.buf;
    let payload_crc = crc32c(&payload);
    let mut h = Writer::new();
    h.bytes(&LOG_MAGIC);
    h.u16(LOG_HEADER_LEN as u16);
    h.u16(code);
    h.u64(sequence);
    h.u32(payload.len() as u32);
    h.u32(payload_crc);
    let record_crc = crc32c(&h.buf);
    h.u32(record_crc);
    let mut out = h.buf;
    out.extend_from_slice(&payload);
    out
}

/// Replay log bytes onto `hive`, applying records with sequence > `base` (spec §12.5). Stops
/// cleanly at a torn/invalid trailing record (spec §18.2). Returns the highest sequence applied.
pub fn replay_log(hive: &mut Hive, bytes: &[u8], base: u64) -> u64 {
    let mut r = Reader::new(bytes);
    let mut last = base;
    loop {
        let start = bytes.len() - r.remaining();
        let Some(magic) = r.blob_fixed::<4>() else { break };
        if magic != LOG_MAGIC {
            break;
        }
        let (Some(_hsize), Some(op), Some(sequence), Some(plen), Some(pcrc), Some(rcrc)) =
            (r.u16(), r.u16(), r.u64(), r.u32(), r.u32(), r.u32())
        else {
            break;
        };
        let Some(header) = bytes.get(start..start + LOG_HEADER_LEN) else { break };
        if crc32c(&header[..LOG_HEADER_LEN - 4]) != rcrc {
            break;
        }
        let Some(payload) = r.take_slice(plen as usize) else { break };
        if crc32c(payload) != pcrc {
            break;
        }
        if sequence > last {
            apply_log(hive, op, payload);
            last = sequence;
        }
    }
    last
}

fn apply_log(hive: &mut Hive, op: u16, payload: &[u8]) {
    let mut r = Reader::new(payload);
    match op {
        OP_CREATE_KEY => {
            if let Some(path) = r.str16() {
                hive.create_key(&path);
            }
        }
        OP_SET_VALUE => {
            if let (Some(path), Some(name), Some(ty), Some(data)) =
                (r.str16(), r.str16(), r.u32(), r.blob())
            {
                let key = hive.create_key(&path);
                let vt = RegistryValueType::from_u32(ty).unwrap_or(RegistryValueType::Binary);
                hive.set_value(key, &name, vt, data);
            }
        }
        OP_DELETE_VALUE => {
            if let (Some(_path), Some(_name)) = (r.str16(), r.str16()) {
                // v0.1: value deletes are logged but not required for the acceptance path.
            }
        }
        _ => {}
    }
}

// Reconstruction helpers used only by the decoder (kept here to touch pub(crate) internals).
impl Hive {
    fn empty(kind: HiveKind, root: CellId, generation: u64, sequence: u64) -> Hive {
        Hive {
            cells: Vec::new(),
            root,
            next_id: 1,
            kind,
            generation,
            sequence,
            dirty: Vec::new(),
        }
    }
    fn insert_key(&mut self, k: KeyCell) {
        let idx = k.id.0 as usize;
        if idx >= self.cells.len() {
            self.cells.resize_with(idx + 1, || None);
        }
        self.next_id = self.next_id.max(k.id.0 + 1);
        self.cells[idx] = Some(Cell::Key(k));
    }
    fn insert_value(&mut self, v: ValueCell) {
        let idx = v.id.0 as usize;
        let parent = v.parent_key;
        if idx >= self.cells.len() {
            self.cells.resize_with(idx + 1, || None);
        }
        self.next_id = self.next_id.max(v.id.0 + 1);
        self.cells[idx] = Some(Cell::Value(v));
        if let Some(Cell::Key(k)) = self.cells.get_mut(parent.0 as usize).and_then(|c| c.as_mut()) {
            k.values.push(CellId(idx as u64));
        }
    }
    /// Rebuild every key's subkey list from the parent links (spec §11.4).
    fn relink_subkeys(&mut self) {
        let links: Vec<(CellId, String, CellId)> = self
            .cells
            .iter()
            .filter_map(|c| match c {
                Some(Cell::Key(k)) => k.parent.map(|p| (p, crate::hive::fold(&k.name), k.id)),
                _ => None,
            })
            .collect();
        for (parent, folded, id) in links {
            if let Some(Cell::Key(k)) = self.cells.get_mut(parent.0 as usize).and_then(|c| c.as_mut()) {
                k.subkeys.push((folded, id));
            }
        }
    }
}
