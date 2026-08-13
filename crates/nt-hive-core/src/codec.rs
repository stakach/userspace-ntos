//! Hive image + log codecs (spec §11-§12). Versioned, checksummed, explicit TLV (never Rust
//! struct layout), reusing the `nt-config-store` byte primitives + CRC-32C.

use alloc::vec::Vec;

use nt_config_store::codec::{crc32c, Reader, Writer};

use crate::hive::{Cell, CellId, Hive, HiveKind, KeyCell, RegistryValueType, ValueCell};

const IMAGE_MAGIC: [u8; 8] = *b"UNTHIVE1";
const IMAGE_HEADER_LEN: usize = 8 + 2 + 2 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 4 + 4; // 68
const MIN_SCHEMA_VERSION: u16 = 1;
const SCHEMA_VERSION: u16 = 2;

const REC_KEY_CELL: u16 = 1;
const REC_VALUE_CELL: u16 = 2;

const LOG_MAGIC: [u8; 4] = *b"HLR1";
const LOG_HEADER_LEN: usize = 4 + 2 + 2 + 8 + 4 + 4 + 4; // 28
const OP_CREATE_KEY: u16 = 1;
const OP_SET_VALUE: u16 = 2;
const OP_DELETE_VALUE: u16 = 3;
const OP_DELETE_KEY: u16 = 4;
const OP_SET_KEY_CLASS: u16 = 5;
const OP_SET_KEY_SECURITY_DESCRIPTOR: u16 = 6;

/// Why decoding a hive image/log failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveDecodeError {
    BadMagic,
    BadChecksum,
    Truncated,
    UnsupportedSchema,
}

/// Why encoding a hive image failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HiveEncodeError {
    SizeOverflow,
    OutOfMemory,
}

// --- image (spec §11) --------------------------------------------------------

/// Serialize a hive to a versioned, checksummed image (spec §11).
pub fn encode_image(hive: &Hive) -> Vec<u8> {
    try_encode_image(hive).expect("hive image encode failed")
}

/// Serialize a hive to a versioned, checksummed image without panicking on allocation failure.
pub fn try_encode_image(hive: &Hive) -> Result<Vec<u8>, HiveEncodeError> {
    let mut record_count = 0u64;
    let root = hive.root();
    let payload_len = image_payload_len(hive)?;
    let total_len = encoded_image_len(hive)?;
    let mut p = CheckedWriter::with_capacity(total_len)?;
    p.bytes(&[0u8; IMAGE_HEADER_LEN]);
    for k in hive.key_cells() {
        p.u16(REC_KEY_CELL);
        p.u64(k.id.0);
        p.u64(k.parent.unwrap_or(CellId(0)).0);
        p.str16(&k.name);
        p.u32(0); // flags
        match &k.class_name {
            Some(c) => {
                p.u8(1);
                p.str16(c);
            }
            None => p.u8(0),
        }
        match &k.security_descriptor {
            Some(descriptor) => {
                p.u8(1);
                p.blob(descriptor);
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
        p.blob(hive.value_data(v).unwrap_or(&[]));
        p.u64(v.last_write_sequence);
        record_count += 1;
    }
    debug_assert_eq!(p.buf.len(), total_len);
    let payload_crc = crc32c(&p.buf[IMAGE_HEADER_LEN..]);

    let mut header = [0u8; IMAGE_HEADER_LEN];
    header[..IMAGE_MAGIC.len()].copy_from_slice(&IMAGE_MAGIC);
    put_u16_at(&mut header[8..10], IMAGE_HEADER_LEN as u16);
    put_u16_at(&mut header[10..12], SCHEMA_VERSION);
    put_u32_at(&mut header[12..16], 0); // flags
    put_u32_at(&mut header[16..20], hive.kind as u32);
    put_u64_at(&mut header[20..28], hive.generation);
    put_u64_at(&mut header[28..36], hive.sequence);
    put_u64_at(&mut header[36..44], root.0);
    put_u64_at(&mut header[44..52], record_count);
    put_u64_at(&mut header[52..60], payload_len as u64);
    put_u32_at(&mut header[60..64], payload_crc);
    let header_crc = crc32c(&header[..IMAGE_HEADER_LEN - 4]);
    put_u32_at(&mut header[64..68], header_crc);
    p.buf[..IMAGE_HEADER_LEN].copy_from_slice(&header);
    Ok(p.buf)
}

/// Exact byte length [`try_encode_image`] will allocate for a hive image, without materialising it.
pub fn encoded_image_len(hive: &Hive) -> Result<usize, HiveEncodeError> {
    IMAGE_HEADER_LEN
        .checked_add(image_payload_len(hive)?)
        .ok_or(HiveEncodeError::SizeOverflow)
}

struct CheckedWriter {
    buf: Vec<u8>,
}

impl CheckedWriter {
    fn with_capacity(capacity: usize) -> Result<Self, HiveEncodeError> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(capacity)
            .map_err(|_| HiveEncodeError::OutOfMemory)?;
        Ok(Self { buf })
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    fn blob(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.bytes(b);
    }

    fn str16(&mut self, s: &str) {
        let byte_len = s.encode_utf16().count() * 2;
        self.u32(byte_len as u32);
        for unit in s.encode_utf16() {
            self.u16(unit);
        }
    }
}

fn image_payload_len(hive: &Hive) -> Result<usize, HiveEncodeError> {
    let mut len = 0usize;
    for key in hive.key_cells() {
        len = checked_add(len, key_record_len(key)?)?;
    }
    for value in hive.value_cells() {
        len = checked_add(len, value_record_len(hive, value)?)?;
    }
    Ok(len)
}

fn key_record_len(key: &KeyCell) -> Result<usize, HiveEncodeError> {
    let mut len = 2usize + 8 + 8;
    len = checked_add(len, str16_record_len(&key.name)?)?;
    len = checked_add(len, 4 + 1)?;
    if let Some(class_name) = &key.class_name {
        len = checked_add(len, str16_record_len(class_name)?)?;
    }
    len = checked_add(len, 1)?;
    if let Some(descriptor) = &key.security_descriptor {
        len = checked_add(len, blob_record_len(descriptor.len())?)?;
    }
    checked_add(len, 8)
}

fn value_record_len(hive: &Hive, value: &ValueCell) -> Result<usize, HiveEncodeError> {
    let mut len = 2usize + 8 + 8;
    len = checked_add(len, str16_record_len(&value.name)?)?;
    len = checked_add(len, 4)?;
    len = checked_add(
        len,
        blob_record_len(hive.value_data(value).unwrap_or(&[]).len())?,
    )?;
    checked_add(len, 8)
}

fn str16_record_len(s: &str) -> Result<usize, HiveEncodeError> {
    let units = s.encode_utf16().count();
    let bytes = units.checked_mul(2).ok_or(HiveEncodeError::SizeOverflow)?;
    if bytes > u32::MAX as usize {
        return Err(HiveEncodeError::SizeOverflow);
    }
    checked_add(4, bytes)
}

fn blob_record_len(bytes: usize) -> Result<usize, HiveEncodeError> {
    if bytes > u32::MAX as usize {
        return Err(HiveEncodeError::SizeOverflow);
    }
    checked_add(4, bytes)
}

fn checked_add(a: usize, b: usize) -> Result<usize, HiveEncodeError> {
    a.checked_add(b).ok_or(HiveEncodeError::SizeOverflow)
}

fn put_u16_at(out: &mut [u8], v: u16) {
    out.copy_from_slice(&v.to_le_bytes());
}

fn put_u32_at(out: &mut [u8], v: u32) {
    out.copy_from_slice(&v.to_le_bytes());
}

fn put_u64_at(out: &mut [u8], v: u64) {
    out.copy_from_slice(&v.to_le_bytes());
}

fn compact_cell_id(map: &[(CellId, CellId)], raw: CellId) -> Option<CellId> {
    map.iter()
        .find(|(existing, _)| *existing == raw)
        .map(|(_, mapped)| *mapped)
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
    if !(MIN_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&schema) {
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

    // Rebuild the arena with compact CellIds. Older images can contain REGF cell offsets as
    // CellIds; preserving them would inflate the restored `Vec<Option<Cell>>` into a sparse arena.
    let mut hive = Hive::empty(kind, CellId(0), generation, sequence);
    let mut id_map: Vec<(CellId, CellId)> = Vec::new();
    let mut next_id = 0u64;
    map_decoded_cell_id(&mut id_map, CellId(root_cell), &mut next_id);
    let mut pr = Reader::new(payload);
    while !pr.is_empty() {
        match pr.u16().ok_or(HiveDecodeError::Truncated)? {
            REC_KEY_CELL => {
                let raw_id = CellId(pr.u64().ok_or(HiveDecodeError::Truncated)?);
                let parent_raw = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let name = pr.str16().ok_or(HiveDecodeError::Truncated)?;
                let _flags = pr.u32().ok_or(HiveDecodeError::Truncated)?;
                let class_name = match pr.u8().ok_or(HiveDecodeError::Truncated)? {
                    0 => None,
                    _ => Some(pr.str16().ok_or(HiveDecodeError::Truncated)?),
                };
                let security_descriptor = if schema >= 2 {
                    match pr.u8().ok_or(HiveDecodeError::Truncated)? {
                        0 => None,
                        _ => Some(pr.blob().ok_or(HiveDecodeError::Truncated)?),
                    }
                } else {
                    None
                };
                let seq = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let id = map_decoded_cell_id(&mut id_map, raw_id, &mut next_id);
                // The root cell has no parent (encoded as 0); every other key links to its parent.
                let parent = (raw_id.0 != root_cell)
                    .then(|| map_decoded_cell_id(&mut id_map, CellId(parent_raw), &mut next_id));
                hive.insert_key(KeyCell {
                    id,
                    parent,
                    name,
                    subkeys: Vec::new(),
                    values: Vec::new(),
                    class_name,
                    security_descriptor,
                    last_write_sequence: seq,
                });
            }
            REC_VALUE_CELL => {
                let raw_id = CellId(pr.u64().ok_or(HiveDecodeError::Truncated)?);
                let raw_parent_key = CellId(pr.u64().ok_or(HiveDecodeError::Truncated)?);
                let name = pr.str16().ok_or(HiveDecodeError::Truncated)?;
                let ty = pr.u32().ok_or(HiveDecodeError::Truncated)?;
                let data = pr.blob().ok_or(HiveDecodeError::Truncated)?;
                let seq = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let Some(parent_key) = compact_cell_id(&id_map, raw_parent_key) else {
                    return Err(HiveDecodeError::Truncated);
                };
                let id = map_decoded_cell_id(&mut id_map, raw_id, &mut next_id);
                let data_blob = hive.intern_value_data(data);
                hive.insert_value(ValueCell {
                    id,
                    parent_key,
                    name,
                    value_type: RegistryValueType::from_u32(ty)
                        .unwrap_or(RegistryValueType::Binary),
                    data_blob,
                    last_write_sequence: seq,
                });
            }
            _ => return Err(HiveDecodeError::Truncated),
        }
    }
    hive.relink_subkeys();
    Ok(hive)
}

/// Validate a hive image header and payload checksum without materialising a [`Hive`].
///
/// Storage and checkpoint scheduling sometimes only need to know whether a byte slice is a valid
/// mutable-hive checkpoint and how long it is. This follows the fixed-header, schema, kind,
/// header-CRC, payload-bounds, and payload-CRC checks used by [`decode_image`] without allocating
/// the registry cell arena.
pub fn image_len_if_valid(bytes: &[u8]) -> Result<usize, HiveDecodeError> {
    let mut r = Reader::new(bytes);
    let magic = r.blob_fixed::<8>().ok_or(HiveDecodeError::Truncated)?;
    if magic != IMAGE_MAGIC {
        return Err(HiveDecodeError::BadMagic);
    }
    let header_len = r.u16().ok_or(HiveDecodeError::Truncated)? as usize;
    if header_len != IMAGE_HEADER_LEN || bytes.len() < IMAGE_HEADER_LEN {
        return Err(HiveDecodeError::Truncated);
    }
    let schema = r.u16().ok_or(HiveDecodeError::Truncated)?;
    if !(MIN_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&schema) {
        return Err(HiveDecodeError::UnsupportedSchema);
    }
    let _flags = r.u32().ok_or(HiveDecodeError::Truncated)?;
    let _kind = HiveKind::from_u32(r.u32().ok_or(HiveDecodeError::Truncated)?)
        .ok_or(HiveDecodeError::UnsupportedSchema)?;
    let _generation = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let _sequence = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let _root_cell = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let _record_count = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let payload_len64 = r.u64().ok_or(HiveDecodeError::Truncated)?;
    if payload_len64 > usize::MAX as u64 {
        return Err(HiveDecodeError::Truncated);
    }
    let payload_len = payload_len64 as usize;
    let payload_crc = r.u32().ok_or(HiveDecodeError::Truncated)?;
    let header_crc = r.u32().ok_or(HiveDecodeError::Truncated)?;
    if crc32c(&bytes[..IMAGE_HEADER_LEN - 4]) != header_crc {
        return Err(HiveDecodeError::BadChecksum);
    }
    let image_len = IMAGE_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(HiveDecodeError::Truncated)?;
    let payload = bytes
        .get(IMAGE_HEADER_LEN..image_len)
        .ok_or(HiveDecodeError::Truncated)?;
    if crc32c(payload) != payload_crc {
        return Err(HiveDecodeError::BadChecksum);
    }
    Ok(bytes.len())
}

fn take_len_prefixed_slice<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], HiveDecodeError> {
    let len = r.u32().ok_or(HiveDecodeError::Truncated)? as usize;
    r.take_slice(len).ok_or(HiveDecodeError::Truncated)
}

fn utf16le_ascii_eq_ignore_case(encoded: &[u8], ascii: &str) -> bool {
    fn ascii_fold(byte: u8) -> u8 {
        match byte {
            b'A'..=b'Z' => byte + (b'a' - b'A'),
            _ => byte,
        }
    }

    if encoded.len() != ascii.len().saturating_mul(2) {
        return false;
    }
    encoded
        .chunks_exact(2)
        .zip(ascii.bytes())
        .all(|(unit, want)| unit[1] == 0 && ascii_fold(unit[0]) == ascii_fold(want))
}

fn path_component_count(path: &str) -> usize {
    path.split('\\')
        .filter(|component| !component.is_empty())
        .count()
}

fn path_component(path: &str, index: usize) -> Option<&str> {
    path.split('\\')
        .filter(|component| !component.is_empty())
        .nth(index)
}

/// Return a value's byte length from a valid core hive image without materialising the hive arena.
///
/// Gate/proof code often only needs a content witness late in boot, when the executive bump heap is
/// intentionally close to full. This follows the same image checksum validation as [`decode_image`]
/// and then walks the key/value records in place.
pub fn image_value_len_if_valid(
    bytes: &[u8],
    key_path: &str,
    value_name: &str,
) -> Result<usize, HiveDecodeError> {
    let mut r = Reader::new(bytes);
    let magic = r.blob_fixed::<8>().ok_or(HiveDecodeError::Truncated)?;
    if magic != IMAGE_MAGIC {
        return Err(HiveDecodeError::BadMagic);
    }
    let header_len = r.u16().ok_or(HiveDecodeError::Truncated)? as usize;
    if header_len != IMAGE_HEADER_LEN || bytes.len() < IMAGE_HEADER_LEN {
        return Err(HiveDecodeError::Truncated);
    }
    let schema = r.u16().ok_or(HiveDecodeError::Truncated)?;
    if !(MIN_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&schema) {
        return Err(HiveDecodeError::UnsupportedSchema);
    }
    let _flags = r.u32().ok_or(HiveDecodeError::Truncated)?;
    let _kind = HiveKind::from_u32(r.u32().ok_or(HiveDecodeError::Truncated)?)
        .ok_or(HiveDecodeError::UnsupportedSchema)?;
    let _generation = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let _sequence = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let root_cell = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let _record_count = r.u64().ok_or(HiveDecodeError::Truncated)?;
    let payload_len64 = r.u64().ok_or(HiveDecodeError::Truncated)?;
    if payload_len64 > usize::MAX as u64 {
        return Err(HiveDecodeError::Truncated);
    }
    let payload_len = payload_len64 as usize;
    let payload_crc = r.u32().ok_or(HiveDecodeError::Truncated)?;
    let header_crc = r.u32().ok_or(HiveDecodeError::Truncated)?;
    if crc32c(&bytes[..IMAGE_HEADER_LEN - 4]) != header_crc {
        return Err(HiveDecodeError::BadChecksum);
    }
    let image_len = IMAGE_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(HiveDecodeError::Truncated)?;
    let payload = bytes
        .get(IMAGE_HEADER_LEN..image_len)
        .ok_or(HiveDecodeError::Truncated)?;
    if crc32c(payload) != payload_crc {
        return Err(HiveDecodeError::BadChecksum);
    }

    const PREFIX_MATCH_CAP: usize = 64;
    let target_depth = path_component_count(key_path);
    let mut prefix_matches = [(0u64, 0usize); PREFIX_MATCH_CAP];
    let mut prefix_len = 1usize;
    prefix_matches[0] = (root_cell, 0);
    let mut target_key = if target_depth == 0 {
        Some(root_cell)
    } else {
        None
    };

    let mut pr = Reader::new(payload);
    while !pr.is_empty() {
        match pr.u16().ok_or(HiveDecodeError::Truncated)? {
            REC_KEY_CELL => {
                let raw_id = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let parent_raw = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let name = take_len_prefixed_slice(&mut pr)?;
                let _flags = pr.u32().ok_or(HiveDecodeError::Truncated)?;
                match pr.u8().ok_or(HiveDecodeError::Truncated)? {
                    0 => {}
                    _ => {
                        let _ = take_len_prefixed_slice(&mut pr)?;
                    }
                }
                if schema >= 2 {
                    match pr.u8().ok_or(HiveDecodeError::Truncated)? {
                        0 => {}
                        _ => {
                            let _ = take_len_prefixed_slice(&mut pr)?;
                        }
                    }
                }
                let _seq = pr.u64().ok_or(HiveDecodeError::Truncated)?;

                if raw_id == root_cell {
                    continue;
                }
                let parent_depth = prefix_matches[..prefix_len]
                    .iter()
                    .find(|(id, depth)| *id == parent_raw && *depth < target_depth)
                    .map(|(_, depth)| *depth);
                let Some(parent_depth) = parent_depth else {
                    continue;
                };
                let Some(component) = path_component(key_path, parent_depth) else {
                    continue;
                };
                if !utf16le_ascii_eq_ignore_case(name, component) {
                    continue;
                }
                let depth = parent_depth + 1;
                if depth == target_depth {
                    target_key = Some(raw_id);
                }
                if depth < target_depth && prefix_len < PREFIX_MATCH_CAP {
                    prefix_matches[prefix_len] = (raw_id, depth);
                    prefix_len += 1;
                }
            }
            REC_VALUE_CELL => {
                let _raw_id = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let raw_parent_key = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                let name = take_len_prefixed_slice(&mut pr)?;
                let _ty = pr.u32().ok_or(HiveDecodeError::Truncated)?;
                let data = take_len_prefixed_slice(&mut pr)?;
                let _seq = pr.u64().ok_or(HiveDecodeError::Truncated)?;
                if target_key == Some(raw_parent_key)
                    && utf16le_ascii_eq_ignore_case(name, value_name)
                {
                    return Ok(data.len());
                }
            }
            _ => return Err(HiveDecodeError::Truncated),
        }
    }
    Ok(0)
}

fn map_decoded_cell_id(map: &mut Vec<(CellId, CellId)>, raw: CellId, next: &mut u64) -> CellId {
    if let Some(mapped) = compact_cell_id(map, raw) {
        return mapped;
    }
    let mapped = CellId(*next);
    *next = next.saturating_add(1);
    map.push((raw, mapped));
    mapped
}

// --- log (spec §12) ----------------------------------------------------------

/// A hive mutation to log (spec §12.4), path-addressed so it survives cell-ID rewrites.
pub enum HiveLogOp<'a> {
    CreateKey {
        path: &'a str,
    },
    SetValue {
        path: &'a str,
        name: &'a str,
        value_type: RegistryValueType,
        data: &'a [u8],
    },
    DeleteValue {
        path: &'a str,
        name: &'a str,
    },
    DeleteKey {
        path: &'a str,
    },
    SetKeyClass {
        path: &'a str,
        class_name: Option<&'a str>,
    },
    SetKeySecurityDescriptor {
        path: &'a str,
        descriptor: &'a [u8],
    },
}

/// Encode one log record (spec §12.3): an `HLR1` header (op + sequence + CRCs) + payload.
pub fn encode_log_record(op: &HiveLogOp, sequence: u64) -> Vec<u8> {
    let mut p = Writer::new();
    let code = match op {
        HiveLogOp::CreateKey { path } => {
            p.str16(path);
            OP_CREATE_KEY
        }
        HiveLogOp::SetValue {
            path,
            name,
            value_type,
            data,
        } => {
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
        HiveLogOp::DeleteKey { path } => {
            p.str16(path);
            OP_DELETE_KEY
        }
        HiveLogOp::SetKeyClass { path, class_name } => {
            p.str16(path);
            match class_name {
                Some(class_name) => {
                    p.u8(1);
                    p.str16(class_name);
                }
                None => p.u8(0),
            }
            OP_SET_KEY_CLASS
        }
        HiveLogOp::SetKeySecurityDescriptor { path, descriptor } => {
            p.str16(path);
            p.blob(descriptor);
            OP_SET_KEY_SECURITY_DESCRIPTOR
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
        let Some(magic) = r.blob_fixed::<4>() else {
            break;
        };
        if magic != LOG_MAGIC {
            break;
        }
        let (Some(_hsize), Some(op), Some(sequence), Some(plen), Some(pcrc), Some(rcrc)) =
            (r.u16(), r.u16(), r.u64(), r.u32(), r.u32(), r.u32())
        else {
            break;
        };
        let Some(header) = bytes.get(start..start + LOG_HEADER_LEN) else {
            break;
        };
        if crc32c(&header[..LOG_HEADER_LEN - 4]) != rcrc {
            break;
        }
        let Some(payload) = r.take_slice(plen as usize) else {
            break;
        };
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
            if let (Some(path), Some(name)) = (r.str16(), r.str16()) {
                if let Some(key) = hive.open_key(&path) {
                    hive.delete_value(key, &name);
                }
            }
        }
        OP_DELETE_KEY => {
            if let Some(path) = r.str16() {
                if let Some(key) = hive.open_key(&path) {
                    let _ = hive.delete_key(key);
                }
            }
        }
        OP_SET_KEY_CLASS => {
            if let (Some(path), Some(has_class)) = (r.str16(), r.u8()) {
                let class_name = if has_class != 0 { r.str16() } else { None };
                if let Some(key) = hive.open_key(&path) {
                    hive.set_key_class(key, class_name.as_deref());
                }
            }
        }
        OP_SET_KEY_SECURITY_DESCRIPTOR => {
            if let (Some(path), Some(descriptor)) = (r.str16(), r.blob()) {
                if let Some(key) = hive.open_key(&path) {
                    hive.set_key_security_descriptor(key, &descriptor);
                }
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
            value_blobs: Vec::new(),
            root,
            next_id: 1,
            kind,
            generation,
            sequence,
            clean_sequence: sequence,
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
        if let Some(Cell::Key(k)) = self
            .cells
            .get_mut(parent.0 as usize)
            .and_then(|c| c.as_mut())
        {
            k.values.push(CellId(idx as u64));
        }
    }
    /// Rebuild every key's subkey list from the parent links (spec §11.4).
    fn relink_subkeys(&mut self) {
        let links: Vec<(CellId, CellId)> = self
            .cells
            .iter()
            .filter_map(|c| match c {
                Some(Cell::Key(k)) => k.parent.map(|p| (p, k.id)),
                _ => None,
            })
            .collect();
        for (parent, id) in links {
            if let Some(Cell::Key(k)) = self
                .cells
                .get_mut(parent.0 as usize)
                .and_then(|c| c.as_mut())
            {
                k.subkeys.push(id);
            }
        }
    }
}
