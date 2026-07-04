//! # `nt-config-store` — Configuration Manager persistence (hive store)
//!
//! Durable storage for the Configuration Manager (spec: NT Configuration Manager Persistence):
//! a versioned, CRC-32C-checksummed binary **snapshot** of the whole configuration ([`snapshot`]),
//! an append-only **journal** of runtime mutations with idempotent replay ([`journal`]), and the
//! boot / compaction engine ([`Persistence`]) over a [`ConfigManager`], behind a [`ConfigStore`]
//! backend. The wire format is explicit TLV (never Rust struct layout), little-endian, UTF-16LE
//! strings, and every read is bounds-checked — safe to parse from untrusted bytes. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

mod codec;
mod store;

use alloc::vec::Vec;

use nt_config_manager::{ConfigManager, DevPropKey, PropertyValue, RegistryValueType};

pub use codec::crc32c;
pub use store::{ConfigStore, Durability, FaultStore, MemoryStore, StoreError, StoreLock};

use codec::{Reader, Writer};

const SNAPSHOT_MAGIC: [u8; 8] = *b"USNTCM\x00\x01";
const SNAPSHOT_HEADER_LEN: u16 = 8 + 2 + 2 + 4 + 8 + 8 + 8 + 8 + 4 + 4; // 56
const SCHEMA_VERSION: u16 = 1;

// Snapshot record types (spec §9.4).
const REC_REGISTRY_KEY: u16 = 1;
const REC_SERVICE: u16 = 3;
const REC_DEVNODE: u16 = 4;
const REC_INTERFACE: u16 = 5;
const REC_LEGACY_PROPERTY: u16 = 6;
const REC_DEVPROP: u16 = 7;

// Journal ops (spec §10.4).
const OP_REG_CREATE_KEY: u16 = 1;
const OP_REG_SET_VALUE: u16 = 3;
const OP_REG_DELETE_VALUE: u16 = 4;

const JOURNAL_REC_MAGIC: [u8; 4] = *b"CJR1";
const JOURNAL_REC_HEADER_LEN: u16 = 40; // magic(4)+hsize(2)+op(2)+flags(4)+seq(8)+txn(8)+plen(4)+pcrc(4)+rcrc(4)

/// A parsed snapshot header (spec §9.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub schema_version: u16,
    pub generation: u64,
    pub base_journal_sequence: u64,
    pub record_count: u64,
}

/// Why decoding a snapshot/journal failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BadMagic,
    BadChecksum,
    Truncated,
    UnsupportedSchema,
}

// --- snapshot -----------------------------------------------------------------

/// Snapshot codec (spec §9).
pub mod snapshot {
    use super::*;

    fn write_property_value(w: &mut Writer, v: &PropertyValue) {
        w.u32(v.prop_type);
        w.blob(&v.data);
    }

    /// Serialize the full configuration to a versioned, checksummed snapshot (spec §9). Records
    /// are emitted structure-first (service/devnode/interface/property) then the whole registry
    /// tree, so a restore rebuilds records then overlays every registry value.
    pub fn encode(cm: &ConfigManager, generation: u64, base_journal_sequence: u64) -> Vec<u8> {
        let mut p = Writer::new();
        let mut record_count = 0u64;

        for s in cm.services() {
            p.u16(REC_SERVICE);
            p.str16(&s.name);
            p.str16(&s.image_path);
            opt_str(&mut p, s.class.as_deref());
            opt_str(&mut p, s.class_guid.as_deref());
            p.u32(s.start_type);
            p.u32(s.error_control);
            record_count += 1;
        }
        for d in cm.devnodes() {
            p.u16(REC_DEVNODE);
            p.str16(&d.instance_id);
            opt_str(&mut p, d.service.as_deref());
            opt_str(&mut p, d.pdo_name.as_deref());
            p.u32(d.hardware_ids.len() as u32);
            for h in &d.hardware_ids {
                p.str16(h);
            }
            p.u32(d.compatible_ids.len() as u32);
            for c in &d.compatible_ids {
                p.str16(c);
            }
            record_count += 1;

            for (ord, v) in d.properties.legacy_entries() {
                p.u16(REC_LEGACY_PROPERTY);
                p.str16(&d.instance_id);
                p.u32(*ord);
                write_property_value(&mut p, v);
                record_count += 1;
            }
            for (key, v) in d.properties.devprop_entries() {
                p.u16(REC_DEVPROP);
                p.str16(&d.instance_id);
                p.bytes(&key.fmtid);
                p.u32(key.pid);
                write_property_value(&mut p, v);
                record_count += 1;
            }
        }
        for i in cm.interfaces() {
            let instance = cm
                .devnodes()
                .iter()
                .find(|d| d.id == i.devnode)
                .map(|d| d.instance_id.as_str())
                .unwrap_or("");
            p.u16(REC_INTERFACE);
            p.str16(instance);
            p.str16(&i.guid);
            p.str16(&i.reference);
            p.u8(i.enabled as u8);
            record_count += 1;
        }
        // The full registry tree (all keys + values, parents first).
        for (path, volatile, values) in cm.registry().snapshot_keys() {
            p.u16(REC_REGISTRY_KEY);
            p.u8(volatile as u8);
            p.str16(&path);
            p.u32(values.len() as u32);
            for v in &values {
                p.str16(&v.name);
                p.u32(v.value_type as u32);
                p.blob(&v.data);
            }
            record_count += 1;
        }

        let payload = p.buf;
        let payload_crc = crc32c(&payload);

        let mut h = Writer::new();
        h.bytes(&SNAPSHOT_MAGIC);
        h.u16(SNAPSHOT_HEADER_LEN);
        h.u16(SCHEMA_VERSION);
        h.u32(0); // flags
        h.u64(generation);
        h.u64(base_journal_sequence);
        h.u64(record_count);
        h.u64(payload.len() as u64);
        h.u32(payload_crc);
        let header_crc = crc32c(&h.buf);
        h.u32(header_crc);

        let mut out = h.buf;
        out.extend_from_slice(&payload);
        out
    }

    /// Parse + validate a snapshot header (spec §18 step 3).
    pub fn parse_header(bytes: &[u8]) -> Result<SnapshotInfo, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.blob_fixed::<8>().ok_or(DecodeError::Truncated)?;
        if magic != SNAPSHOT_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let _header_size = r.u16().ok_or(DecodeError::Truncated)?;
        let schema_version = r.u16().ok_or(DecodeError::Truncated)?;
        if schema_version != SCHEMA_VERSION {
            return Err(DecodeError::UnsupportedSchema);
        }
        let _flags = r.u32().ok_or(DecodeError::Truncated)?;
        let generation = r.u64().ok_or(DecodeError::Truncated)?;
        let base_journal_sequence = r.u64().ok_or(DecodeError::Truncated)?;
        let record_count = r.u64().ok_or(DecodeError::Truncated)?;
        let payload_len = r.u64().ok_or(DecodeError::Truncated)? as usize;
        let payload_crc = r.u32().ok_or(DecodeError::Truncated)?;
        let header_crc = r.u32().ok_or(DecodeError::Truncated)?;
        // Header CRC covers everything up to the header_crc field itself.
        if crc32c(&bytes[..SNAPSHOT_HEADER_LEN as usize - 4]) != header_crc {
            return Err(DecodeError::BadChecksum);
        }
        let payload = bytes
            .get(SNAPSHOT_HEADER_LEN as usize..SNAPSHOT_HEADER_LEN as usize + payload_len)
            .ok_or(DecodeError::Truncated)?;
        if crc32c(payload) != payload_crc {
            return Err(DecodeError::BadChecksum);
        }
        Ok(SnapshotInfo {
            schema_version,
            generation,
            base_journal_sequence,
            record_count,
        })
    }

    /// Decode a snapshot into a fresh [`ConfigManager`] (spec §18 steps 3-5).
    pub fn decode(bytes: &[u8]) -> Result<ConfigManager, DecodeError> {
        parse_header(bytes)?;
        let payload = &bytes[SNAPSHOT_HEADER_LEN as usize..];
        let mut r = Reader::new(payload);
        let mut cm = ConfigManager::new();
        while !r.is_empty() {
            let rec = r.u16().ok_or(DecodeError::Truncated)?;
            match rec {
                REC_SERVICE => {
                    let name = r.str16().ok_or(DecodeError::Truncated)?;
                    let image = r.str16().ok_or(DecodeError::Truncated)?;
                    let class = opt_str_read(&mut r)?;
                    let class_guid = opt_str_read(&mut r)?;
                    let start = r.u32().ok_or(DecodeError::Truncated)?;
                    let error = r.u32().ok_or(DecodeError::Truncated)?;
                    cm.register_service(
                        &name,
                        &image,
                        class.as_deref(),
                        class_guid.as_deref(),
                        start,
                        error,
                    );
                }
                REC_DEVNODE => {
                    let instance = r.str16().ok_or(DecodeError::Truncated)?;
                    let service = opt_str_read(&mut r)?;
                    let pdo = opt_str_read(&mut r)?;
                    let hw = read_str_list(&mut r)?;
                    let compat = read_str_list(&mut r)?;
                    let hw_refs: Vec<&str> = hw.iter().map(|s| s.as_str()).collect();
                    let compat_refs: Vec<&str> = compat.iter().map(|s| s.as_str()).collect();
                    cm.register_devnode(
                        &instance,
                        service.as_deref(),
                        pdo.as_deref(),
                        &hw_refs,
                        &compat_refs,
                    );
                }
                REC_INTERFACE => {
                    let instance = r.str16().ok_or(DecodeError::Truncated)?;
                    let guid = r.str16().ok_or(DecodeError::Truncated)?;
                    let reference = r.str16().ok_or(DecodeError::Truncated)?;
                    let enabled = r.u8().ok_or(DecodeError::Truncated)? != 0;
                    if let Some(dn) = cm.devnode(&instance).map(|d| d.id) {
                        cm.register_interface(dn, &guid, &reference, enabled);
                    }
                }
                REC_LEGACY_PROPERTY => {
                    let instance = r.str16().ok_or(DecodeError::Truncated)?;
                    let ord = r.u32().ok_or(DecodeError::Truncated)?;
                    let value = read_property_value(&mut r)?;
                    if let Some(dn) = cm.devnode(&instance).map(|d| d.id) {
                        cm.set_legacy_property(dn, ord, value);
                    }
                }
                REC_DEVPROP => {
                    let instance = r.str16().ok_or(DecodeError::Truncated)?;
                    let fmtid = r.blob_fixed::<16>().ok_or(DecodeError::Truncated)?;
                    let pid = r.u32().ok_or(DecodeError::Truncated)?;
                    let value = read_property_value(&mut r)?;
                    if let Some(dn) = cm.devnode(&instance).map(|d| d.id) {
                        cm.assign_devprop(dn, DevPropKey { fmtid, pid }, value);
                    }
                }
                REC_REGISTRY_KEY => {
                    let volatile = r.u8().ok_or(DecodeError::Truncated)? != 0;
                    let path = r.str16().ok_or(DecodeError::Truncated)?;
                    let key = cm.registry_mut().create_key(&path);
                    cm.registry_mut().set_volatile(key, volatile);
                    let n = r.u32().ok_or(DecodeError::Truncated)?;
                    for _ in 0..n {
                        let name = r.str16().ok_or(DecodeError::Truncated)?;
                        let ty = r.u32().ok_or(DecodeError::Truncated)?;
                        let data = r.blob().ok_or(DecodeError::Truncated)?;
                        let vt =
                            RegistryValueType::from_u32(ty).unwrap_or(RegistryValueType::Binary);
                        cm.registry_mut().set_value(key, &name, vt, data);
                    }
                }
                _ => return Err(DecodeError::Truncated), // unknown record type
            }
        }
        Ok(cm)
    }

    fn read_property_value(r: &mut Reader) -> Result<PropertyValue, DecodeError> {
        let prop_type = r.u32().ok_or(DecodeError::Truncated)?;
        let data = r.blob().ok_or(DecodeError::Truncated)?;
        Ok(PropertyValue { prop_type, data })
    }
}

// --- journal ------------------------------------------------------------------

/// Journal codec + replay (spec §10).
pub mod journal {
    use super::*;

    /// A runtime registry mutation to journal (spec §10.4). v0.1 covers the registry writes a
    /// running driver makes (e.g. `SeenByDriver`, `RuntimeValue`).
    pub enum Mutation<'a> {
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
    }

    /// Encode one journal record (spec §10.3): a `CJR1` header (op + sequence + payload CRC +
    /// record CRC) followed by the payload.
    pub fn encode_record(m: &Mutation, sequence: u64) -> Vec<u8> {
        let mut p = Writer::new();
        let op = match m {
            Mutation::CreateKey { path } => {
                p.str16(path);
                OP_REG_CREATE_KEY
            }
            Mutation::SetValue {
                path,
                name,
                value_type,
                data,
            } => {
                p.str16(path);
                p.str16(name);
                p.u32(*value_type as u32);
                p.blob(data);
                OP_REG_SET_VALUE
            }
            Mutation::DeleteValue { path, name } => {
                p.str16(path);
                p.str16(name);
                OP_REG_DELETE_VALUE
            }
        };
        let payload = p.buf;
        let payload_crc = crc32c(&payload);
        let mut h = Writer::new();
        h.bytes(&JOURNAL_REC_MAGIC); // 4
        h.u16(JOURNAL_REC_HEADER_LEN); // 2  (header size = 40)
        h.u16(op); // 2
        h.u32(0); // flags — 4
        h.u64(sequence); // 8
        h.u64(0); // transaction_id — 8
        h.u32(payload.len() as u32); // 4
        h.u32(payload_crc); // 4  → 36 bytes so far
        let record_crc = crc32c(&h.buf); // covers the 36-byte header prefix
        h.u32(record_crc); // 4  → 40-byte header
        let mut out = h.buf;
        out.extend_from_slice(&payload);
        out
    }

    /// Replay journal bytes onto `cm`, applying records whose sequence is `> base_sequence`
    /// (idempotent, spec §10.5). A torn/invalid trailing record (bad magic/CRC/length) stops
    /// replay cleanly (spec §21.2). Returns the highest sequence applied.
    pub fn replay(cm: &mut ConfigManager, bytes: &[u8], base_sequence: u64) -> u64 {
        let mut r = Reader::new(bytes);
        let mut last = base_sequence;
        loop {
            let start = bytes.len() - r.remaining();
            let Some(magic) = r.blob_fixed::<4>() else {
                break;
            };
            if magic != JOURNAL_REC_MAGIC {
                break;
            }
            let (
                Some(_hsize),
                Some(op),
                Some(_flags),
                Some(sequence),
                Some(_txn),
                Some(plen),
                Some(pcrc),
                Some(rcrc),
            ) = (
                r.u16(),
                r.u16(),
                r.u32(),
                r.u64(),
                r.u64(),
                r.u32(),
                r.u32(),
                r.u32(),
            )
            else {
                break;
            };
            // Validate the record header CRC (covers the 36-byte prefix) + that the full payload
            // is present + intact.
            let Some(header) = bytes.get(start..start + JOURNAL_REC_HEADER_LEN as usize) else {
                break;
            };
            if crc32c(&header[..36]) != rcrc {
                break;
            }
            let Some(payload) = r.take_slice(plen as usize) else {
                break;
            };
            if crc32c(payload) != pcrc {
                break;
            }
            if sequence > last {
                apply(cm, op, payload);
                last = sequence;
            }
        }
        last
    }

    fn apply(cm: &mut ConfigManager, op: u16, payload: &[u8]) {
        let mut r = Reader::new(payload);
        match op {
            OP_REG_CREATE_KEY => {
                if let Some(path) = r.str16() {
                    cm.registry_mut().create_key(&path);
                }
            }
            OP_REG_SET_VALUE => {
                if let (Some(path), Some(name), Some(ty), Some(data)) =
                    (r.str16(), r.str16(), r.u32(), r.blob())
                {
                    let key = cm.registry_mut().create_key(&path);
                    let vt = RegistryValueType::from_u32(ty).unwrap_or(RegistryValueType::Binary);
                    cm.registry_mut().set_value(key, &name, vt, data);
                }
            }
            OP_REG_DELETE_VALUE => {
                if let (Some(path), Some(name)) = (r.str16(), r.str16()) {
                    if let Some(key) = cm.registry().open_key(&path) {
                        cm.registry_mut().delete_value(key, &name);
                    }
                }
            }
            _ => {}
        }
    }
}

// --- persistence engine -------------------------------------------------------

/// The boot / mutate / compaction engine over a [`ConfigStore`] (spec §11, §18-§20).
pub struct Persistence<S: ConfigStore> {
    store: S,
    generation: u64,
    next_sequence: u64,
    base_sequence: u64,
    durability: Durability,
}

impl<S: ConfigStore> Persistence<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            generation: 0,
            next_sequence: 1,
            base_sequence: 0,
            durability: Durability::Strict,
        }
    }
    pub fn with_durability(mut self, d: Durability) -> Self {
        self.durability = d;
        self
    }

    /// Boot (spec §18): load + validate the snapshot, then replay journal records after the
    /// snapshot's base sequence. Returns the reconstructed [`ConfigManager`] (a fresh one if no
    /// snapshot exists yet — the caller then imports the fixture).
    pub fn boot(&mut self) -> Result<ConfigManager, DecodeError> {
        let _lock = self.store.lock_store();
        let mut cm = match self.store.read_snapshot().ok().flatten() {
            Some(bytes) => {
                let info = snapshot::parse_header(&bytes)?;
                self.generation = info.generation;
                self.base_sequence = info.base_journal_sequence;
                snapshot::decode(&bytes)?
            }
            None => ConfigManager::new(),
        };
        let journal = self.store.read_journal().unwrap_or_default();
        let last = journal::replay(&mut cm, &journal, self.base_sequence);
        self.next_sequence = last + 1;
        Ok(cm)
    }

    /// Journal + apply one mutation (spec §11.2): append the record (fsync in Strict mode), then
    /// apply it to `cm`. On a store fault the mutation is not applied (the memory + disk stay
    /// consistent).
    pub fn mutate(
        &mut self,
        cm: &mut ConfigManager,
        m: journal::Mutation,
    ) -> Result<(), StoreError> {
        let seq = self.next_sequence;
        let rec = journal::encode_record(&m, seq);
        self.store.append_journal_record(&rec)?;
        if self.durability == Durability::Strict {
            self.store.fsync_journal()?;
        }
        journal::replay(cm, &rec, seq - 1);
        self.next_sequence += 1;
        Ok(())
    }

    /// Compaction (spec §20 / shutdown §19): write a fresh snapshot at the current generation +
    /// truncate the journal, so boot no longer needs replay.
    pub fn compact(&mut self, cm: &ConfigManager) -> Result<(), StoreError> {
        self.generation += 1;
        self.base_sequence = self.next_sequence - 1;
        let bytes = snapshot::encode(cm, self.generation, self.base_sequence);
        self.store.write_snapshot_atomic(&bytes)?;
        self.store.fsync_snapshot()?;
        self.store.truncate_journal()?;
        self.store.fsync_journal()?;
        Ok(())
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

// --- small helpers ------------------------------------------------------------

fn opt_str(w: &mut Writer, s: Option<&str>) {
    match s {
        Some(v) => {
            w.u8(1);
            w.str16(v);
        }
        None => w.u8(0),
    }
}
fn opt_str_read(r: &mut Reader) -> Result<Option<alloc::string::String>, DecodeError> {
    match r.u8().ok_or(DecodeError::Truncated)? {
        0 => Ok(None),
        _ => Ok(Some(r.str16().ok_or(DecodeError::Truncated)?)),
    }
}
fn read_str_list(r: &mut Reader) -> Result<Vec<alloc::string::String>, DecodeError> {
    let n = r.u32().ok_or(DecodeError::Truncated)?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(r.str16().ok_or(DecodeError::Truncated)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
