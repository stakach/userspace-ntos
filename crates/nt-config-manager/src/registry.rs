//! The registry key/value tree — the Configuration Manager's core state (spec §8).
//!
//! A case-preserving, case-insensitive tree of keys, each holding named values of the v0.1
//! `REG_*` types (spec §8.3). Keys are addressed by NT path (`\Registry\Machine\…`) or by an
//! opaque [`RegistryKeyId`] handle. String data is stored as UTF-16LE bytes (the on-the-wire
//! registry encoding, spec §8.4); helpers convert to/from Rust `&str`.

use alloc::string::String;
use alloc::vec::Vec;

/// An opaque registry key handle.
pub type RegistryKeyId = u64;

/// `REG_*` value type (spec §8.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RegistryValueType {
    None = 0,
    Sz = 1,
    ExpandSz = 2,
    Binary = 3,
    Dword = 4,
    MultiSz = 7,
    Qword = 11,
}

impl RegistryValueType {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            7 => Self::MultiSz,
            11 => Self::Qword,
            _ => return None,
        })
    }
}

/// A registry value: name + `REG_*` type + raw data (spec §8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: RegistryValueType,
    pub data: Vec<u8>,
}

impl RegistryValue {
    /// Interpret as a `REG_DWORD` (4-byte LE).
    pub fn as_dword(&self) -> Option<u32> {
        if self.value_type == RegistryValueType::Dword && self.data.len() == 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }
    /// Interpret as a `REG_QWORD` (8-byte LE).
    pub fn as_qword(&self) -> Option<u64> {
        if self.value_type == RegistryValueType::Qword && self.data.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.data);
            Some(u64::from_le_bytes(b))
        } else {
            None
        }
    }
    /// Interpret as a `REG_SZ`/`REG_EXPAND_SZ` (UTF-16LE), stripping a trailing NUL.
    pub fn as_string(&self) -> Option<String> {
        matches!(
            self.value_type,
            RegistryValueType::Sz | RegistryValueType::ExpandSz
        )
        .then(|| decode_utf16le(&self.data))
    }
}

/// Encode `s` as UTF-16LE + a NUL terminator (the registry `REG_SZ` on-disk form).
pub fn encode_sz(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2 + 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

pub(crate) fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Case-insensitive registry name key (ASCII fold — registry names are ASCII in practice).
fn fold(name: &str) -> String {
    name.to_ascii_lowercase()
}

struct KeyRecord {
    id: RegistryKeyId,
    parent: Option<RegistryKeyId>,
    name: String,
    subkeys: Vec<(String, RegistryKeyId)>, // (folded name, id)
    values: Vec<RegistryValue>,
    volatile: bool,
    generation: u32,
}

/// The registry tree.
pub struct Registry {
    keys: Vec<KeyRecord>,
    next_id: RegistryKeyId,
    root: RegistryKeyId,
    next_gen: u32,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Build a registry with the required root keys created (spec §8.5).
    pub fn new() -> Self {
        let mut r = Registry {
            keys: Vec::new(),
            next_id: 1,
            root: 0,
            next_gen: 1,
        };
        // The anonymous namespace root (id 1); its children are named keys.
        r.root = r.alloc_key(None, "");
        for path in [
            r"\Registry",
            r"\Registry\Machine",
            r"\Registry\Machine\System",
            r"\Registry\Machine\System\CurrentControlSet",
            r"\Registry\Machine\System\CurrentControlSet\Services",
            r"\Registry\Machine\System\CurrentControlSet\Enum",
            r"\Registry\Machine\System\CurrentControlSet\Control",
            r"\Registry\Machine\System\CurrentControlSet\Control\DeviceClasses",
        ] {
            r.create_key(path);
        }
        r
    }

    fn alloc_key(&mut self, parent: Option<RegistryKeyId>, name: &str) -> RegistryKeyId {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.keys.push(KeyRecord {
            id,
            parent,
            name: name.into(),
            subkeys: Vec::new(),
            values: Vec::new(),
            volatile: false,
            generation,
        });
        id
    }

    fn record(&self, id: RegistryKeyId) -> Option<&KeyRecord> {
        self.keys.iter().find(|k| k.id == id)
    }
    fn record_mut(&mut self, id: RegistryKeyId) -> Option<&mut KeyRecord> {
        self.keys.iter_mut().find(|k| k.id == id)
    }

    fn components(path: &str) -> impl Iterator<Item = &str> {
        path.split('\\').filter(|c| !c.is_empty())
    }

    /// `ZwOpenKey` — resolve an NT path to a key id (`None` if absent).
    pub fn open_key(&self, path: &str) -> Option<RegistryKeyId> {
        let mut cur = self.root;
        for comp in Self::components(path) {
            cur = self.open_subkey(cur, comp)?;
        }
        Some(cur)
    }

    /// Open an immediate subkey by (case-insensitive) name.
    pub fn open_subkey(&self, parent: RegistryKeyId, name: &str) -> Option<RegistryKeyId> {
        let folded = fold(name);
        self.record(parent)?
            .subkeys
            .iter()
            .find(|(n, _)| *n == folded)
            .map(|(_, id)| *id)
    }

    /// `ZwCreateKey` — open or create the key at `path`, creating intermediate keys.
    pub fn create_key(&mut self, path: &str) -> RegistryKeyId {
        let mut cur = self.root;
        for comp in Self::components(path) {
            cur = self.create_subkey(cur, comp);
        }
        cur
    }

    /// Open or create an immediate subkey.
    pub fn create_subkey(&mut self, parent: RegistryKeyId, name: &str) -> RegistryKeyId {
        if let Some(id) = self.open_subkey(parent, name) {
            return id;
        }
        let id = self.alloc_key(Some(parent), name);
        let folded = fold(name);
        self.record_mut(parent).unwrap().subkeys.push((folded, id));
        id
    }

    pub fn key_exists(&self, id: RegistryKeyId) -> bool {
        self.record(id).is_some()
    }

    /// The full NT path of a key (`\Registry\…`).
    pub fn key_path(&self, id: RegistryKeyId) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        let mut cur = self.record(id)?;
        loop {
            if cur.parent.is_none() {
                break;
            }
            parts.push(&cur.name);
            cur = self.record(cur.parent?)?;
        }
        let mut path = String::new();
        for p in parts.iter().rev() {
            path.push('\\');
            path.push_str(p);
        }
        Some(path)
    }

    pub fn set_volatile(&mut self, id: RegistryKeyId, volatile: bool) {
        if let Some(k) = self.record_mut(id) {
            k.volatile = volatile;
        }
    }
    pub fn is_volatile(&self, id: RegistryKeyId) -> bool {
        self.record(id).map(|k| k.volatile).unwrap_or(false)
    }
    pub fn generation(&self, id: RegistryKeyId) -> Option<u32> {
        self.record(id).map(|k| k.generation)
    }

    // --- values ---------------------------------------------------------------

    /// `ZwSetValueKey` — set (create or replace) a named value on a key.
    pub fn set_value(
        &mut self,
        key: RegistryKeyId,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        let folded = fold(name);
        let Some(k) = self.record_mut(key) else {
            return false;
        };
        if let Some(v) = k.values.iter_mut().find(|v| fold(&v.name) == folded) {
            v.value_type = value_type;
            v.data = data;
        } else {
            k.values.push(RegistryValue {
                name: name.into(),
                value_type,
                data,
            });
        }
        true
    }

    pub fn set_dword(&mut self, key: RegistryKeyId, name: &str, value: u32) -> bool {
        self.set_value(
            key,
            name,
            RegistryValueType::Dword,
            value.to_le_bytes().to_vec(),
        )
    }
    pub fn set_qword(&mut self, key: RegistryKeyId, name: &str, value: u64) -> bool {
        self.set_value(
            key,
            name,
            RegistryValueType::Qword,
            value.to_le_bytes().to_vec(),
        )
    }
    pub fn set_string(&mut self, key: RegistryKeyId, name: &str, value: &str) -> bool {
        self.set_value(key, name, RegistryValueType::Sz, encode_sz(value))
    }

    /// `ZwQueryValueKey` — read a named value.
    pub fn query_value(&self, key: RegistryKeyId, name: &str) -> Option<&RegistryValue> {
        let folded = fold(name);
        self.record(key)?
            .values
            .iter()
            .find(|v| fold(&v.name) == folded)
    }
    pub fn query_dword(&self, key: RegistryKeyId, name: &str) -> Option<u32> {
        self.query_value(key, name)?.as_dword()
    }
    pub fn query_qword(&self, key: RegistryKeyId, name: &str) -> Option<u64> {
        self.query_value(key, name)?.as_qword()
    }
    pub fn query_string(&self, key: RegistryKeyId, name: &str) -> Option<String> {
        self.query_value(key, name)?.as_string()
    }

    /// `ZwDeleteValueKey`.
    pub fn delete_value(&mut self, key: RegistryKeyId, name: &str) -> bool {
        let folded = fold(name);
        let Some(k) = self.record_mut(key) else {
            return false;
        };
        let before = k.values.len();
        k.values.retain(|v| fold(&v.name) != folded);
        k.values.len() != before
    }

    /// `ZwEnumerateKey` — the immediate subkey names (case-preserved).
    pub fn enum_subkeys(&self, key: RegistryKeyId) -> Vec<String> {
        let Some(k) = self.record(key) else {
            return Vec::new();
        };
        k.subkeys
            .iter()
            .filter_map(|(_, id)| self.record(*id).map(|r| r.name.clone()))
            .collect()
    }
    /// `ZwEnumerateValueKey` — the value names (case-preserved).
    pub fn enum_values(&self, key: RegistryKeyId) -> Vec<String> {
        self.record(key)
            .map(|k| k.values.iter().map(|v| v.name.clone()).collect())
            .unwrap_or_default()
    }
    pub fn value_count(&self, key: RegistryKeyId) -> usize {
        self.record(key).map(|k| k.values.len()).unwrap_or(0)
    }

    /// All named values on a key (for persistence snapshots).
    pub fn values(&self, key: RegistryKeyId) -> &[RegistryValue] {
        self.record(key).map(|k| k.values.as_slice()).unwrap_or(&[])
    }

    /// Walk the whole tree (skipping the anonymous root) as `(path, volatile, values)` — the
    /// input to a persistence snapshot (spec §9.4). Ordered so parents precede children.
    pub fn snapshot_keys(&self) -> Vec<(String, bool, Vec<RegistryValue>)> {
        let mut out: Vec<(String, bool, Vec<RegistryValue>)> = self
            .keys
            .iter()
            .filter(|k| k.parent.is_some())
            .filter_map(|k| {
                self.key_path(k.id)
                    .map(|path| (path, k.volatile, k.values.clone()))
            })
            .collect();
        // Shorter paths (parents) first, so a restore creates parents before children.
        out.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
        out
    }

    /// `ZwDeleteKey` — delete a leaf key (removing it from its parent). Fails if it has
    /// subkeys (matching NT semantics) unless `recursive`.
    pub fn delete_key(&mut self, key: RegistryKeyId, recursive: bool) -> bool {
        let Some(k) = self.record(key) else {
            return false;
        };
        if !k.subkeys.is_empty() && !recursive {
            return false;
        }
        let parent = k.parent;
        let children: Vec<RegistryKeyId> = k.subkeys.iter().map(|(_, id)| *id).collect();
        for c in children {
            self.delete_key(c, true);
        }
        if let Some(p) = parent {
            if let Some(pr) = self.record_mut(p) {
                pr.subkeys.retain(|(_, id)| *id != key);
            }
        }
        self.keys.retain(|k| k.id != key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_open_nested_and_case_insensitive() {
        let mut r = Registry::new();
        let k = r.create_key(r"\Registry\Machine\Software\Vendor\App");
        assert_eq!(
            r.open_key(r"\registry\MACHINE\software\vendor\app"),
            Some(k)
        );
        assert_eq!(
            r.key_path(k).as_deref(),
            Some(r"\Registry\Machine\Software\Vendor\App")
        );
        // Intermediate keys were created.
        assert!(r.open_key(r"\Registry\Machine\Software\Vendor").is_some());
    }

    #[test]
    fn value_types_roundtrip() {
        let mut r = Registry::new();
        let k = r.create_key(r"\Registry\Machine\Test");
        r.set_dword(k, "D", 0xDEAD_BEEF);
        r.set_qword(k, "Q", 0x1122_3344_5566_7788);
        r.set_string(k, "S", "hello");
        assert_eq!(r.query_dword(k, "d"), Some(0xDEAD_BEEF)); // case-insensitive value name
        assert_eq!(r.query_qword(k, "Q"), Some(0x1122_3344_5566_7788));
        assert_eq!(r.query_string(k, "S").as_deref(), Some("hello"));
        // Overwrite + delete.
        r.set_dword(k, "D", 1);
        assert_eq!(r.query_dword(k, "D"), Some(1));
        assert!(r.delete_value(k, "D"));
        assert_eq!(r.query_value(k, "D"), None);
    }

    #[test]
    fn enumerate_and_delete_key() {
        let mut r = Registry::new();
        let parent = r.create_key(r"\Registry\Machine\P");
        r.create_subkey(parent, "A");
        r.create_subkey(parent, "B");
        let mut subs = r.enum_subkeys(parent);
        subs.sort();
        assert_eq!(subs, alloc::vec![String::from("A"), String::from("B")]);
        // Non-recursive delete of a key with subkeys fails.
        assert!(!r.delete_key(parent, false));
        assert!(r.delete_key(parent, true));
        assert_eq!(r.open_key(r"\Registry\Machine\P"), None);
    }
}
