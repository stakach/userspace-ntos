//! # `RegistryOverlay` — an in-memory, mutable write overlay over a read-only base hive
//!
//! The `nt-hive-regf` parser and the `Hive` cell arena are **read-only** navigators over an
//! on-disk `regf` image. The Configuration Manager, however, must service registry **writes**
//! (`NtCreateKey`/`NtSetValueKey`) — volatile keys the boot creates (e.g. the SCM's
//! `Control\ServiceCurrent`) never exist on disk. This overlay is the write plane: a small,
//! path-keyed set of *created keys* + *set values* that **shadows** the base hive.
//!
//! The reader checks the **overlay first, then the read-only base**: a created key / set value in
//! the overlay wins; anything absent falls through to the base hive. Writes land only here.
//!
//! Keys are addressed by a **canonical NT path** ([`canon_path`]): components split on `\`, empty
//! components dropped, each lowercased. The caller applies the `CurrentControlSet` alias
//! ([`crate::apply_ccs_alias`]) *before* canonicalizing so a write to `CurrentControlSet\…` and a
//! later read via `ControlSet001\…` land on the same overlay key.
//!
//! `no_std` + `alloc`. Pure model (no I/O, no pointers) → host-testable; the executive keeps one
//! instance alive across its per-syscall bump-heap reset by pre-reserving its capacity and pinning
//! the heap high-water mark past each mutation (see the executive's `service_sec_image` loop).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Lowercase a string (Unicode-aware, matching the hive parser's case folding).
fn fold(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        for lc in c.to_lowercase() {
            out.push(lc);
        }
    }
    out
}

/// Canonicalize an NT registry path for overlay comparison: split on `\`, drop empty components,
/// lowercase each, rejoin with a leading `\`. The `CurrentControlSet` alias is applied by the
/// caller (via [`crate::apply_ccs_alias`]) *before* this, so reads and writes land on one key.
pub fn canon_path(path: &str) -> String {
    let mut out = String::new();
    for comp in path.split('\\').filter(|c| !c.is_empty()) {
        out.push('\\');
        out.push_str(&fold(comp));
    }
    if out.is_empty() {
        out.push('\\');
    }
    out
}

/// A value set in the overlay: its original-case name (for enumeration), folded name (for
/// comparison), REG_* type, and raw data bytes.
struct OverlayValue {
    name_raw: String,
    name_folded: String,
    ty: u32,
    data: Vec<u8>,
}

/// A key created in the overlay: its canonical path + the values written on it.
struct OverlayKey {
    path: String,
    values: Vec<OverlayValue>,
}

/// A mutable registry write overlay over a read-only base hive. See the module docs.
#[derive(Default)]
pub struct RegistryOverlay {
    keys: Vec<OverlayKey>,
}

impl RegistryOverlay {
    /// An empty overlay.
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// An empty overlay whose key vector is pre-reserved for `n` keys (so the executive can pin
    /// the backing buffer below its per-syscall heap mark and avoid a reallocation).
    pub fn with_capacity(n: usize) -> Self {
        Self { keys: Vec::with_capacity(n) }
    }

    /// Number of created keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the overlay has no created keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Find an existing overlay key by canonical path.
    pub fn find(&self, canon: &str) -> Option<usize> {
        self.keys.iter().position(|k| k.path == canon)
    }

    /// Create-or-open a key at the canonical `canon` path. Returns `(index, created)` where
    /// `created` is `true` only if the key did not already exist in the overlay.
    pub fn create(&mut self, canon: &str) -> (usize, bool) {
        if let Some(i) = self.find(canon) {
            return (i, false);
        }
        self.keys.push(OverlayKey { path: String::from(canon), values: Vec::new() });
        (self.keys.len() - 1, true)
    }

    /// The canonical path of an overlay key.
    pub fn path(&self, idx: usize) -> Option<&str> {
        self.keys.get(idx).map(|k| k.path.as_str())
    }

    /// Set (create-or-replace) a value on an overlay key. `name` may be `""` (the default value).
    /// Returns `false` if `idx` is out of range.
    pub fn set_value(&mut self, idx: usize, name: &str, ty: u32, data: &[u8]) -> bool {
        let folded = fold(name);
        let Some(k) = self.keys.get_mut(idx) else {
            return false;
        };
        if let Some(v) = k.values.iter_mut().find(|v| v.name_folded == folded) {
            v.ty = ty;
            v.name_raw = String::from(name);
            v.data.clear();
            v.data.extend_from_slice(data);
        } else {
            k.values.push(OverlayValue {
                name_raw: String::from(name),
                name_folded: folded,
                ty,
                data: data.to_vec(),
            });
        }
        true
    }

    /// Read a value by name (case-insensitive) on an overlay key: `(reg_type, data)`.
    pub fn value(&self, idx: usize, name: &str) -> Option<(u32, &[u8])> {
        let folded = fold(name);
        let k = self.keys.get(idx)?;
        k.values.iter().find(|v| v.name_folded == folded).map(|v| (v.ty, v.data.as_slice()))
    }

    /// Number of values set on an overlay key.
    pub fn values_len(&self, idx: usize) -> usize {
        self.keys.get(idx).map_or(0, |k| k.values.len())
    }

    /// Enumerate the value at `i` on an overlay key: `(original-case name, reg_type, data)`.
    pub fn value_by_index(&self, idx: usize, i: usize) -> Option<(&str, u32, &[u8])> {
        let k = self.keys.get(idx)?;
        k.values.get(i).map(|v| (v.name_raw.as_str(), v.ty, v.data.as_slice()))
    }

    /// The immediate child key-name components (already canonical/folded) of `parent_canon`.
    pub fn subkeys(&self, parent_canon: &str) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for k in &self.keys {
            if let Some(child) = immediate_child(&k.path, parent_canon) {
                if !out.contains(&child) {
                    out.push(child);
                }
            }
        }
        out
    }
}

/// If `path` is an immediate child of `parent` (both canonical), return the leaf component.
fn immediate_child<'a>(path: &'a str, parent: &str) -> Option<&'a str> {
    // Both start with '\'. A child of "\" is any single-component path; a child of "\a\b" is
    // "\a\b\c" with exactly one more component.
    let rest = if parent == "\\" {
        path.strip_prefix('\\')?
    } else {
        path.strip_prefix(parent)?.strip_prefix('\\')?
    };
    if rest.is_empty() || rest.contains('\\') {
        None
    } else {
        Some(rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canon_is_case_insensitive_and_trims() {
        assert_eq!(canon_path(r"\Registry\Machine\SYSTEM"), r"\registry\machine\system");
        assert_eq!(canon_path(r"Registry\\Machine\"), r"\registry\machine");
        assert_eq!(canon_path(""), "\\");
    }

    #[test]
    fn create_is_create_or_open() {
        let mut ov = RegistryOverlay::with_capacity(4);
        let (i0, created0) = ov.create(r"\registry\machine\system\x");
        assert!(created0);
        let (i1, created1) = ov.create(r"\registry\machine\system\x");
        assert!(!created1, "second create must OPEN the existing key");
        assert_eq!(i0, i1);
        assert_eq!(ov.len(), 1);
        assert_eq!(ov.find(r"\registry\machine\system\x"), Some(i0));
        assert_eq!(ov.find(r"\registry\machine\system\y"), None);
    }

    #[test]
    fn set_and_read_value_roundtrip() {
        let mut ov = RegistryOverlay::new();
        let (i, _) = ov.create(r"\control\servicecurrent");
        // default (unnamed) value: a REG_DWORD = 1
        assert!(ov.set_value(i, "", 4, &1u32.to_le_bytes()));
        assert_eq!(ov.value(i, ""), Some((4u32, &1u32.to_le_bytes()[..])));
        // named value, case-insensitive read
        assert!(ov.set_value(i, "Start", 4, &2u32.to_le_bytes()));
        assert_eq!(ov.value(i, "START"), Some((4u32, &2u32.to_le_bytes()[..])));
        assert_eq!(ov.values_len(i), 2);
    }

    #[test]
    fn set_value_replaces_in_place() {
        let mut ov = RegistryOverlay::new();
        let (i, _) = ov.create(r"\k");
        ov.set_value(i, "v", 4, &1u32.to_le_bytes());
        ov.set_value(i, "V", 1, b"hello"); // same folded name, new type + data
        assert_eq!(ov.values_len(i), 1);
        assert_eq!(ov.value(i, "v"), Some((1u32, &b"hello"[..])));
    }

    #[test]
    fn enumerate_values_preserves_case() {
        let mut ov = RegistryOverlay::new();
        let (i, _) = ov.create(r"\k");
        ov.set_value(i, "ErrorControl", 4, &1u32.to_le_bytes());
        let (name, ty, data) = ov.value_by_index(i, 0).unwrap();
        assert_eq!(name, "ErrorControl");
        assert_eq!(ty, 4);
        assert_eq!(data, &1u32.to_le_bytes());
        assert!(ov.value_by_index(i, 1).is_none());
    }

    #[test]
    fn subkeys_are_immediate_children_only() {
        let mut ov = RegistryOverlay::new();
        ov.create(r"\registry\machine\system\a");
        ov.create(r"\registry\machine\system\a\b"); // grandchild of \registry\machine\system
        ov.create(r"\registry\machine\system\c");
        let mut kids = ov.subkeys(r"\registry\machine\system");
        kids.sort();
        assert_eq!(kids, alloc::vec!["a", "c"]);
        assert_eq!(ov.subkeys(r"\registry\machine\system\a"), alloc::vec!["b"]);
    }
}
