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
//! components dropped, each lowercased. A mounted SYSTEM hive resolves its generation-specific
//! `CurrentControlSet` identity before canonicalization, so alias and physical paths land on the
//! same overlay key.
//!
//! `no_std` + `alloc`. Pure model (no I/O, no pointers) → host-testable; the executive owns one
//! instance for the mounted hive's lifetime.

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
/// lowercase each, rejoin with a leading `\`. Mount-owned namespace aliases must be resolved before
/// this representation-only operation.
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
    data: Option<usize>,
    deleted: bool,
}

/// A key created in the overlay: its canonical path + the values written on it.
///
/// `detached` is the `NtUnloadKey` state: the key's *slot* stays in place (so an already-minted
/// `KeyRef` that encodes this index can never silently start naming a DIFFERENT key) but the key
/// is invisible to every lookup while the hive it shadows is unloaded. The values are retained so
/// a later `NtLoadKey` can model the prior `RegFlushKey`/unload by reattaching the write set.
struct OverlayKey {
    path: String,
    values: Vec<OverlayValue>,
    class_name: Option<String>,
    security_descriptor: Option<usize>,
    volatile: bool,
    detached: bool,
}

/// A mutable registry write overlay over a read-only base hive. See the module docs.
#[derive(Default)]
pub struct RegistryOverlay {
    keys: Vec<OverlayKey>,
    blobs: Vec<Vec<u8>>,
}

impl RegistryOverlay {
    /// An empty overlay.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            blobs: Vec::new(),
        }
    }

    /// An empty overlay whose key vector is pre-reserved for `n` keys (so the executive can pin
    /// the backing buffer below its per-syscall heap mark and avoid a reallocation).
    pub fn with_capacity(n: usize) -> Self {
        Self {
            keys: Vec::with_capacity(n),
            blobs: Vec::new(),
        }
    }

    /// Number of unique value byte blobs retained by the overlay.
    pub fn unique_data_blobs(&self) -> usize {
        self.blobs.len()
    }

    /// Number of key SLOTS, including slots detached by [`Self::detach_subtree`]. This is the
    /// allocator's high-water mark (indices are never reused), which is what a capacity check
    /// must be compared against.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Number of keys that are actually visible (slots minus detached ones).
    pub fn live_len(&self) -> usize {
        self.keys.iter().filter(|k| !k.detached).count()
    }

    /// Whether the overlay has no created keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Find an existing overlay key by canonical path. A detached key is not found.
    pub fn find(&self, canon: &str) -> Option<usize> {
        self.keys
            .iter()
            .position(|k| k.path == canon && !k.detached)
    }

    /// Find a path-based overlay key only when it should remain authoritative over a live mounted
    /// mutable hive. Explicit volatile keys shadow mounted hives; nonvolatile shadows yield back to
    /// the mutable hive once that hive owns the path.
    pub fn find_for_path_authority(
        &self,
        canon: &str,
        mutable_hive_owns_path: bool,
    ) -> Option<usize> {
        let index = self.find(canon)?;
        if self.is_volatile(index).unwrap_or(false) || !mutable_hive_owns_path {
            Some(index)
        } else {
            None
        }
    }

    /// Whether the slot at `idx` has been detached by [`Self::detach_subtree`].
    pub fn is_detached(&self, idx: usize) -> bool {
        self.keys.get(idx).is_some_and(|k| k.detached)
    }

    /// Create-or-open a key at the canonical `canon` path. Returns `(index, created)` where
    /// `created` is `true` only if the key did not already exist in the overlay.
    ///
    /// A DETACHED slot with the same path is re-attached in place and emptied for an explicit new
    /// create. `NtLoadKey` remounts must reload the hive image from their backing file; detached
    /// overlay values are not persistent registry storage.
    pub fn create(&mut self, canon: &str) -> (usize, bool) {
        self.create_with_volatility(canon, true)
    }

    /// Create-or-open a key and record whether a newly-created slot is volatile.
    ///
    /// Existing keys keep their original volatility. NT's `REG_OPTION_VOLATILE` is a create-time
    /// property: reopening the same key with a different option must not rewrite key metadata.
    pub fn create_with_volatility(&mut self, canon: &str, volatile: bool) -> (usize, bool) {
        self.create_owned_with_volatility(String::from(canon), volatile)
    }

    /// Create-or-open a key, taking ownership of the caller's canonical path when a new overlay
    /// slot is needed. This lets the executive transfer durable registry paths into the write plane
    /// after dropping pre-mutation scratch allocations.
    pub fn create_owned(&mut self, canon: String) -> (usize, bool) {
        self.create_owned_with_volatility(canon, true)
    }

    /// Create-or-open a key, taking ownership of the caller's canonical path and recording whether
    /// a newly-created slot is volatile.
    pub fn create_owned_with_volatility(&mut self, canon: String, volatile: bool) -> (usize, bool) {
        if let Some(i) = self.find(&canon) {
            return (i, false);
        }
        if let Some(i) = self.keys.iter().position(|k| k.path == canon && k.detached) {
            self.keys[i].detached = false;
            self.keys[i].values.clear();
            self.keys[i].class_name = None;
            self.keys[i].security_descriptor = None;
            self.keys[i].volatile = volatile;
            return (i, true);
        }
        self.keys.push(OverlayKey {
            path: canon,
            values: Vec::new(),
            class_name: None,
            security_descriptor: None,
            volatile,
            detached: false,
        });
        (self.keys.len() - 1, true)
    }

    /// The canonical path of an overlay key. `None` for a detached slot.
    pub fn path(&self, idx: usize) -> Option<&str> {
        self.keys
            .get(idx)
            .filter(|k| !k.detached)
            .map(|k| k.path.as_str())
    }

    /// Whether a live overlay key was created as volatile.
    pub fn is_volatile(&self, idx: usize) -> Option<bool> {
        self.keys
            .get(idx)
            .filter(|k| !k.detached)
            .map(|k| k.volatile)
    }

    /// Count visible overlay keys created with `REG_OPTION_VOLATILE`.
    pub fn volatile_len(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| !k.detached && k.volatile)
            .count()
    }

    /// Count visible overlay keys that are runtime-only because they have no mounted hive backing,
    /// but were not explicitly created as volatile.
    pub fn nonvolatile_shadow_len(&self) -> usize {
        self.keys
            .iter()
            .filter(|k| !k.detached && !k.volatile)
            .count()
    }

    /// DETACH every key at or below `canon` — the write-plane half of `NtUnloadKey`. Without this
    /// an unload would leave volatile overlay keys made below the mounted hive still resolving at
    /// the same path, so the "unloaded" key would keep answering opens. Values are kept hidden until
    /// an explicit new create reuses the slot and starts empty.
    pub fn detach_subtree(&mut self, canon: &str) -> usize {
        let mut detached = 0;
        for key in self.keys.iter_mut() {
            if key.detached {
                continue;
            }
            let under = key.path == canon
                || (key.path.len() > canon.len()
                    && key.path.starts_with(canon)
                    && key.path.as_bytes()[canon.len()] == b'\\');
            if under {
                key.detached = true;
                detached += 1;
            }
        }
        detached
    }

    /// Set (create-or-replace) a value on an overlay key. `name` may be `""` (the default value).
    /// Returns `false` if `idx` is out of range.
    pub fn set_value(&mut self, idx: usize, name: &str, ty: u32, data: &[u8]) -> bool {
        self.set_value_from_slice(idx, String::from(name), ty, data)
    }

    /// Set (create-or-replace) a value, taking ownership of the raw name and data bytes.
    pub fn set_value_owned(&mut self, idx: usize, name: String, ty: u32, data: Vec<u8>) -> bool {
        if !self.keys.get(idx).is_some_and(|k| !k.detached) {
            return false;
        }
        let data_index = self.intern_data_owned(data);
        self.set_value_with_blob(idx, name, ty, data_index)
    }

    /// Set (create-or-replace) a value, taking ownership of the raw name and borrowing data bytes.
    /// Equal data already held by the overlay is reused without allocating another byte blob.
    pub fn set_value_from_slice(&mut self, idx: usize, name: String, ty: u32, data: &[u8]) -> bool {
        if !self.keys.get(idx).is_some_and(|k| !k.detached) {
            return false;
        }
        let data_index = self.intern_data_slice(data);
        self.set_value_with_blob(idx, name, ty, data_index)
    }

    fn set_value_with_blob(
        &mut self,
        idx: usize,
        name: String,
        ty: u32,
        data_index: usize,
    ) -> bool {
        if !self.keys.get(idx).is_some_and(|k| !k.detached) {
            return false;
        }
        let folded = fold(&name);
        let Some(k) = self.keys.get_mut(idx).filter(|k| !k.detached) else {
            return false;
        };
        if let Some(v) = k.values.iter_mut().find(|v| v.name_folded == folded) {
            v.ty = ty;
            v.name_raw = name;
            v.name_folded = folded;
            v.data = Some(data_index);
            v.deleted = false;
        } else {
            k.values.push(OverlayValue {
                name_raw: name,
                name_folded: folded,
                ty,
                data: Some(data_index),
                deleted: false,
            });
        }
        true
    }

    fn intern_data_slice(&mut self, data: &[u8]) -> usize {
        if let Some(index) = self
            .blobs
            .iter()
            .position(|existing| existing.as_slice() == data)
        {
            return index;
        }
        self.blobs.push(data.to_vec());
        self.blobs.len() - 1
    }

    fn intern_data_owned(&mut self, data: Vec<u8>) -> usize {
        if let Some(index) = self
            .blobs
            .iter()
            .position(|existing| existing.as_slice() == data.as_slice())
        {
            return index;
        }
        self.blobs.push(data);
        self.blobs.len() - 1
    }

    pub fn set_key_security_descriptor(&mut self, idx: usize, descriptor: &[u8]) -> bool {
        if !self.keys.get(idx).is_some_and(|k| !k.detached) {
            return false;
        }
        let data_index = self.intern_data_slice(descriptor);
        let Some(k) = self.keys.get_mut(idx).filter(|k| !k.detached) else {
            return false;
        };
        k.security_descriptor = Some(data_index);
        true
    }

    pub fn key_security_descriptor(&self, idx: usize) -> Option<&[u8]> {
        let k = self.keys.get(idx).filter(|k| !k.detached)?;
        self.blobs.get(k.security_descriptor?).map(Vec::as_slice)
    }

    /// Set the key's create-time class metadata. `Some("")` is an explicit empty class;
    /// `None` clears the overlay override so a shadowing key can inherit its base class.
    pub fn set_key_class(&mut self, idx: usize, class_name: Option<&str>) -> bool {
        let Some(key) = self.keys.get_mut(idx).filter(|key| !key.detached) else {
            return false;
        };
        key.class_name = class_name.map(String::from);
        true
    }

    /// The class metadata explicitly owned by this overlay key, if any.
    pub fn key_class(&self, idx: usize) -> Option<&str> {
        self.keys
            .get(idx)
            .filter(|key| !key.detached)
            .and_then(|key| key.class_name.as_deref())
    }

    /// Hide a value in this overlay, including a value that exists only in the read-only base hive.
    /// The tombstone remains addressable so a later [`Self::set_value`] can replace it in place.
    /// Returns `false` if `idx` is out of range.
    pub fn delete_value(&mut self, idx: usize, name: &str) -> bool {
        let folded = fold(name);
        let Some(k) = self.keys.get_mut(idx).filter(|k| !k.detached) else {
            return false;
        };
        if let Some(v) = k.values.iter_mut().find(|v| v.name_folded == folded) {
            v.name_raw = String::from(name);
            v.data = None;
            v.deleted = true;
        } else {
            k.values.push(OverlayValue {
                name_raw: String::from(name),
                name_folded: folded,
                ty: 0,
                data: None,
                deleted: true,
            });
        }
        true
    }

    /// Whether this overlay explicitly hides `name` from the read-only base hive.
    pub fn value_is_deleted(&self, idx: usize, name: &str) -> bool {
        let folded = fold(name);
        self.keys
            .get(idx)
            .filter(|k| !k.detached)
            .and_then(|k| k.values.iter().find(|v| v.name_folded == folded))
            .is_some_and(|v| v.deleted)
    }

    /// Read a value by name (case-insensitive) on an overlay key: `(reg_type, data)`.
    pub fn value(&self, idx: usize, name: &str) -> Option<(u32, &[u8])> {
        let folded = fold(name);
        let k = self.keys.get(idx).filter(|k| !k.detached)?;
        k.values
            .iter()
            .find(|v| v.name_folded == folded && !v.deleted)
            .and_then(|v| Some((v.ty, self.blobs.get(v.data?)?.as_slice())))
    }

    /// Number of values set on an overlay key.
    pub fn values_len(&self, idx: usize) -> usize {
        self.keys
            .get(idx)
            .filter(|k| !k.detached)
            .map_or(0, |k| k.values.iter().filter(|v| !v.deleted).count())
    }

    /// Enumerate the value at `i` on an overlay key: `(original-case name, reg_type, data)`.
    pub fn value_by_index(&self, idx: usize, i: usize) -> Option<(&str, u32, &[u8])> {
        let k = self.keys.get(idx).filter(|k| !k.detached)?;
        k.values.iter().filter(|v| !v.deleted).nth(i).and_then(|v| {
            Some((
                v.name_raw.as_str(),
                v.ty,
                self.blobs.get(v.data?)?.as_slice(),
            ))
        })
    }

    /// The immediate child key-name components (already canonical/folded) of `parent_canon`.
    pub fn subkeys(&self, parent_canon: &str) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for k in self.keys.iter().filter(|k| !k.detached) {
            if let Some(child) = immediate_child(&k.path, parent_canon) {
                if !out.contains(&child) {
                    out.push(child);
                }
            }
        }
        out
    }

    /// Number of unique immediate child key-name components under `parent_canon`.
    pub fn subkeys_len(&self, parent_canon: &str) -> usize {
        let mut count = 0;
        for (idx, key) in self.keys.iter().enumerate().filter(|(_, k)| !k.detached) {
            let Some(child) = immediate_child(&key.path, parent_canon) else {
                continue;
            };
            if !self.subkey_seen_before(parent_canon, idx, child) {
                count += 1;
            }
        }
        count
    }

    /// Borrow the `index`th unique immediate child key-name component under `parent_canon`.
    pub fn subkey_by_index(&self, parent_canon: &str, index: usize) -> Option<&str> {
        let mut visible = 0;
        for (idx, key) in self.keys.iter().enumerate().filter(|(_, k)| !k.detached) {
            let Some(child) = immediate_child(&key.path, parent_canon) else {
                continue;
            };
            if self.subkey_seen_before(parent_canon, idx, child) {
                continue;
            }
            if visible == index {
                return Some(child);
            }
            visible += 1;
        }
        None
    }

    fn subkey_seen_before(&self, parent_canon: &str, before: usize, child: &str) -> bool {
        self.keys
            .iter()
            .take(before)
            .filter(|k| !k.detached)
            .filter_map(|k| immediate_child(&k.path, parent_canon))
            .any(|prior| prior == child)
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
        assert_eq!(
            canon_path(r"\Registry\Machine\SYSTEM"),
            r"\registry\machine\system"
        );
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
    fn create_owned_has_the_same_create_or_open_semantics() {
        let mut ov = RegistryOverlay::new();
        let (i0, created0) = ov.create_owned(String::from(r"\registry\machine\software\classes"));
        assert!(created0);

        let (i1, created1) = ov.create_owned(String::from(r"\registry\machine\software\classes"));
        assert_eq!(i0, i1);
        assert!(!created1);
        assert_eq!(ov.path(i0), Some(r"\registry\machine\software\classes"));
    }

    #[test]
    fn create_records_volatility_only_for_new_slots() {
        let mut ov = RegistryOverlay::new();
        let (volatile, created) = ov.create_with_volatility(r"\runtime", true);
        assert!(created);
        assert_eq!(ov.is_volatile(volatile), Some(true));
        assert_eq!(ov.volatile_len(), 1);
        assert_eq!(ov.nonvolatile_shadow_len(), 0);

        let (again, created_again) = ov.create_with_volatility(r"\runtime", false);
        assert_eq!(again, volatile);
        assert!(!created_again);
        assert_eq!(
            ov.is_volatile(again),
            Some(true),
            "reopening a key with different CreateOptions must not mutate key metadata"
        );

        let (shadow, created_shadow) = ov.create_with_volatility(r"\shadow", false);
        assert!(created_shadow);
        assert_eq!(ov.is_volatile(shadow), Some(false));
        assert_eq!(ov.volatile_len(), 1);
        assert_eq!(ov.nonvolatile_shadow_len(), 1);
    }

    #[test]
    fn owned_shadow_paths_can_be_nonvolatile() {
        let mut ov = RegistryOverlay::new();
        let (shadow, created) = ov.create_owned_with_volatility(
            String::from(r"\registry\machine\software\shadow"),
            false,
        );
        assert!(created);
        assert_eq!(ov.is_volatile(shadow), Some(false));
        assert_eq!(ov.volatile_len(), 0);
        assert_eq!(ov.nonvolatile_shadow_len(), 1);

        let (again, created_again) =
            ov.create_with_volatility(r"\registry\machine\software\shadow", true);
        assert_eq!(again, shadow);
        assert!(!created_again);
        assert_eq!(
            ov.is_volatile(again),
            Some(false),
            "reopening an implicit shadow with REG_OPTION_VOLATILE must not reclassify it"
        );
    }

    #[test]
    fn nonvolatile_shadow_yields_to_mutable_path_authority() {
        let mut ov = RegistryOverlay::new();
        let (shadow, created) =
            ov.create_with_volatility(r"\registry\machine\software\microsoft\setupcopy", false);
        assert!(created);

        assert_eq!(
            ov.find_for_path_authority(r"\registry\machine\software\microsoft\setupcopy", false),
            Some(shadow),
            "without mounted mutable ownership the shadow remains the only writable authority"
        );
        assert_eq!(
            ov.find_for_path_authority(r"\registry\machine\software\microsoft\setupcopy", true),
            None,
            "mounted mutable hives must outrank old nonvolatile overlay shadows"
        );
    }

    #[test]
    fn volatile_overlay_stays_authoritative_over_mutable_path() {
        let mut ov = RegistryOverlay::new();
        let (volatile, created) =
            ov.create_with_volatility(r"\registry\user\s-1-5-21-1\volatile environment", true);
        assert!(created);

        assert_eq!(
            ov.find_for_path_authority(r"\registry\user\s-1-5-21-1\volatile environment", true),
            Some(volatile),
            "explicit volatile keys still shadow mounted mutable hives"
        );
    }

    #[test]
    fn reattached_overlay_slot_gets_new_volatility() {
        let mut ov = RegistryOverlay::new();
        let (idx, created) = ov.create_with_volatility(r"\registry\user\s-1-5-21-1", false);
        assert!(created);
        assert_eq!(ov.is_volatile(idx), Some(false));
        ov.set_value(idx, "Stale", 4, &7u32.to_le_bytes());
        assert_eq!(ov.detach_subtree(r"\registry\user\s-1-5-21-1"), 1);
        assert_eq!(ov.is_volatile(idx), None);

        let (again, created_again) = ov.create_with_volatility(r"\registry\user\s-1-5-21-1", true);
        assert_eq!(again, idx);
        assert!(created_again);
        assert_eq!(ov.is_volatile(idx), Some(true));
        assert_eq!(ov.values_len(idx), 0);
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
    fn set_value_owned_replaces_in_place() {
        let mut ov = RegistryOverlay::new();
        let (i, _) = ov.create(r"\k");
        assert!(ov.set_value_owned(i, String::from("Value"), 4, Vec::from(&b"old"[..])));
        assert!(ov.set_value_owned(i, String::from("VALUE"), 1, Vec::from(&b"new"[..])));

        assert_eq!(ov.values_len(i), 1);
        assert_eq!(ov.value(i, "value"), Some((1, &b"new"[..])));
        assert_eq!(ov.value_by_index(i, 0).map(|v| v.0), Some("VALUE"));
    }

    #[test]
    fn set_value_owned_interns_equal_data_across_keys() {
        let mut ov = RegistryOverlay::new();
        let (a, _) = ov.create(r"\a");
        let (b, _) = ov.create(r"\b");
        let descriptor = Vec::from(&b"same-security-descriptor"[..]);

        assert!(ov.set_value_owned(a, String::from("Security"), 3, descriptor.clone()));
        assert!(ov.set_value_owned(b, String::from("Security"), 3, descriptor));

        assert_eq!(ov.unique_data_blobs(), 1);
        assert_eq!(
            ov.value(a, "security"),
            Some((3, &b"same-security-descriptor"[..]))
        );
        assert_eq!(
            ov.value(b, "security"),
            Some((3, &b"same-security-descriptor"[..]))
        );
    }

    #[test]
    fn set_value_from_slice_reuses_existing_blob_without_owned_data() {
        let mut ov = RegistryOverlay::new();
        let (a, _) = ov.create(r"\a");
        let (b, _) = ov.create(r"\b");

        assert!(ov.set_value_from_slice(a, String::from("Security"), 3, b"descriptor"));
        assert!(ov.set_value_from_slice(b, String::from("Security"), 3, b"descriptor"));

        assert_eq!(ov.unique_data_blobs(), 1);
        assert_eq!(ov.value(b, "security"), Some((3, &b"descriptor"[..])));
    }

    #[test]
    fn key_security_descriptors_are_key_metadata() {
        let mut ov = RegistryOverlay::new();
        let (a, _) = ov.create(r"\a");
        let (b, _) = ov.create(r"\b");
        let descriptor = b"\x01\x00\x00\x80";

        assert!(ov.set_key_security_descriptor(a, descriptor));
        assert!(ov.set_key_security_descriptor(b, descriptor));
        assert_eq!(ov.unique_data_blobs(), 1);
        assert_eq!(ov.key_security_descriptor(a), Some(&descriptor[..]));
        assert_eq!(ov.key_security_descriptor(b), Some(&descriptor[..]));
    }

    #[test]
    fn key_classes_are_create_time_metadata_and_reset_on_reattach() {
        let mut ov = RegistryOverlay::new();
        let (key, created) = ov.create_with_volatility(r"\registry\machine\system\volatile", true);
        assert!(created);
        assert!(ov.set_key_class(key, Some("DeviceClass")));
        assert_eq!(ov.key_class(key), Some("DeviceClass"));

        let (same, reopened) = ov.create_with_volatility(
            r"\registry\machine\system\volatile",
            false,
        );
        assert_eq!(same, key);
        assert!(!reopened);
        assert_eq!(ov.key_class(key), Some("DeviceClass"));

        assert!(ov.set_key_class(key, Some("")));
        assert_eq!(ov.key_class(key), Some(""));
        assert_eq!(
            ov.detach_subtree(r"\registry\machine\system\volatile"),
            1
        );
        let (reattached, created_again) = ov.create_with_volatility(
            r"\registry\machine\system\volatile",
            true,
        );
        assert_eq!(reattached, key);
        assert!(created_again);
        assert_eq!(ov.key_class(reattached), None);
    }

    #[test]
    fn delete_value_tombstones_overlay_and_base_values() {
        let mut ov = RegistryOverlay::new();
        let (i, _) = ov.create(r"\k");
        ov.set_value(i, "Present", 4, &1u32.to_le_bytes());

        assert!(ov.delete_value(i, "present"));
        assert!(ov.value_is_deleted(i, "PRESENT"));
        assert_eq!(ov.value(i, "Present"), None);
        assert_eq!(ov.values_len(i), 0);
        assert!(ov.value_by_index(i, 0).is_none());

        assert!(ov.delete_value(i, "BaseOnly"));
        assert!(ov.value_is_deleted(i, "baseonly"));
        assert_eq!(ov.values_len(i), 0);
    }

    #[test]
    fn set_value_revives_a_tombstone_in_place() {
        let mut ov = RegistryOverlay::new();
        let (i, _) = ov.create(r"\k");
        ov.delete_value(i, "Value");
        ov.set_value(i, "VALUE", 1, b"new");

        assert!(!ov.value_is_deleted(i, "value"));
        assert_eq!(ov.value(i, "value"), Some((1, &b"new"[..])));
        assert_eq!(ov.values_len(i), 1);
        assert_eq!(ov.value_by_index(i, 0).map(|v| v.0), Some("VALUE"));
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

    // ── `NtUnloadKey`'s write-plane half ─────────────────────────────────────────────────────
    #[test]
    fn detach_subtree_hides_the_key_and_everything_under_it() {
        let mut ov = RegistryOverlay::new();
        let (root, _) = ov.create(r"\registry\user\s-1-5-21-1");
        let (child, _) = ov.create(r"\registry\user\s-1-5-21-1\environment");
        let (other, _) = ov.create(r"\registry\user\s-1-5-21-11"); // NOT a child (prefix only)
        let (keep, _) = ov.create(r"\registry\user\.default");
        ov.set_value(root, "Loaded", 4, &1u32.to_le_bytes());
        ov.set_value(child, "TEMP", 1, b"t");
        assert_eq!(ov.live_len(), 4);

        assert_eq!(ov.detach_subtree(r"\registry\user\s-1-5-21-1"), 2);

        // The unloaded subtree answers nothing…
        assert_eq!(ov.find(r"\registry\user\s-1-5-21-1"), None);
        assert_eq!(ov.find(r"\registry\user\s-1-5-21-1\environment"), None);
        assert!(ov.is_detached(root) && ov.is_detached(child));
        assert_eq!(ov.path(root), None);
        assert_eq!(ov.value(root, "Loaded"), None);
        assert_eq!(ov.values_len(root), 0);
        assert!(!ov.set_value(root, "Loaded", 4, &2u32.to_le_bytes()));
        assert!(ov.subkeys(r"\registry\user\s-1-5-21-1").is_empty());
        assert!(!ov.subkeys(r"\registry\user").contains(&"s-1-5-21-1"));
        // …and nothing else moved: the slots are still there, only 2 are live.
        assert_eq!(ov.len(), 4);
        assert_eq!(ov.live_len(), 2);
        assert_eq!(ov.find(r"\registry\user\s-1-5-21-11"), Some(other));
        assert_eq!(ov.find(r"\registry\user\.default"), Some(keep));

        let (again, created_again) = ov.create(r"\registry\user\s-1-5-21-1");
        assert_eq!(again, root);
        assert!(created_again);
        assert_eq!(ov.values_len(root), 0);
        assert!(ov.is_detached(child));
        assert_eq!(ov.live_len(), 3);
    }

    #[test]
    fn detach_refuses_a_path_that_was_never_mounted() {
        let mut ov = RegistryOverlay::new();
        ov.create(r"\registry\user\.default");
        assert_eq!(ov.detach_subtree(r"\registry\user\s-1-5-21-9"), 0);
        assert_eq!(ov.live_len(), 1);
    }

    #[test]
    fn re_creating_a_detached_path_reuses_the_slot_and_starts_empty() {
        let mut ov = RegistryOverlay::new();
        let (idx, created) = ov.create(r"\registry\user\s-1-5-21-1");
        assert!(created);
        ov.set_value(idx, "Stale", 4, &7u32.to_le_bytes());
        assert_eq!(ov.detach_subtree(r"\registry\user\s-1-5-21-1"), 1);

        let (again, created_again) = ov.create(r"\registry\user\s-1-5-21-1");
        assert_eq!(again, idx, "a re-mount must re-use the detached slot");
        assert!(
            created_again,
            "a re-mounted key is newly created, not opened"
        );
        assert!(!ov.is_detached(idx));
        assert_eq!(
            ov.values_len(idx),
            0,
            "the previous mount's writes must not survive"
        );
        assert_eq!(ov.len(), 1);
    }

    #[test]
    fn create_owned_reattaches_a_detached_slot() {
        let mut ov = RegistryOverlay::new();
        let (idx, _) = ov.create(r"\registry\user\s-1-5-21-1");
        ov.set_value(idx, "Stale", 4, &7u32.to_le_bytes());
        assert_eq!(ov.detach_subtree(r"\registry\user\s-1-5-21-1"), 1);

        let (again, created_again) = ov.create_owned(String::from(r"\registry\user\s-1-5-21-1"));
        assert_eq!(again, idx);
        assert!(created_again);
        assert_eq!(ov.values_len(idx), 0);
        assert_eq!(ov.path(idx), Some(r"\registry\user\s-1-5-21-1"));
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
        assert_eq!(ov.subkeys_len(r"\registry\machine\system"), 2);
        assert_eq!(
            ov.subkey_by_index(r"\registry\machine\system", 0),
            Some("a")
        );
        assert_eq!(
            ov.subkey_by_index(r"\registry\machine\system", 1),
            Some("c")
        );
        assert_eq!(ov.subkey_by_index(r"\registry\machine\system", 2), None);
        assert_eq!(ov.subkeys(r"\registry\machine\system\a"), alloc::vec!["b"]);
    }
}
