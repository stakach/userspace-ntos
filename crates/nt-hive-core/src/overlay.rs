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
    detached: bool,
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

    /// Whether the slot at `idx` has been detached by [`Self::detach_subtree`].
    pub fn is_detached(&self, idx: usize) -> bool {
        self.keys.get(idx).is_some_and(|k| k.detached)
    }

    /// Create-or-open a key at the canonical `canon` path. Returns `(index, created)` where
    /// `created` is `true` only if the key did not already exist in the overlay.
    ///
    /// A DETACHED slot with the same path is re-attached in place and emptied for an explicit new
    /// create. The `NtLoadKey` remount path uses [`Self::reattach_subtree`] instead, because a prior
    /// `RegFlushKey`/unload must make those retained writes visible again.
    pub fn create(&mut self, canon: &str) -> (usize, bool) {
        if let Some(i) = self.find(canon) {
            return (i, false);
        }
        if let Some(i) = self
            .keys
            .iter()
            .position(|k| k.path == canon && k.detached)
        {
            self.keys[i].detached = false;
            self.keys[i].values.clear();
            return (i, true);
        }
        self.keys.push(OverlayKey {
            path: String::from(canon),
            values: Vec::new(),
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

    /// DETACH every key at or below `canon` — the write-plane half of `NtUnloadKey`. Without this
    /// an unload would leave the writes made through the mounted hive still resolving at the same
    /// path, so the "unloaded" key would keep answering opens. Values are kept hidden, not erased:
    /// the registry hive write path has no on-disk writer, so this retained overlay is the durable
    /// state a later `NtLoadKey` reattaches. Returns how many keys were detached (0 = nothing was
    /// mounted there, which the caller must report as a refusal).
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

    /// REATTACH every detached key at or below `canon`, restoring the overlay writes hidden by
    /// [`Self::detach_subtree`]. This models a hive that was flushed/unloaded and then mounted again
    /// from the same path: while unloaded it answered nothing, but its prior writes are still the
    /// volatile backing store once the mount returns.
    pub fn reattach_subtree(&mut self, canon: &str) -> usize {
        let mut reattached = 0;
        for key in self.keys.iter_mut() {
            if !key.detached {
                continue;
            }
            let under = key.path == canon
                || (key.path.len() > canon.len()
                    && key.path.starts_with(canon)
                    && key.path.as_bytes()[canon.len()] == b'\\');
            if under {
                key.detached = false;
                reattached += 1;
            }
        }
        reattached
    }

    /// Set (create-or-replace) a value on an overlay key. `name` may be `""` (the default value).
    /// Returns `false` if `idx` is out of range.
    pub fn set_value(&mut self, idx: usize, name: &str, ty: u32, data: &[u8]) -> bool {
        let folded = fold(name);
        let Some(k) = self.keys.get_mut(idx).filter(|k| !k.detached) else {
            return false;
        };
        if let Some(v) = k.values.iter_mut().find(|v| v.name_folded == folded) {
            v.ty = ty;
            v.name_raw = String::from(name);
            v.data.clear();
            v.data.extend_from_slice(data);
            v.deleted = false;
        } else {
            k.values.push(OverlayValue {
                name_raw: String::from(name),
                name_folded: folded,
                ty,
                data: data.to_vec(),
                deleted: false,
            });
        }
        true
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
            v.data.clear();
            v.deleted = true;
        } else {
            k.values.push(OverlayValue {
                name_raw: String::from(name),
                name_folded: folded,
                ty: 0,
                data: Vec::new(),
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
            .map(|v| (v.ty, v.data.as_slice()))
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
        k.values
            .iter()
            .filter(|v| !v.deleted)
            .nth(i)
            .map(|v| (v.name_raw.as_str(), v.ty, v.data.as_slice()))
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
        assert!(!ov
            .subkeys(r"\registry\user")
            .contains(&"s-1-5-21-1"));
        // …and nothing else moved: the slots are still there, only 2 are live.
        assert_eq!(ov.len(), 4);
        assert_eq!(ov.live_len(), 2);
        assert_eq!(ov.find(r"\registry\user\s-1-5-21-11"), Some(other));
        assert_eq!(ov.find(r"\registry\user\.default"), Some(keep));

        assert_eq!(ov.reattach_subtree(r"\registry\user\s-1-5-21-1"), 2);
        assert_eq!(ov.find(r"\registry\user\s-1-5-21-1"), Some(root));
        assert_eq!(ov.find(r"\registry\user\s-1-5-21-1\environment"), Some(child));
        assert_eq!(ov.value(root, "Loaded"), Some((4, &1u32.to_le_bytes()[..])));
        assert_eq!(ov.value(child, "TEMP"), Some((1, &b"t"[..])));
        assert_eq!(ov.live_len(), 4);
    }

    #[test]
    fn detach_refuses_a_path_that_was_never_mounted() {
        let mut ov = RegistryOverlay::new();
        ov.create(r"\registry\user\.default");
        assert_eq!(ov.detach_subtree(r"\registry\user\s-1-5-21-9"), 0);
        assert_eq!(ov.reattach_subtree(r"\registry\user\s-1-5-21-9"), 0);
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
        assert!(created_again, "a re-mounted key is newly created, not opened");
        assert!(!ov.is_detached(idx));
        assert_eq!(ov.values_len(idx), 0, "the previous mount's writes must not survive");
        assert_eq!(ov.len(), 1);
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
