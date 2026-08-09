//! # `nt-hive-regf` — read-only `regf` hive parser
//!
//! Parses the **real** Windows/ReactOS on-disk registry hive format so the NT registry subsystem
//! can be served from a live-CD `SYSTEM` hive (rather than a synthesized one). This is a
//! navigator over the raw bytes — no mutation, no transcode — so opening a key / reading a value
//! is just bounds-checked offset arithmetic.
//!
//! Format (all multi-byte little-endian):
//! * **Base block** (4096 B): `regf` signature @0, root-cell offset @0x24, hive-bins size @0x28.
//! * **Hive bins** (`hbin`): 4 KiB-aligned, starting at file offset 0x1000. Every *cell offset*
//!   is relative to that 0x1000 base.
//! * **Cell**: a signed `i32` size (negative = allocated/in-use) then the cell body; the body's
//!   first 2 bytes are the type signature (`nk`/`vk`/`lf`/`lh`/`li`/`ri`/`sk`).
//! * **`nk`** (key node): subkey-list offset @0x1C, value-count @0x24, value-list offset @0x28,
//!   name-length @0x48, name @0x4C (ASCII if flags@0x02 & 0x20, else UTF-16LE).
//! * **`vk`** (value): name-length @0x02, data-length @0x04 (top bit set = ≤4 B data inlined in
//!   the data-offset field), data-offset @0x08, type @0x0C, flags @0x10 (bit0 = ASCII name).
//! * **subkey lists**: `lf`/`lh` = count then (offset,hint) pairs; `li` = count then offsets;
//!   `ri` = count then offsets to *other* subkey lists.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use nt_config_manager::{
    ConfigManager, Registry, RegistryKeyId, RegistryValueType, CONTROL_CLASS_PATH, ENUM_PATH,
    SERVICES_PATH, SERVICE_GROUP_ORDER_PATH,
};
use nt_hive_core::{CellId, Hive, HiveKind};

const HBIN_BASE: usize = 0x1000;

/// A parsed, read-only `regf` hive borrowing its raw bytes (no copy — the hive image is large and
/// mapped once). Keys are referred to by their hbin-relative cell offset (`KeyRef`).
pub struct RegfHive<'a> {
    data: &'a [u8],
    root: u32,
}

enum ValueDataView<'a> {
    Inline { ty: u32, data: [u8; 4], len: usize },
    Borrowed { ty: u32, data: &'a [u8] },
}

impl<'a> ValueDataView<'a> {
    fn ty(&self) -> u32 {
        match self {
            ValueDataView::Inline { ty, .. } | ValueDataView::Borrowed { ty, .. } => *ty,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            ValueDataView::Inline { data, len, .. } => &data[..*len],
            ValueDataView::Borrowed { data, .. } => data,
        }
    }
}

/// A reference to a key node (its hbin-relative cell offset).
pub type KeyRef = u32;

/// Import accounting for copying a real `regf` hive into the mutable Hive Manager arena.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RegfHiveImportStats {
    pub keys: usize,
    pub values: usize,
    pub skipped_values: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RegfHiveCellCounts {
    keys: usize,
    values: usize,
}

fn live_mutation_cell_headroom(kind: HiveKind, imported_cells: usize) -> usize {
    match kind {
        // services.exe performs real ControlSet construction by copying a large SYSTEM subtree
        // immediately after boot. Reserve enough metadata cells for that second live tree.
        HiveKind::System => imported_cells,
        // The install-time SOFTWARE writes we own here are class/profile metadata, not another full
        // hive copy. Fixed slack avoids a late Vec growth while keeping profile-load headroom.
        HiveKind::Software => 512,
        // SAM/SECURITY boot hives are tiny on the live CD but grow during first-boot database
        // creation; give them room for real account/policy keys without scaling by imported size.
        HiveKind::Sam | HiveKind::Security => 1024,
        // .Default and dynamically loaded user hives need Volatile Environment and profile deltas,
        // but not a full duplicate of the prototype hive.
        HiveKind::Default => 256,
    }
}

fn live_mutation_value_headroom(kind: HiveKind, imported_values: usize) -> usize {
    match kind {
        HiveKind::System => imported_values,
        HiveKind::Software => 256,
        HiveKind::Sam | HiveKind::Security => 512,
        HiveKind::Default => 128,
    }
}

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn i32le(b: &[u8], off: usize) -> Option<i32> {
    b.get(off..off + 4)
        .map(|s| i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> RegfHive<'a> {
    /// Validate the base block and locate the root key node. Returns `None` if the bytes aren't a
    /// well-formed `regf` hive whose root cell is an `nk`.
    pub fn new(data: &'a [u8]) -> Option<RegfHive<'a>> {
        if data.len() < HBIN_BASE + 0x20 || &data[0..4] != b"regf" {
            return None;
        }
        let root = u32le(data, 0x24)?;
        let hive = RegfHive { data, root };
        if hive.cell_body(root)?.get(0..2)? != b"nk" {
            return None;
        }
        Some(hive)
    }

    /// The root key node.
    pub fn root(&self) -> KeyRef {
        self.root
    }

    /// The raw `regf` image this read-only hive navigates.
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The cell body (after the 4-byte signed size) at a hbin-relative `offset`, bounds-checked.
    fn cell_body(&self, offset: u32) -> Option<&[u8]> {
        let fo = HBIN_BASE.checked_add(offset as usize)?;
        let size = i32le(self.data, fo)?;
        let len = (size.unsigned_abs() as usize).max(4);
        self.data.get(fo + 4..fo + len)
    }

    fn cell_body_len(&self, offset: u32) -> Option<usize> {
        let fo = HBIN_BASE.checked_add(offset as usize)?;
        let size = i32le(self.data, fo)?;
        let len = (size.unsigned_abs() as usize).max(4);
        self.data.get(fo + 4..fo + len).map(|body| body.len())
    }

    /// A cell body given a *file* offset already past the size word is not needed — everything is
    /// keyed by hbin-relative cell offset via `cell_body`.

    /// The name of a key node (ASCII or UTF-16LE per its flags), lowercased for case-insensitive
    /// comparison.
    fn key_name_folded(&self, nk: u32) -> Option<String> {
        let b = self.cell_body(nk)?;
        let flags = u16le(b, 0x02)?;
        let name_len = u16le(b, 0x48)? as usize;
        let raw = b.get(0x4c..0x4c + name_len)?;
        let mut s = String::new();
        if flags & 0x20 != 0 {
            // COMP_NAME: Latin-1 / ASCII, one byte per char.
            for &c in raw {
                s.push((c as char).to_ascii_lowercase());
            }
        } else {
            // UTF-16LE.
            for pair in raw.chunks_exact(2) {
                let w = u16::from_le_bytes([pair[0], pair[1]]);
                if let Some(c) = char::from_u32(w as u32) {
                    for lc in c.to_lowercase() {
                        s.push(lc);
                    }
                }
            }
        }
        Some(s)
    }

    /// The original-case name of a key node.
    fn key_name_raw(&self, nk: KeyRef) -> Option<String> {
        let b = self.cell_body(nk)?;
        if b.get(0..2)? != b"nk" {
            return None;
        }
        let flags = u16le(b, 0x02)?;
        let name_len = u16le(b, 0x48)? as usize;
        let raw = b.get(0x4c..0x4c + name_len)?;
        let mut s = String::new();
        if flags & 0x20 != 0 {
            for &c in raw {
                s.push(c as char);
            }
        } else {
            for pair in raw.chunks_exact(2) {
                let w = u16::from_le_bytes([pair[0], pair[1]]);
                s.push(char::from_u32(w as u32)?);
            }
        }
        Some(s)
    }

    fn key_name_utf16_len(&self, nk: KeyRef) -> Option<usize> {
        let b = self.cell_body(nk)?;
        if b.get(0..2)? != b"nk" {
            return None;
        }
        let flags = u16le(b, 0x02)?;
        let name_len = u16le(b, 0x48)? as usize;
        b.get(0x4c..0x4c + name_len)?;
        if flags & 0x20 != 0 {
            Some(name_len)
        } else {
            Some(name_len / 2)
        }
    }

    /// Reconstruct a key's `\`-separated path relative to the hive root.
    ///
    /// The root itself is `""`. Malformed parent links, cycles, and paths deeper than 256 keys are
    /// rejected. This is useful when a mutable overlay must shadow a value reached through an
    /// already-open read-only hive key.
    pub fn key_path(&self, nk: KeyRef) -> Option<String> {
        let mut components = Vec::new();
        let mut seen = Vec::new();
        let mut current = nk;
        for _ in 0..256 {
            if current == self.root {
                components.reverse();
                return Some(components.join("\\"));
            }
            if seen.contains(&current) {
                return None;
            }
            seen.push(current);
            let body = self.cell_body(current)?;
            if body.get(0..2)? != b"nk" {
                return None;
            }
            components.push(self.key_name_raw(current)?);
            let parent = u32le(body, 0x10)?;
            if parent == u32::MAX {
                return None;
            }
            current = parent;
        }
        None
    }

    /// Iterate the immediate subkeys of `nk` as `(folded_name, nk_offset)`.
    pub fn subkeys(&self, nk: KeyRef) -> Vec<(String, KeyRef)> {
        self.subkeys_named(nk, false)
    }

    /// Iterate the immediate subkeys of `nk` as `(original_case_name, nk_offset)`.
    pub fn subkeys_raw(&self, nk: KeyRef) -> Vec<(String, KeyRef)> {
        self.subkeys_named(nk, true)
    }

    fn subkeys_named(&self, nk: KeyRef, raw_names: bool) -> Vec<(String, KeyRef)> {
        let mut out = Vec::new();
        let body = match self.cell_body(nk) {
            Some(b) => b,
            None => return out,
        };
        let list_off = match u32le(body, 0x1c) {
            Some(o) if o != 0 && o != u32::MAX => o,
            _ => return out,
        };
        self.collect_subkeys(list_off, &mut out, 0, raw_names);
        out
    }

    /// Number of immediate subkeys recorded on `nk`.
    pub fn subkey_count(&self, nk: KeyRef) -> usize {
        self.cell_body(nk)
            .and_then(|body| u32le(body, 0x14))
            .unwrap_or(0) as usize
    }

    /// Enumerate one immediate subkey without materializing the complete child list.
    pub fn subkey_by_index(&self, nk: KeyRef, index: usize) -> Option<(String, KeyRef)> {
        let body = self.cell_body(nk)?;
        let list_off = match u32le(body, 0x1c) {
            Some(o) if o != 0 && o != u32::MAX => o,
            _ => return None,
        };
        let mut remaining = index;
        self.subkey_by_index_in_list(list_off, &mut remaining, 0, false)
    }

    fn subkey_ref_by_index(&self, nk: KeyRef, index: usize) -> Option<KeyRef> {
        let body = self.cell_body(nk)?;
        let list_off = match u32le(body, 0x1c) {
            Some(o) if o != 0 && o != u32::MAX => o,
            _ => return None,
        };
        let mut remaining = index;
        self.subkey_ref_by_index_in_list(list_off, &mut remaining, 0)
    }

    /// UTF-16 code units in the original-case immediate subkey name at `index`.
    pub fn subkey_name_utf16_len_by_index(&self, nk: KeyRef, index: usize) -> Option<usize> {
        let (_, cell) = self.subkey_by_index(nk, index)?;
        self.key_name_utf16_len(cell)
    }

    /// Walk a subkey-list cell (lf/lh/li/ri), pushing `(name, nk_off)`. `ri` recurses into its
    /// sub-lists; `depth` guards against a malformed cyclic hive.
    fn collect_subkeys(
        &self,
        list_off: u32,
        out: &mut Vec<(String, KeyRef)>,
        depth: u32,
        raw_names: bool,
    ) {
        if depth > 8 {
            return;
        }
        let b = match self.cell_body(list_off) {
            Some(b) => b,
            None => return,
        };
        let sig = match b.get(0..2) {
            Some(s) => s,
            None => return,
        };
        let count = match u16le(b, 0x02) {
            Some(c) => c as usize,
            None => return,
        };
        match sig {
            b"lf" | b"lh" => {
                // count × (u32 nk_offset, u32 hint), starting @0x04.
                for i in 0..count {
                    if let Some(off) = u32le(b, 0x04 + i * 8) {
                        let name = if raw_names {
                            self.key_name_raw(off)
                        } else {
                            self.key_name_folded(off)
                        };
                        if let Some(name) = name {
                            out.push((name, off));
                        }
                    }
                }
            }
            b"li" => {
                // count × u32 nk_offset.
                for i in 0..count {
                    if let Some(off) = u32le(b, 0x04 + i * 4) {
                        let name = if raw_names {
                            self.key_name_raw(off)
                        } else {
                            self.key_name_folded(off)
                        };
                        if let Some(name) = name {
                            out.push((name, off));
                        }
                    }
                }
            }
            b"ri" => {
                // count × u32 offset-to-another-subkey-list.
                for i in 0..count {
                    if let Some(sub) = u32le(b, 0x04 + i * 4) {
                        self.collect_subkeys(sub, out, depth + 1, raw_names);
                    }
                }
            }
            _ => {}
        }
    }

    fn subkey_by_index_in_list(
        &self,
        list_off: u32,
        remaining: &mut usize,
        depth: u32,
        raw_names: bool,
    ) -> Option<(String, KeyRef)> {
        if depth > 8 {
            return None;
        }
        let b = self.cell_body(list_off)?;
        let sig = b.get(0..2)?;
        let count = u16le(b, 0x02)? as usize;
        match sig {
            b"lf" | b"lh" => {
                for i in 0..count {
                    let off = u32le(b, 0x04 + i * 8)?;
                    if *remaining == 0 {
                        let name = if raw_names {
                            self.key_name_raw(off)?
                        } else {
                            self.key_name_folded(off)?
                        };
                        return Some((name, off));
                    }
                    *remaining -= 1;
                }
            }
            b"li" => {
                for i in 0..count {
                    let off = u32le(b, 0x04 + i * 4)?;
                    if *remaining == 0 {
                        let name = if raw_names {
                            self.key_name_raw(off)?
                        } else {
                            self.key_name_folded(off)?
                        };
                        return Some((name, off));
                    }
                    *remaining -= 1;
                }
            }
            b"ri" => {
                for i in 0..count {
                    let sub = u32le(b, 0x04 + i * 4)?;
                    if let Some(found) =
                        self.subkey_by_index_in_list(sub, remaining, depth + 1, raw_names)
                    {
                        return Some(found);
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn subkey_ref_by_index_in_list(
        &self,
        list_off: u32,
        remaining: &mut usize,
        depth: u32,
    ) -> Option<KeyRef> {
        if depth > 8 {
            return None;
        }
        let b = self.cell_body(list_off)?;
        let sig = b.get(0..2)?;
        let count = u16le(b, 0x02)? as usize;
        match sig {
            b"lf" | b"lh" => {
                for i in 0..count {
                    let off = u32le(b, 0x04 + i * 8)?;
                    if *remaining == 0 {
                        return Some(off);
                    }
                    *remaining -= 1;
                }
            }
            b"li" => {
                for i in 0..count {
                    let off = u32le(b, 0x04 + i * 4)?;
                    if *remaining == 0 {
                        return Some(off);
                    }
                    *remaining -= 1;
                }
            }
            b"ri" => {
                for i in 0..count {
                    let sub = u32le(b, 0x04 + i * 4)?;
                    if let Some(found) = self.subkey_ref_by_index_in_list(sub, remaining, depth + 1)
                    {
                        return Some(found);
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// Open the immediate subkey named `name` (case-insensitive) under `nk`.
    pub fn open_subkey(&self, nk: KeyRef, name: &str) -> Option<KeyRef> {
        let want = fold(name);
        for index in 0.. {
            let Some((folded, cell)) = self.subkey_by_index(nk, index) else {
                break;
            };
            if folded == want {
                return Some(cell);
            }
        }
        None
    }

    /// Resolve a `\`-separated relative path from `from` (empty components ignored).
    pub fn open_key_from(&self, from: KeyRef, rel_path: &str) -> Option<KeyRef> {
        let mut cur = from;
        for comp in rel_path.split('\\').filter(|c| !c.is_empty()) {
            cur = self.open_subkey(cur, comp)?;
        }
        Some(cur)
    }

    /// Resolve a `\`-separated relative path from the hive root.
    pub fn open_key(&self, rel_path: &str) -> Option<KeyRef> {
        self.open_key_from(self.root, rel_path)
    }

    /// Iterate the values of `nk` as `(folded_name, vk_offset)`.
    pub fn values(&self, nk: KeyRef) -> Vec<(String, u32)> {
        let mut out = Vec::new();
        let body = match self.cell_body(nk) {
            Some(b) => b,
            None => return out,
        };
        let count = u32le(body, 0x24).unwrap_or(0) as usize;
        let list_off = match u32le(body, 0x28) {
            Some(o) if o != 0 && o != u32::MAX => o,
            _ => return out,
        };
        let list = match self.cell_body(list_off) {
            Some(l) => l,
            None => return out,
        };
        for i in 0..count {
            if let Some(vk) = u32le(list, i * 4) {
                if let Some(name) = self.value_name_folded(vk) {
                    out.push((name, vk));
                }
            }
        }
        out
    }

    /// Number of values recorded on `nk`.
    pub fn value_count(&self, nk: KeyRef) -> usize {
        self.cell_body(nk)
            .and_then(|body| u32le(body, 0x24))
            .unwrap_or(0) as usize
    }

    fn value_cell_by_index(&self, nk: KeyRef, index: usize) -> Option<u32> {
        let body = self.cell_body(nk)?;
        let count = u32le(body, 0x24)? as usize;
        if index >= count {
            return None;
        }
        let list_off = match u32le(body, 0x28) {
            Some(o) if o != 0 && o != u32::MAX => o,
            _ => return None,
        };
        let list = self.cell_body(list_off)?;
        u32le(list, index * 4)
    }

    fn value_cell_by_name(&self, nk: KeyRef, name: &str) -> Option<u32> {
        let want = fold(name);
        for index in 0..self.value_count(nk) {
            let Some(vk) = self.value_cell_by_index(nk, index) else {
                continue;
            };
            if self
                .value_name_folded(vk)
                .is_some_and(|folded| folded == want)
            {
                return Some(vk);
            }
        }
        None
    }

    fn value_name_folded(&self, vk: u32) -> Option<String> {
        let b = self.cell_body(vk)?;
        if b.get(0..2)? != b"vk" {
            return None;
        }
        let name_len = u16le(b, 0x02)? as usize;
        if name_len == 0 {
            return Some(String::new()); // the default (unnamed) value
        }
        let raw = b.get(0x14..0x14 + name_len)?;
        // vk names are ASCII when flags@0x10 bit0 is set; treat as Latin-1 either way.
        let mut s = String::new();
        for &c in raw {
            s.push((c as char).to_ascii_lowercase());
        }
        Some(s)
    }

    fn value_name_utf16_len(&self, vk: u32) -> Option<usize> {
        let b = self.cell_body(vk)?;
        if b.get(0..2)? != b"vk" {
            return None;
        }
        let name_len = u16le(b, 0x02)? as usize;
        b.get(0x14..0x14 + name_len)?;
        if name_len == 0 {
            return Some(0);
        }
        let flags = u16le(b, 0x10)?;
        if flags & 1 != 0 {
            Some(name_len)
        } else {
            Some(name_len / 2)
        }
    }

    /// Read a value by name (case-insensitive) under `nk`: returns `(reg_type, data_bytes)`.
    /// Handles small (≤4 B) inline data (data-length top bit set).
    pub fn value(&self, nk: KeyRef, name: &str) -> Option<(u32, Vec<u8>)> {
        self.value_with(nk, name, |ty, data| (ty, data.to_vec()))
    }

    /// Read a value by name and borrow its data for the duration of `visit`.
    pub fn value_with<R>(
        &self,
        nk: KeyRef,
        name: &str,
        visit: impl FnOnce(u32, &[u8]) -> R,
    ) -> Option<R> {
        let vk = self.value_cell_by_name(nk, name)?;
        let data = self.value_data_view(vk)?;
        Some(visit(data.ty(), data.as_slice()))
    }

    /// Whether a value exists by name without cloning the complete value list or data body.
    pub fn value_exists(&self, nk: KeyRef, name: &str) -> bool {
        self.value_cell_by_name(nk, name).is_some()
    }

    /// Compare a value by type and bytes without touching its data body when the lengths differ.
    pub fn value_matches(&self, nk: KeyRef, name: &str, ty: u32, data: &[u8]) -> Option<bool> {
        let vk = self.value_cell_by_name(nk, name)?;
        let (stored_ty, stored_len) = self.value_data_type_len(vk)?;
        if stored_ty != ty || stored_len != data.len() {
            return Some(false);
        }
        let stored = self.value_data_view(vk)?;
        Some(stored.ty() == ty && stored.as_slice() == data)
    }

    /// The original-case (unfolded) name of a value cell — for enumeration output.
    fn value_name_raw(&self, vk: u32) -> Option<String> {
        let b = self.cell_body(vk)?;
        if b.get(0..2)? != b"vk" {
            return None;
        }
        let name_len = u16le(b, 0x02)? as usize;
        if name_len == 0 {
            return Some(String::new());
        }
        let flags = u16le(b, 0x10)?;
        let raw = b.get(0x14..0x14 + name_len)?;
        let mut s = String::new();
        if flags & 1 != 0 {
            for &c in raw {
                s.push(c as char); // COMP_NAME: Latin-1
            }
        } else {
            for pair in raw.chunks_exact(2) {
                if let Some(c) = char::from_u32(u16::from_le_bytes([pair[0], pair[1]]) as u32) {
                    s.push(c);
                }
            }
        }
        Some(s)
    }

    /// Enumerate the value at `index` under `nk`: `(name, reg_type, data_bytes)` in stored order.
    pub fn value_by_index(&self, nk: KeyRef, index: usize) -> Option<(String, u32, Vec<u8>)> {
        self.value_by_index_with(nk, index, |name, ty, data| {
            (String::from(name), ty, data.to_vec())
        })
    }

    /// Enumerate the value at `index` and borrow its data for the duration of `visit`.
    pub fn value_by_index_with<R>(
        &self,
        nk: KeyRef,
        index: usize,
        visit: impl FnOnce(&str, u32, &[u8]) -> R,
    ) -> Option<R> {
        let vk = self.value_cell_by_index(nk, index)?;
        let name = self.value_name_raw(vk)?;
        let data = self.value_data_view(vk)?;
        Some(visit(&name, data.ty(), data.as_slice()))
    }

    /// Original-case value name at `index` without cloning its data body.
    pub fn value_name_by_index(&self, nk: KeyRef, index: usize) -> Option<String> {
        let vk = self.value_cell_by_index(nk, index)?;
        self.value_name_raw(vk)
    }

    /// Lengths for the value at `index`: `(name_utf16_bytes, data_bytes)`.
    pub fn value_lengths_by_index(&self, nk: KeyRef, index: usize) -> Option<(usize, usize)> {
        let vk = self.value_cell_by_index(nk, index)?;
        let name_bytes = self.value_name_utf16_len(vk)?.checked_mul(2)?;
        let data_bytes = self.value_data_len(vk)?;
        Some((name_bytes, data_bytes))
    }

    fn value_data_view<'s>(&'s self, vk: u32) -> Option<ValueDataView<'s>> {
        let b = self.cell_body(vk)?;
        let data_len_raw = u32le(b, 0x04)?;
        let data_off = u32le(b, 0x08)?;
        let reg_type = u32le(b, 0x0c)?;
        let inline = data_len_raw & 0x8000_0000 != 0;
        let len = (data_len_raw & 0x7fff_ffff) as usize;
        if inline {
            // Data (≤4 bytes) stored directly in the data-offset field.
            Some(ValueDataView::Inline {
                ty: reg_type,
                data: data_off.to_le_bytes(),
                len: len.min(4),
            })
        } else {
            let db = self.cell_body(data_off)?;
            Some(ValueDataView::Borrowed {
                ty: reg_type,
                data: db.get(..len.min(db.len()))?,
            })
        }
    }

    fn value_data_len(&self, vk: u32) -> Option<usize> {
        self.value_data_type_len(vk).map(|(_, len)| len)
    }

    fn value_data_type_len(&self, vk: u32) -> Option<(u32, usize)> {
        let b = self.cell_body(vk)?;
        let data_len_raw = u32le(b, 0x04)?;
        let data_off = u32le(b, 0x08)?;
        let reg_type = u32le(b, 0x0c)?;
        let inline = data_len_raw & 0x8000_0000 != 0;
        let len = (data_len_raw & 0x7fff_ffff) as usize;
        let len = if inline {
            len.min(4)
        } else {
            len.min(self.cell_body_len(data_off)?)
        };
        Some((reg_type, len))
    }
}

/// Copy a real read-only `regf` image into the mutable Hive Manager arena.
///
/// The returned hive is clean: import-time construction does not appear as dirty runtime state, and
/// the first later `HiveManager::mutate` call owns sequence number 1. Malformed value records are
/// counted and skipped, matching the read-only parser's fail-closed cell access.
pub fn import_regf_into_hive(source: &RegfHive<'_>, kind: HiveKind) -> (Hive, RegfHiveImportStats) {
    let mut target = Hive::new(kind);
    let counts = count_regf_key_cells(source, source.root(), 0);
    let imported_cells = counts.keys.saturating_add(counts.values);
    let live_cells =
        imported_cells.saturating_add(live_mutation_cell_headroom(kind, imported_cells));
    let live_value_blobs = counts
        .values
        .saturating_add(live_mutation_value_headroom(kind, counts.values));

    // Imported hives become live Configuration Manager authority immediately. Leave measured arena
    // headroom for early boot mutations without doubling large hives.
    let _ = target.reserve_cells(live_cells.saturating_sub(1));
    let _ = target.reserve_value_blobs(live_value_blobs);
    let mut stats = RegfHiveImportStats {
        keys: 1,
        ..RegfHiveImportStats::default()
    };
    let root = target.root();
    import_regf_key_into_hive(source, source.root(), &mut target, root, &mut stats, 0);
    target.finish_clean_import();
    (target, stats)
}

fn count_regf_key_cells(
    source: &RegfHive<'_>,
    source_key: KeyRef,
    depth: usize,
) -> RegfHiveCellCounts {
    if depth > 256 {
        return RegfHiveCellCounts::default();
    }
    let mut counts = RegfHiveCellCounts {
        keys: 1,
        values: source.value_count(source_key),
    };
    for index in 0.. {
        let Some(source_child) = source.subkey_ref_by_index(source_key, index) else {
            break;
        };
        let child = count_regf_key_cells(source, source_child, depth + 1);
        counts.keys = counts.keys.saturating_add(child.keys);
        counts.values = counts.values.saturating_add(child.values);
    }
    counts
}

fn import_regf_key_into_hive(
    source: &RegfHive<'_>,
    source_key: KeyRef,
    target: &mut Hive,
    target_key: CellId,
    stats: &mut RegfHiveImportStats,
    depth: usize,
) {
    if depth > 256 {
        return;
    }
    for index in 0..source.value_count(source_key) {
        let Some((name, raw_type, data)) = source.value_by_index(source_key, index) else {
            stats.skipped_values += 1;
            continue;
        };
        let value_type = RegistryValueType::from_u32(raw_type).unwrap_or(RegistryValueType::Binary);
        if target.set_value(target_key, &name, value_type, data) {
            stats.values += 1;
        } else {
            stats.skipped_values += 1;
        }
    }
    for (child_name, source_child) in source.subkeys_raw(source_key) {
        let target_child = target.create_subkey(target_key, &child_name);
        stats.keys += 1;
        import_regf_key_into_hive(source, source_child, target, target_child, stats, depth + 1);
    }
}

/// Import counts for a control-set snapshot loaded into Configuration Manager state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlSetImportCounts {
    pub services: usize,
    pub enum_devnodes: usize,
    pub class_keys: usize,
    pub service_group_order_values: usize,
}

/// Import the control-set state needed to select boot/system drivers from a read-only REGF hive.
pub fn import_control_set_boot_config_into_config_manager(
    hive: &RegfHive<'_>,
    cm: &mut ConfigManager,
    control_set: &str,
) -> ControlSetImportCounts {
    ControlSetImportCounts {
        services: import_control_set_services_into_config_manager(hive, cm, control_set),
        enum_devnodes: import_control_set_enum_into_config_manager(hive, cm, control_set),
        class_keys: import_control_set_class_into_config_manager(hive, cm, control_set),
        service_group_order_values: import_control_set_service_group_order_into_config_manager(
            hive,
            cm,
            control_set,
        ),
    }
}

/// Import `ControlSetXXX\Services` from a read-only REGF hive into
/// `\Registry\Machine\System\CurrentControlSet\Services`.
pub fn import_control_set_services_into_config_manager(
    hive: &RegfHive<'_>,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_services_path = String::from(control_set);
    src_services_path.push_str("\\Services");
    let Some(src_services) = hive.open_key(&src_services_path) else {
        return 0;
    };
    let dst_services = cm.registry_mut().create_key(SERVICES_PATH);
    let service_names = hive.subkeys_raw(src_services);
    let count = service_names.len();
    for (name, src_service) in service_names {
        let dst_service = cm.registry_mut().create_subkey(dst_services, &name);
        import_regf_key(hive, src_service, cm.registry_mut(), dst_service);
    }
    count
}

/// Import `ControlSetXXX\Enum` from a read-only REGF hive into
/// `\Registry\Machine\System\CurrentControlSet\Enum`, then index devnode records from the imported
/// registry keys.
pub fn import_control_set_enum_into_config_manager(
    hive: &RegfHive<'_>,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_enum_path = String::from(control_set);
    src_enum_path.push_str("\\Enum");
    let Some(src_enum) = hive.open_key(&src_enum_path) else {
        return 0;
    };
    let dst_enum = cm.registry_mut().create_key(ENUM_PATH);
    import_regf_key(hive, src_enum, cm.registry_mut(), dst_enum);
    cm.index_registry_devnodes()
}

/// Import `ControlSetXXX\Control\Class` from a read-only REGF hive into
/// `\Registry\Machine\System\CurrentControlSet\Control\Class`.
pub fn import_control_set_class_into_config_manager(
    hive: &RegfHive<'_>,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_path = String::from(control_set);
    src_path.push_str("\\Control\\Class");
    let Some(src_class) = hive.open_key(&src_path) else {
        return 0;
    };
    let dst_class = cm.registry_mut().create_key(CONTROL_CLASS_PATH);
    let class_names = hive.subkeys_raw(src_class);
    let count = class_names.len();
    for (name, src_child) in class_names {
        let dst_child = cm.registry_mut().create_subkey(dst_class, &name);
        import_regf_key(hive, src_child, cm.registry_mut(), dst_child);
    }
    count
}

/// Import `ControlSetXXX\Control\ServiceGroupOrder` from a read-only REGF hive into
/// `\Registry\Machine\System\CurrentControlSet\Control\ServiceGroupOrder`.
pub fn import_control_set_service_group_order_into_config_manager(
    hive: &RegfHive<'_>,
    cm: &mut ConfigManager,
    control_set: &str,
) -> usize {
    let mut src_path = String::from(control_set);
    src_path.push_str("\\Control\\ServiceGroupOrder");
    let Some(src_key) = hive.open_key(&src_path) else {
        return 0;
    };
    let value_count = hive.values(src_key).len();
    let dst_key = cm.registry_mut().create_key(SERVICE_GROUP_ORDER_PATH);
    import_regf_key(hive, src_key, cm.registry_mut(), dst_key);
    value_count
}

fn import_regf_key(hive: &RegfHive<'_>, src: KeyRef, dst: &mut Registry, dst_key: RegistryKeyId) {
    let mut index = 0usize;
    while let Some((value_name, raw_type, data)) = hive.value_by_index(src, index) {
        let value_type = RegistryValueType::from_u32(raw_type).unwrap_or(RegistryValueType::Binary);
        let _ = dst.set_value(dst_key, &value_name, value_type, data);
        index += 1;
    }
    for (child_name, src_child) in hive.subkeys_raw(src) {
        let dst_child = dst.create_subkey(dst_key, &child_name);
        import_regf_key(hive, src_child, dst, dst_child);
    }
}

/// Fold a path component for case-insensitive comparison.
fn fold(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        for lc in c.to_lowercase() {
            out.push(lc);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_nk(data: &mut [u8], cell: u32, parent: u32, name: &[u8]) {
        let offset = HBIN_BASE + cell as usize;
        data[offset..offset + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        let body = offset + 4;
        data[body..body + 2].copy_from_slice(b"nk");
        write_u16(data, body + 0x02, 0x20); // compressed (single-byte) name
        write_u32(data, body + 0x10, parent);
        write_u16(data, body + 0x48, name.len() as u16);
        data[body + 0x4c..body + 0x4c + name.len()].copy_from_slice(name);
    }

    fn write_subkey_list(data: &mut [u8], cell: u32, children: &[u32]) {
        let offset = HBIN_BASE + cell as usize;
        data[offset..offset + 4].copy_from_slice(&(-0x40i32).to_le_bytes());
        let body = offset + 4;
        data[body..body + 2].copy_from_slice(b"lf");
        write_u16(data, body + 0x02, children.len() as u16);
        for (i, child) in children.iter().enumerate() {
            write_u32(data, body + 0x04 + i * 8, *child);
        }
    }

    fn set_nk_subkeys(data: &mut [u8], cell: u32, list: u32) {
        let body = HBIN_BASE + cell as usize + 4;
        write_u32(data, body + 0x1c, list);
    }

    fn set_nk_values(data: &mut [u8], cell: u32, list: u32, count: usize) {
        let body = HBIN_BASE + cell as usize + 4;
        write_u32(data, body + 0x24, count as u32);
        write_u32(data, body + 0x28, list);
    }

    fn write_value_list(data: &mut [u8], cell: u32, values: &[u32]) {
        let offset = HBIN_BASE + cell as usize;
        data[offset..offset + 4].copy_from_slice(&(-0x40i32).to_le_bytes());
        let body = offset + 4;
        for (i, value) in values.iter().enumerate() {
            write_u32(data, body + i * 4, *value);
        }
    }

    fn write_data_cell(data: &mut [u8], cell: u32, bytes: &[u8]) {
        let offset = HBIN_BASE + cell as usize;
        data[offset..offset + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        data[offset + 4..offset + 4 + bytes.len()].copy_from_slice(bytes);
    }

    fn write_vk_data(data: &mut [u8], cell: u32, name: &[u8], value_type: u32, data_cell: u32) {
        let offset = HBIN_BASE + cell as usize;
        data[offset..offset + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        let body = offset + 4;
        data[body..body + 2].copy_from_slice(b"vk");
        write_u16(data, body + 0x02, name.len() as u16);
        data[body + 0x14..body + 0x14 + name.len()].copy_from_slice(name);
        write_u32(data, body + 0x08, data_cell);
        write_u32(data, body + 0x0c, value_type);
        write_u16(data, body + 0x10, 1); // compressed ASCII value name
    }

    fn write_vk_inline_dword(data: &mut [u8], cell: u32, name: &[u8], value: u32) {
        let offset = HBIN_BASE + cell as usize;
        data[offset..offset + 4].copy_from_slice(&(-0x80i32).to_le_bytes());
        let body = offset + 4;
        data[body..body + 2].copy_from_slice(b"vk");
        write_u16(data, body + 0x02, name.len() as u16);
        write_u32(data, body + 0x04, 0x8000_0004);
        write_u32(data, body + 0x08, value);
        write_u32(data, body + 0x0c, RegistryValueType::Dword as u32);
        write_u16(data, body + 0x10, 1); // compressed ASCII value name
        data[body + 0x14..body + 0x14 + name.len()].copy_from_slice(name);
    }

    fn utf16le_sz(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in s.encode_utf16().chain(core::iter::once(0)) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn path_test_hive() -> Vec<u8> {
        const ROOT: u32 = 0x20;
        const CHILD: u32 = 0xa0;
        const GRANDCHILD: u32 = 0x120;
        let mut data = vec![0u8; 0x2000];
        data[..4].copy_from_slice(b"regf");
        write_u32(&mut data, 0x24, ROOT);
        write_nk(&mut data, ROOT, u32::MAX, b"SYSTEM");
        write_nk(&mut data, CHILD, ROOT, b"ControlSet001");
        write_nk(&mut data, GRANDCHILD, CHILD, b"Control");
        data
    }

    fn services_test_hive() -> Vec<u8> {
        const ROOT: u32 = 0x20;
        const CONTROL_SET: u32 = 0x100;
        const SERVICES: u32 = 0x180;
        const NPFS: u32 = 0x240;
        const PARAMETERS: u32 = 0x300;
        const CONTROL: u32 = 0x880;
        const SERVICE_GROUP_ORDER: u32 = 0x900;
        const ENUM: u32 = 0xb00;
        const ENUM_PCI: u32 = 0xb80;
        const ENUM_DEVICE: u32 = 0xc00;
        const ENUM_INSTANCE: u32 = 0xc80;

        const ROOT_LIST: u32 = 0x380;
        const CS_LIST: u32 = 0x3c0;
        const SERVICES_LIST: u32 = 0x400;
        const NPFS_LIST: u32 = 0x440;
        const CONTROL_LIST: u32 = 0x980;
        const ENUM_LIST: u32 = 0xd00;
        const ENUM_PCI_LIST: u32 = 0xd40;
        const ENUM_DEVICE_LIST: u32 = 0xd80;

        const NPFS_VALUE_LIST: u32 = 0x480;
        const VK_IMAGE: u32 = 0x500;
        const VK_TYPE: u32 = 0x580;
        const VK_START: u32 = 0x600;
        const VK_ERROR: u32 = 0x680;
        const IMAGE_DATA: u32 = 0x700;

        const PARAM_VALUE_LIST: u32 = 0x780;
        const VK_ANSWER: u32 = 0x800;
        const SGO_VALUE_LIST: u32 = 0x9c0;
        const VK_SGO_LIST: u32 = 0xa00;
        const SGO_LIST_DATA: u32 = 0xa80;
        const ENUM_INSTANCE_VALUE_LIST: u32 = 0xdc0;
        const VK_ENUM_SERVICE: u32 = 0xe00;
        const VK_ENUM_PDO: u32 = 0xe80;
        const VK_ENUM_HWID: u32 = 0xf00;
        const ENUM_SERVICE_DATA: u32 = 0xf80;
        const ENUM_PDO_DATA: u32 = 0x1000;
        const ENUM_HWID_DATA: u32 = 0x1080;

        let mut data = vec![0u8; 0x3000];
        data[..4].copy_from_slice(b"regf");
        write_u32(&mut data, 0x24, ROOT);

        write_nk(&mut data, ROOT, u32::MAX, b"SYSTEM");
        write_nk(&mut data, CONTROL_SET, ROOT, b"ControlSet001");
        write_nk(&mut data, SERVICES, CONTROL_SET, b"Services");
        write_nk(&mut data, NPFS, SERVICES, b"Npfs");
        write_nk(&mut data, PARAMETERS, NPFS, b"Parameters");
        write_nk(&mut data, CONTROL, CONTROL_SET, b"Control");
        write_nk(
            &mut data,
            SERVICE_GROUP_ORDER,
            CONTROL,
            b"ServiceGroupOrder",
        );
        write_nk(&mut data, ENUM, CONTROL_SET, b"Enum");
        write_nk(&mut data, ENUM_PCI, ENUM, b"PCI");
        write_nk(&mut data, ENUM_DEVICE, ENUM_PCI, b"VEN_8086&DEV_100E");
        write_nk(&mut data, ENUM_INSTANCE, ENUM_DEVICE, b"3&11583659&0&18");

        write_subkey_list(&mut data, ROOT_LIST, &[CONTROL_SET]);
        write_subkey_list(&mut data, CS_LIST, &[SERVICES, CONTROL, ENUM]);
        write_subkey_list(&mut data, SERVICES_LIST, &[NPFS]);
        write_subkey_list(&mut data, NPFS_LIST, &[PARAMETERS]);
        write_subkey_list(&mut data, CONTROL_LIST, &[SERVICE_GROUP_ORDER]);
        write_subkey_list(&mut data, ENUM_LIST, &[ENUM_PCI]);
        write_subkey_list(&mut data, ENUM_PCI_LIST, &[ENUM_DEVICE]);
        write_subkey_list(&mut data, ENUM_DEVICE_LIST, &[ENUM_INSTANCE]);
        set_nk_subkeys(&mut data, ROOT, ROOT_LIST);
        set_nk_subkeys(&mut data, CONTROL_SET, CS_LIST);
        set_nk_subkeys(&mut data, SERVICES, SERVICES_LIST);
        set_nk_subkeys(&mut data, NPFS, NPFS_LIST);
        set_nk_subkeys(&mut data, CONTROL, CONTROL_LIST);
        set_nk_subkeys(&mut data, ENUM, ENUM_LIST);
        set_nk_subkeys(&mut data, ENUM_PCI, ENUM_PCI_LIST);
        set_nk_subkeys(&mut data, ENUM_DEVICE, ENUM_DEVICE_LIST);

        write_value_list(
            &mut data,
            NPFS_VALUE_LIST,
            &[VK_IMAGE, VK_TYPE, VK_START, VK_ERROR],
        );
        set_nk_values(&mut data, NPFS, NPFS_VALUE_LIST, 4);
        let image = utf16le_sz(r"system32\drivers\npfs.sys");
        write_data_cell(&mut data, IMAGE_DATA, &image);
        write_vk_data(
            &mut data,
            VK_IMAGE,
            b"ImagePath",
            RegistryValueType::ExpandSz as u32,
            IMAGE_DATA,
        );
        write_u32(
            &mut data,
            HBIN_BASE + VK_IMAGE as usize + 4 + 0x04,
            image.len() as u32,
        );
        write_vk_inline_dword(
            &mut data,
            VK_TYPE,
            b"Type",
            nt_config_manager::SERVICE_FILE_SYSTEM_DRIVER,
        );
        write_vk_inline_dword(
            &mut data,
            VK_START,
            b"Start",
            nt_config_manager::SERVICE_SYSTEM_START,
        );
        write_vk_inline_dword(&mut data, VK_ERROR, b"ErrorControl", 1);

        write_value_list(&mut data, PARAM_VALUE_LIST, &[VK_ANSWER]);
        set_nk_values(&mut data, PARAMETERS, PARAM_VALUE_LIST, 1);
        write_vk_inline_dword(&mut data, VK_ANSWER, b"Answer", 42);

        write_value_list(&mut data, SGO_VALUE_LIST, &[VK_SGO_LIST]);
        set_nk_values(&mut data, SERVICE_GROUP_ORDER, SGO_VALUE_LIST, 1);
        let group_order =
            nt_config_manager::encode_multi_sz(&["FSFilter Infrastructure", "File System"]);
        write_data_cell(&mut data, SGO_LIST_DATA, &group_order);
        write_vk_data(
            &mut data,
            VK_SGO_LIST,
            b"List",
            RegistryValueType::MultiSz as u32,
            SGO_LIST_DATA,
        );
        write_u32(
            &mut data,
            HBIN_BASE + VK_SGO_LIST as usize + 4 + 0x04,
            group_order.len() as u32,
        );

        write_value_list(
            &mut data,
            ENUM_INSTANCE_VALUE_LIST,
            &[VK_ENUM_SERVICE, VK_ENUM_PDO, VK_ENUM_HWID],
        );
        set_nk_values(&mut data, ENUM_INSTANCE, ENUM_INSTANCE_VALUE_LIST, 3);
        let enum_service = utf16le_sz("E1000");
        write_data_cell(&mut data, ENUM_SERVICE_DATA, &enum_service);
        write_vk_data(
            &mut data,
            VK_ENUM_SERVICE,
            b"Service",
            RegistryValueType::Sz as u32,
            ENUM_SERVICE_DATA,
        );
        write_u32(
            &mut data,
            HBIN_BASE + VK_ENUM_SERVICE as usize + 4 + 0x04,
            enum_service.len() as u32,
        );
        let pdo_name = utf16le_sz(r"\Device\NTPNP_PCI0001");
        write_data_cell(&mut data, ENUM_PDO_DATA, &pdo_name);
        write_vk_data(
            &mut data,
            VK_ENUM_PDO,
            b"PdoName",
            RegistryValueType::Sz as u32,
            ENUM_PDO_DATA,
        );
        write_u32(
            &mut data,
            HBIN_BASE + VK_ENUM_PDO as usize + 4 + 0x04,
            pdo_name.len() as u32,
        );
        let hardware_ids =
            nt_config_manager::encode_multi_sz(&[r"PCI\VEN_8086&DEV_100E", r"PCI\VEN_8086"]);
        write_data_cell(&mut data, ENUM_HWID_DATA, &hardware_ids);
        write_vk_data(
            &mut data,
            VK_ENUM_HWID,
            b"HardwareID",
            RegistryValueType::MultiSz as u32,
            ENUM_HWID_DATA,
        );
        write_u32(
            &mut data,
            HBIN_BASE + VK_ENUM_HWID as usize + 4 + 0x04,
            hardware_ids.len() as u32,
        );

        data
    }

    #[test]
    fn reconstructs_key_path_relative_to_root() {
        let data = path_test_hive();
        let hive = RegfHive::new(&data).expect("valid test hive");
        assert_eq!(hive.key_path(hive.root()).as_deref(), Some(""));
        assert_eq!(hive.key_path(0xa0).as_deref(), Some("ControlSet001"));
        assert_eq!(
            hive.key_path(0x120).as_deref(),
            Some("ControlSet001\\Control")
        );
    }

    #[test]
    fn rejects_cyclic_key_parents() {
        let mut data = path_test_hive();
        write_u32(&mut data, HBIN_BASE + 0xa0 + 4 + 0x10, 0x120);
        let hive = RegfHive::new(&data).expect("valid test hive");
        assert_eq!(hive.key_path(0x120), None);
    }

    #[test]
    fn imports_services_into_config_manager() {
        let data = services_test_hive();
        let hive = RegfHive::new(&data).expect("valid test hive");
        let services = hive
            .open_key(r"ControlSet001\Services")
            .expect("services key");
        assert_eq!(
            hive.subkeys(services)
                .first()
                .map(|(name, _)| name.as_str()),
            Some("npfs")
        );
        assert_eq!(
            hive.subkeys_raw(services)
                .first()
                .map(|(name, _)| name.as_str()),
            Some("Npfs")
        );
        assert_eq!(
            hive.subkey_by_index(services, 0)
                .map(|(name, _)| name)
                .as_deref(),
            Some("npfs")
        );
        assert_eq!(hive.subkey_name_utf16_len_by_index(services, 0), Some(4));
        assert!(hive.subkey_by_index(services, 1).is_none());
        let npfs = hive.open_key(r"ControlSet001\Services\Npfs").unwrap();
        assert_eq!(hive.value_count(npfs), 4);
        assert!(hive.value_exists(npfs, "ImagePath"));
        assert!(!hive.value_exists(npfs, "Missing"));
        assert_eq!(
            hive.value_matches(
                npfs,
                "ImagePath",
                RegistryValueType::ExpandSz as u32,
                utf16le_sz(r"system32\drivers\npfs.sys").as_slice(),
            ),
            Some(true)
        );
        assert_eq!(
            hive.value_matches(
                npfs,
                "ImagePath",
                RegistryValueType::ExpandSz as u32,
                b"small"
            ),
            Some(false)
        );
        let (name, ty, data) = hive.value_by_index(npfs, 0).unwrap();
        assert_eq!(name, "ImagePath");
        assert_eq!(ty, RegistryValueType::ExpandSz as u32);
        assert_eq!(data, utf16le_sz(r"system32\drivers\npfs.sys"));
        assert_eq!(
            hive.value_lengths_by_index(npfs, 0),
            Some((
                "ImagePath".len() * 2,
                utf16le_sz(r"system32\drivers\npfs.sys").len()
            ))
        );

        let mut cm = ConfigManager::new();
        assert_eq!(
            import_control_set_services_into_config_manager(&hive, &mut cm, "ControlSet001"),
            1
        );
        let svc = cm.service_metadata("npfs").expect("imported service");
        assert_eq!(svc.name, "Npfs");
        assert_eq!(
            svc.image_path.as_deref(),
            Some(r"system32\drivers\npfs.sys")
        );
        assert_eq!(
            svc.driver_service_class(),
            Some(nt_config_manager::DriverServiceClass::FileSystem)
        );
        let drivers = cm.boot_system_driver_candidates();
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].name, "Npfs");

        let answer = cm
            .registry()
            .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\Npfs\Parameters")
            .and_then(|key| cm.registry().query_dword(key, "Answer"));
        assert_eq!(answer, Some(42));
    }

    #[test]
    fn imports_regf_into_mutable_hive_authority() {
        let data = services_test_hive();
        let source = RegfHive::new(&data).expect("valid test hive");
        let counts = count_regf_key_cells(&source, source.root(), 0);
        let (mut hive, stats) = import_regf_into_hive(&source, HiveKind::System);

        assert_eq!(
            stats,
            RegfHiveImportStats {
                keys: 11,
                values: 9,
                skipped_values: 0,
            }
        );
        assert_eq!(counts.keys, stats.keys);
        assert_eq!(counts.values, stats.values);
        assert_eq!(hive.dirty_count(), 0);
        assert_eq!(hive.sequence, 0);
        assert_eq!(hive.generation, 0);

        let npfs = hive.open_key(r"ControlSet001\Services\Npfs").expect("Npfs");
        assert_eq!(
            hive.query_dword(npfs, "Type"),
            Some(nt_config_manager::SERVICE_FILE_SYSTEM_DRIVER)
        );
        assert_eq!(
            hive.query_dword(npfs, "Start"),
            Some(nt_config_manager::SERVICE_SYSTEM_START)
        );
        let (image_ty, image_data) = hive.query_value(npfs, "ImagePath").unwrap();
        assert_eq!(image_ty, RegistryValueType::ExpandSz);
        assert_eq!(
            image_data,
            utf16le_sz(r"system32\drivers\npfs.sys").as_slice()
        );

        let answer = hive
            .open_key(r"ControlSet001\Services\Npfs\Parameters")
            .and_then(|key| hive.query_dword(key, "Answer"));
        assert_eq!(answer, Some(42));
        let enum_instance = hive
            .open_key(r"ControlSet001\Enum\PCI\VEN_8086&DEV_100E\3&11583659&0&18")
            .expect("PCI instance");
        let (service_ty, service_data) = hive.query_value(enum_instance, "Service").unwrap();
        assert_eq!(service_ty, RegistryValueType::Sz);
        assert_eq!(service_data, utf16le_sz("E1000").as_slice());

        let mut manager = nt_hive_core::HiveManager::new(nt_hive_core::MemoryHiveIoProvider::new());
        manager.flush(&mut hive).expect("checkpoint imported hive");
        let provider = manager.into_provider();
        let mut reboot_manager = nt_hive_core::HiveManager::new(provider);
        let rebooted = reboot_manager.boot(HiveKind::System).expect("reboot hive");
        let reboot_npfs = rebooted
            .open_key(r"ControlSet001\Services\Npfs")
            .expect("rebooted Npfs");
        assert_eq!(rebooted.query_dword(reboot_npfs, "ErrorControl"), Some(1));
        let (reboot_image_ty, reboot_image_data) =
            rebooted.query_value(reboot_npfs, "ImagePath").unwrap();
        assert_eq!(reboot_image_ty, RegistryValueType::ExpandSz);
        assert_eq!(
            reboot_image_data,
            utf16le_sz(r"system32\drivers\npfs.sys").as_slice()
        );
        assert_eq!(rebooted.dirty_count(), 0);
    }

    #[test]
    fn imports_boot_config_into_config_manager() {
        let data = services_test_hive();
        let hive = RegfHive::new(&data).expect("valid test hive");
        let mut cm = ConfigManager::new();
        let counts =
            import_control_set_boot_config_into_config_manager(&hive, &mut cm, "ControlSet001");

        assert_eq!(
            counts,
            ControlSetImportCounts {
                services: 1,
                enum_devnodes: 1,
                class_keys: 0,
                service_group_order_values: 1,
            }
        );
        assert_eq!(
            cm.service_group_order(),
            vec![
                String::from("FSFilter Infrastructure"),
                String::from("File System"),
            ]
        );
        assert_eq!(cm.boot_system_driver_candidates()[0].name, "Npfs");
        let devnode = cm
            .devnode(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18")
            .unwrap();
        assert_eq!(devnode.service.as_deref(), Some("E1000"));
        assert_eq!(devnode.pdo_name.as_deref(), Some(r"\Device\NTPNP_PCI0001"));
        assert_eq!(
            devnode.hardware_ids,
            vec![
                String::from(r"PCI\VEN_8086&DEV_100E"),
                String::from(r"PCI\VEN_8086"),
            ]
        );
    }

    #[test]
    fn reactos_system_hive_session_manager() {
        let bytes = match std::fs::read("/tmp/ros-system.hiv") {
            Ok(b) => b,
            Err(_) => {
                eprintln!("skip: /tmp/ros-system.hiv not present");
                return;
            }
        };
        let hive = RegfHive::new(&bytes).expect("valid regf hive");
        // The exact key smss's SmpInit reads (sminit.c:2328), after the CurrentControlSet alias.
        let sm = hive
            .open_key("ControlSet001\\Control\\Session Manager")
            .expect("Session Manager key must resolve in the real ReactOS SYSTEM hive");
        // It has subkeys (Environment, DOS Devices, KnownDLLs, SubSystems, Memory Management, …).
        let subs = hive.subkeys(sm);
        assert!(!subs.is_empty(), "Session Manager should have subkeys");
        let names: Vec<&str> = subs.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.iter().any(|n| n.contains("environment")),
            "expected an Environment subkey, got {names:?}"
        );
        // A well-known value under Session Manager.
        if let Some(sub) = hive.open_key("ControlSet001\\Control\\Session Manager\\SubSystems") {
            let vals = hive.values(sub);
            assert!(
                !vals.is_empty(),
                "SubSystems should have values (Required/Windows/…)"
            );
        }
    }

    #[test]
    fn reactos_system_hive_import_preserves_known_dll_directory() {
        let bytes =
            match std::fs::read("../../rust-micro/.tmp/reactos/reactos/system32/config/system")
                .or_else(|_| std::fs::read("/tmp/ros-system.hiv"))
            {
                Ok(bytes) => bytes,
                Err(_) => {
                    eprintln!("skip: staged ReactOS SYSTEM hive not present");
                    return;
                }
            };
        let source = RegfHive::new(&bytes).expect("valid regf hive");
        let (hive, stats) = import_regf_into_hive(&source, HiveKind::System);
        assert!(
            stats.values > 0,
            "expected imported values from the ReactOS SYSTEM hive"
        );

        let known_dlls = hive
            .open_key(r"ControlSet001\Control\Session Manager\KnownDlls")
            .expect("SMSS KnownDlls key must survive mutable-hive import");
        let (ty, data) = hive
            .query_value(known_dlls, "DllDirectory")
            .expect("SMSS KnownDlls\\DllDirectory value must survive mutable-hive import");
        assert_eq!(ty, RegistryValueType::ExpandSz);
        assert_eq!(data, utf16le_sz(r"%SystemRoot%\system32").as_slice());
        assert!(
            hive.value_count(known_dlls) > 1,
            "KnownDlls should carry DLL entries as well as DllDirectory"
        );

        let mut hives = nt_hive_core::MutableHiveSet::new();
        hives.mount(r"\Registry\Machine\System", 0, hive);
        let known_dlls = hives
            .resolve_key(
                r"\registry\machine\system\currentcontrolset\control\session manager\KnownDlls",
            )
            .expect("SMSS KnownDlls key must resolve through mutable hive mount");
        let (ty, data) = hives
            .query_value(known_dlls, "DllDirectory")
            .expect("SMSS KnownDlls\\DllDirectory value must resolve through mutable hive mount");
        assert_eq!(ty, RegistryValueType::ExpandSz);
        assert_eq!(data, utf16le_sz(r"%SystemRoot%\system32").as_slice());
    }

    #[test]
    fn windows_hiv_fixture_parses() {
        // A tiny real Windows hive shipped in references/ — validates base block + root nk.
        let path = "../../references/windows-kits/10/Assessment and Deployment Kit/Deployment Tools/amd64/DISM/WofAdk.hiv";
        match std::fs::read(path) {
            Ok(bytes) => {
                let hive = RegfHive::new(&bytes).expect("valid regf hive");
                // Root must be an nk; enumerating subkeys must stay in-bounds / not panic.
                let _ = hive.subkeys(hive.root());
            }
            Err(_) => eprintln!("skip: WofAdk.hiv fixture not present"),
        }
    }

    /// The genuine ReactOS `\reactos\system32\config\default` hive — the `HKEY_USERS\.DEFAULT`
    /// prototype that setup copies to become a new user's `ntuser.dat`, and therefore the hive the
    /// executive mounts through `NtLoadKey`. This asserts the two structures that flow depends on:
    /// the `Shell Folders` key `userenv!UpdateUsersShellFolderSettings` writes into, and the
    /// `Environment` values `RegCopyTreeW` carries across.
    #[test]
    fn reactos_default_user_hive_has_the_profile_keys() {
        let path = "../../rust-micro/.tmp/reactos/reactos/system32/config/default";
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("skip: staged `config\\default` not present");
            return;
        };
        let hive = RegfHive::new(&bytes).expect("the staged `config\\default` must be a regf hive");
        let roots: Vec<String> = hive
            .subkeys(hive.root())
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        for expected in ["environment", "control panel", "software"] {
            assert!(
                roots.iter().any(|n| n == expected),
                "missing {expected} in {roots:?}"
            );
        }
        hive.open_key(r"software\microsoft\windows\currentversion\explorer\shell folders")
            .expect("UpdateUsersShellFolderSettings needs `Shell Folders`");
        let env = hive.open_key("environment").expect("Environment");
        let names: Vec<String> = hive.values(env).into_iter().map(|(n, _)| n).collect();
        assert!(
            names.iter().any(|n| n == "temp"),
            "expected TEMP, got {names:?}"
        );
    }

    #[test]
    fn local_reactos_system_hive_boot_driver_metadata() {
        let path = "../../rust-micro/.tmp/reactos/reactos/system32/config/system";
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("skip: staged `config\\system` not present");
            return;
        };
        let hive = RegfHive::new(&bytes).expect("the staged `config\\system` must be a regf hive");
        let mut cm = ConfigManager::new();
        let counts =
            import_control_set_boot_config_into_config_manager(&hive, &mut cm, "ControlSet001");
        assert!(counts.services > 0, "expected imported service keys");
        eprintln!("imported Enum devnodes: {}", counts.enum_devnodes);
        assert!(
            counts.service_group_order_values > 0,
            "expected ServiceGroupOrder values"
        );
        assert!(
            !cm.service_group_order().is_empty(),
            "expected a non-empty ServiceGroupOrder list"
        );
        let drivers = cm.boot_system_driver_candidates();
        eprintln!(
            "boot/system driver prefix: {:?}",
            drivers
                .iter()
                .take(12)
                .map(|service| (
                    service.name.as_str(),
                    service.start_type,
                    service.load_order_group.as_deref(),
                    service.tag,
                    service.image_path.as_deref(),
                ))
                .collect::<Vec<_>>()
        );
        let npfs_rank = drivers
            .iter()
            .position(|service| service.name.eq_ignore_ascii_case("Npfs"));
        eprintln!("Npfs rank in boot/system driver candidates: {npfs_rank:?}");
        if let Some(rank) = npfs_rank {
            let start = rank.saturating_sub(4);
            let end = (rank + 5).min(drivers.len());
            eprintln!(
                "Npfs boot/system neighborhood: {:?}",
                drivers[start..end]
                    .iter()
                    .map(|service| (
                        service.name.as_str(),
                        service.start_type,
                        service.load_order_group.as_deref(),
                        service.tag,
                        service.image_path.as_deref(),
                    ))
                    .collect::<Vec<_>>()
            );
        }
        assert!(
            npfs_rank.is_some(),
            "expected Npfs in boot/system driver candidates"
        );
    }

    #[test]
    fn rejects_non_regf() {
        assert!(RegfHive::new(&[0u8; 0x2000]).is_none());
        assert!(RegfHive::new(b"not a hive").is_none());
    }

    #[test]
    fn exposes_the_borrowed_hive_image() {
        let data = path_test_hive();
        let hive = RegfHive::new(&data).expect("valid test hive");
        assert_eq!(hive.bytes(), data.as_slice());
    }
}
