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
    ConfigManager, Registry, RegistryKeyId, RegistryValueType, SERVICES_PATH,
    SERVICE_GROUP_ORDER_PATH,
};

const HBIN_BASE: usize = 0x1000;

/// A parsed, read-only `regf` hive borrowing its raw bytes (no copy — the hive image is large and
/// mapped once). Keys are referred to by their hbin-relative cell offset (`KeyRef`).
pub struct RegfHive<'a> {
    data: &'a [u8],
    root: u32,
}

/// A reference to a key node (its hbin-relative cell offset).
pub type KeyRef = u32;

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

    /// The cell body (after the 4-byte signed size) at a hbin-relative `offset`, bounds-checked.
    fn cell_body(&self, offset: u32) -> Option<&[u8]> {
        let fo = HBIN_BASE.checked_add(offset as usize)?;
        let size = i32le(self.data, fo)?;
        let len = (size.unsigned_abs() as usize).max(4);
        self.data.get(fo + 4..fo + len)
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

    /// Open the immediate subkey named `name` (case-insensitive) under `nk`.
    pub fn open_subkey(&self, nk: KeyRef, name: &str) -> Option<KeyRef> {
        let want = fold(name);
        self.subkeys(nk)
            .into_iter()
            .find(|(n, _)| *n == want)
            .map(|(_, o)| o)
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

    /// Read a value by name (case-insensitive) under `nk`: returns `(reg_type, data_bytes)`.
    /// Handles small (≤4 B) inline data (data-length top bit set).
    pub fn value(&self, nk: KeyRef, name: &str) -> Option<(u32, Vec<u8>)> {
        let want = fold(name);
        let vk = self
            .values(nk)
            .into_iter()
            .find(|(n, _)| *n == want)
            .map(|(_, o)| o)?;
        self.value_data(vk)
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
        let (_, vk) = self.values(nk).into_iter().nth(index)?;
        let name = self.value_name_raw(vk)?;
        let (ty, data) = self.value_data(vk)?;
        Some((name, ty, data))
    }

    fn value_data(&self, vk: u32) -> Option<(u32, Vec<u8>)> {
        let b = self.cell_body(vk)?;
        let data_len_raw = u32le(b, 0x04)?;
        let data_off = u32le(b, 0x08)?;
        let reg_type = u32le(b, 0x0c)?;
        let inline = data_len_raw & 0x8000_0000 != 0;
        let len = (data_len_raw & 0x7fff_ffff) as usize;
        if inline {
            // Data (≤4 bytes) stored directly in the data-offset field.
            let raw = data_off.to_le_bytes();
            Some((reg_type, raw.get(..len.min(4))?.to_vec()))
        } else {
            let db = self.cell_body(data_off)?;
            Some((reg_type, db.get(..len.min(db.len()))?.to_vec()))
        }
    }
}

/// Import counts for a control-set snapshot loaded into Configuration Manager state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlSetImportCounts {
    pub services: usize,
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

        const ROOT_LIST: u32 = 0x380;
        const CS_LIST: u32 = 0x3c0;
        const SERVICES_LIST: u32 = 0x400;
        const NPFS_LIST: u32 = 0x440;
        const CONTROL_LIST: u32 = 0x980;

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

        write_subkey_list(&mut data, ROOT_LIST, &[CONTROL_SET]);
        write_subkey_list(&mut data, CS_LIST, &[SERVICES, CONTROL]);
        write_subkey_list(&mut data, SERVICES_LIST, &[NPFS]);
        write_subkey_list(&mut data, NPFS_LIST, &[PARAMETERS]);
        write_subkey_list(&mut data, CONTROL_LIST, &[SERVICE_GROUP_ORDER]);
        set_nk_subkeys(&mut data, ROOT, ROOT_LIST);
        set_nk_subkeys(&mut data, CONTROL_SET, CS_LIST);
        set_nk_subkeys(&mut data, SERVICES, SERVICES_LIST);
        set_nk_subkeys(&mut data, NPFS, NPFS_LIST);
        set_nk_subkeys(&mut data, CONTROL, CONTROL_LIST);

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
    fn rejects_non_regf() {
        assert!(RegfHive::new(&[0u8; 0x2000]).is_none());
        assert!(RegfHive::new(b"not a hive").is_none());
    }
}
