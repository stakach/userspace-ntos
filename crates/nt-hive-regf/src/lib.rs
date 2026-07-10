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

    /// Iterate the immediate subkeys of `nk` as `(folded_name, nk_offset)`.
    pub fn subkeys(&self, nk: KeyRef) -> Vec<(String, KeyRef)> {
        let mut out = Vec::new();
        let body = match self.cell_body(nk) {
            Some(b) => b,
            None => return out,
        };
        let list_off = match u32le(body, 0x1c) {
            Some(o) if o != 0 && o != u32::MAX => o,
            _ => return out,
        };
        self.collect_subkeys(list_off, &mut out, 0);
        out
    }

    /// Walk a subkey-list cell (lf/lh/li/ri), pushing `(name, nk_off)`. `ri` recurses into its
    /// sub-lists; `depth` guards against a malformed cyclic hive.
    fn collect_subkeys(&self, list_off: u32, out: &mut Vec<(String, KeyRef)>, depth: u32) {
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
                        if let Some(name) = self.key_name_folded(off) {
                            out.push((name, off));
                        }
                    }
                }
            }
            b"li" => {
                // count × u32 nk_offset.
                for i in 0..count {
                    if let Some(off) = u32le(b, 0x04 + i * 4) {
                        if let Some(name) = self.key_name_folded(off) {
                            out.push((name, off));
                        }
                    }
                }
            }
            b"ri" => {
                // count × u32 offset-to-another-subkey-list.
                for i in 0..count {
                    if let Some(sub) = u32le(b, 0x04 + i * 4) {
                        self.collect_subkeys(sub, out, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    /// Open the immediate subkey named `name` (case-insensitive) under `nk`.
    pub fn open_subkey(&self, nk: KeyRef, name: &str) -> Option<KeyRef> {
        let want = fold(name);
        self.subkeys(nk).into_iter().find(|(n, _)| *n == want).map(|(_, o)| o)
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
        let vk = self.values(nk).into_iter().find(|(n, _)| *n == want).map(|(_, o)| o)?;
        self.value_data(vk)
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
            assert!(!vals.is_empty(), "SubSystems should have values (Required/Windows/…)");
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

    #[test]
    fn rejects_non_regf() {
        assert!(RegfHive::new(&[0u8; 0x2000]).is_none());
        assert!(RegfHive::new(b"not a hive").is_none());
    }
}
