//! UTF-16 string projection helpers (spec §7.4). NT strings are UTF-16LE code
//! units; these allocate a `UNICODE_STRING` + its buffer in the arena and read
//! one back.

use alloc::string::String;
use alloc::vec::Vec;

use nt_kernel_abi::{GuestAddr, UnicodeString};

use crate::arena::Arena;

/// Allocate a `UNICODE_STRING` + its UTF-16LE buffer in `arena`. Returns
/// `(unicode_string_addr, buffer_addr)`.
pub fn alloc_unicode_string(arena: &mut Arena, s: &str) -> Option<(GuestAddr, GuestAddr)> {
    let units: Vec<u16> = s.encode_utf16().collect();
    let mut buf = Vec::with_capacity(units.len() * 2);
    for u in &units {
        buf.extend_from_slice(&u.to_le_bytes());
    }
    let buf_addr = arena.alloc(buf.len().max(1), 2)?;
    arena.write_bytes(buf_addr, &buf);

    let us = UnicodeString::new(buf_addr, units.len());
    let us_addr = arena.alloc(16, 8)?;
    arena.write(us_addr, us);
    Some((us_addr, buf_addr))
}

/// Read a `UNICODE_STRING` at `addr` back into a `String`.
pub fn read_unicode_string(arena: &Arena, addr: GuestAddr) -> Option<String> {
    let us: UnicodeString = arena.read(addr)?;
    let n = us.code_units();
    let bytes = arena.slice(us.buffer, n * 2)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}
