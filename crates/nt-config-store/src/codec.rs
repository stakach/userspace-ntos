//! Byte-level encoding primitives: CRC-32C + a bounds-checked writer/reader. All integers
//! little-endian; strings are UTF-16LE with an explicit byte length (spec §9.5).

use alloc::string::String;
use alloc::vec::Vec;

/// CRC-32C (Castagnoli, reflected poly 0x82F63B78) — the snapshot/journal checksum (spec §9.3).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// An append-only little-endian byte writer.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// A length-prefixed byte blob (`u32` byte count + bytes).
    pub fn blob(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.bytes(b);
    }
    /// A length-prefixed UTF-16LE string (`u32` byte count + code units).
    pub fn str16(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        self.u32((units.len() * 2) as u32);
        for u in units {
            self.u16(u);
        }
    }
}

/// A bounds-checked little-endian byte reader. Every accessor returns `None` on truncation so a
/// malformed/untrusted snapshot never panics (spec §9.1, §23.3).
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Some(s)
    }
    /// Public bounds-checked slice read.
    pub fn take_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        self.take(n)
    }
    /// Read a fixed-size byte array (e.g. an 8-byte magic or a 16-byte GUID).
    pub fn blob_fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Some(out)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| {
            let mut b = [0u8; 8];
            b.copy_from_slice(s);
            u64::from_le_bytes(b)
        })
    }
    pub fn blob(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        self.take(n).map(|s| s.to_vec())
    }
    pub fn str16(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        let bytes = self.take(n)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(
            char::decode_utf16(units)
                .map(|r| r.unwrap_or('\u{FFFD}'))
                .collect(),
        )
    }
}
