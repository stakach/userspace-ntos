//! Byte-level encoding primitives: CRC-32C + a bounds-checked writer/reader. All integers
//! little-endian; strings are UTF-16LE with an explicit byte length (spec §9.5).

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(test)]
#[path = "codec_crc32c_tests.rs"]
mod crc32c_tests;

const CRC32C_TABLE: [u32; 256] = crc32c_table();

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = 0usize;
    while byte < table.len() {
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

/// Incremental CRC-32C (Castagnoli) over exactly the supplied bytes.
pub struct Crc32c {
    crc: u32,
}

impl Crc32c {
    pub fn new() -> Self {
        Self { crc: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.crc ^ u32::from(byte)) & 0xff) as usize;
            self.crc = (self.crc >> 8) ^ CRC32C_TABLE[index];
        }
    }

    pub fn finish(self) -> u32 {
        !self.crc
    }
}

/// CRC-32C (Castagnoli, reflected poly 0x82F63B78) — the snapshot/journal checksum (spec §9.3).
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(data);
    crc.finish()
}

/// CRC-32C of two concatenated streams, given their finalized checksums and the
/// byte length of the second stream. An empty second stream has checksum zero.
///
/// Applies the linear zero-byte operator over GF(2) by repeated squaring. This
/// is the CRC concatenation mathematics also used by Mark Adler's zlib
/// `crc32_combine`, adapted to Castagnoli without polynomial-period assumptions.
/// No allocation or multiplication of the byte length by eight is required.
pub fn crc32c_combine(mut left_crc: u32, right_crc: u32, mut right_len: u64) -> u32 {
    if right_len == 0 {
        return left_crc;
    }
    let mut operator = [0u32; 32];
    for (bit, image) in operator.iter_mut().enumerate() {
        let basis = 1u32 << bit;
        *image = (basis >> 8) ^ CRC32C_TABLE[(basis & 0xff) as usize];
    }
    loop {
        if right_len & 1 != 0 {
            left_crc = apply_crc_operator(&operator, left_crc);
        }
        right_len >>= 1;
        if right_len == 0 {
            return left_crc ^ right_crc;
        }
        let mut squared = [0u32; 32];
        for (image, basis_image) in squared.iter_mut().zip(operator) {
            *image = apply_crc_operator(&operator, basis_image);
        }
        operator = squared;
    }
}

fn apply_crc_operator(operator: &[u32; 32], mut value: u32) -> u32 {
    let mut result = 0;
    while value != 0 {
        result ^= operator[value.trailing_zeros() as usize];
        value &= value - 1;
    }
    result
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
