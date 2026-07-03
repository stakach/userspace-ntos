//! `UNICODE_STRING` projection (spec §7.1).

use bytemuck::{Pod, Zeroable};

use crate::GuestAddr;

/// `UNICODE_STRING` (x64, 16 bytes). `length`/`maximum_length` are **byte** counts
/// (not code units); `buffer` is a guest address to UTF-16LE code units.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub _reserved: u32,
    pub buffer: GuestAddr,
}

impl UnicodeString {
    /// A `UNICODE_STRING` describing `code_units` code units at guest `buffer`.
    pub fn new(buffer: GuestAddr, code_units: usize) -> Self {
        let bytes = (code_units * 2) as u16;
        Self {
            length: bytes,
            maximum_length: bytes,
            _reserved: 0,
            buffer,
        }
    }

    /// The number of UTF-16 code units (`length` is in bytes).
    pub fn code_units(self) -> usize {
        (self.length / 2) as usize
    }
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<UnicodeString>() == 16);
    assert!(offset_of!(UnicodeString, buffer) == 8);
};
