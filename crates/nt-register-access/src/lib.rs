//! # `nt-register-access` — bounded simulated-MMIO register bank
//!
//! A safe register-access abstraction for the simulated hardware backend (spec:
//! Milestone 11, §5.5, §8.6): a bounded byte buffer with width-specific
//! (`u8`/`u16`/`u32`) little-endian load/store that checks bounds, alignment, and
//! per-range read-only permissions before every access. No untrusted raw-pointer
//! dereference. `no_std` + `alloc`.
//!
//! The Driver Host may hand a loaded driver a real pointer into a bank's backing
//! store (register macros are inlined, so access is a direct dereference); this
//! type is the *checked* path used by the HAL service + host integration tests.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// Why a register access was rejected (spec §8.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegError {
    /// `offset + width` exceeds the bank length.
    OutOfBounds,
    /// `offset` is not naturally aligned for the access width.
    Misaligned,
    /// A write targeted a read-only register.
    ReadOnly,
}

/// A bounded register bank backing a simulated device.
pub struct RegisterBank {
    data: Vec<u8>,
    readonly: Vec<(u64, u64)>, // (start, len) read-only ranges
}

impl RegisterBank {
    /// A zeroed bank of `len` bytes.
    pub fn new(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
            readonly: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Mark `[offset, offset+len)` read-only (writes there fail with `ReadOnly`).
    pub fn mark_readonly(&mut self, offset: u64, len: u64) {
        self.readonly.push((offset, len));
    }

    fn in_readonly(&self, offset: u64, width: u64) -> bool {
        self.readonly
            .iter()
            .any(|&(s, l)| offset < s + l && offset + width > s)
    }

    fn check(&self, offset: u64, width: u64) -> Result<usize, RegError> {
        if !offset.is_multiple_of(width) {
            return Err(RegError::Misaligned);
        }
        let end = offset.checked_add(width).ok_or(RegError::OutOfBounds)?;
        if end > self.data.len() as u64 {
            return Err(RegError::OutOfBounds);
        }
        Ok(offset as usize)
    }

    pub fn read_u8(&self, offset: u64) -> Result<u8, RegError> {
        let i = self.check(offset, 1)?;
        Ok(self.data[i])
    }

    pub fn read_u16(&self, offset: u64) -> Result<u16, RegError> {
        let i = self.check(offset, 2)?;
        Ok(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
    }

    pub fn read_u32(&self, offset: u64) -> Result<u32, RegError> {
        let i = self.check(offset, 4)?;
        Ok(u32::from_le_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
        ]))
    }

    pub fn write_u8(&mut self, offset: u64, value: u8) -> Result<(), RegError> {
        let i = self.check(offset, 1)?;
        if self.in_readonly(offset, 1) {
            return Err(RegError::ReadOnly);
        }
        self.data[i] = value;
        Ok(())
    }

    pub fn write_u16(&mut self, offset: u64, value: u16) -> Result<(), RegError> {
        let i = self.check(offset, 2)?;
        if self.in_readonly(offset, 2) {
            return Err(RegError::ReadOnly);
        }
        self.data[i..i + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub fn write_u32(&mut self, offset: u64, value: u32) -> Result<(), RegError> {
        let i = self.check(offset, 4)?;
        if self.in_readonly(offset, 4) {
            return Err(RegError::ReadOnly);
        }
        self.data[i..i + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// Set a `u32` register bypassing the read-only check (device-side mutation,
    /// e.g. hardware raising a status bit).
    pub fn poke_u32(&mut self, offset: u64, value: u32) -> Result<(), RegError> {
        let i = self.check(offset, 4)?;
        self.data[i..i + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// A raw pointer to the backing store — for the Driver Host to hand a loaded
    /// driver as an `MmMapIoSpace` result (register macros are inlined → direct
    /// dereference). The backing store is a bounded, zeroed allocation.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_and_endianness() {
        let mut b = RegisterBank::new(16);
        b.write_u32(0, 0x4d4d_494f).unwrap();
        assert_eq!(b.read_u32(0).unwrap(), 0x4d4d_494f);
        assert_eq!(b.read_u8(0).unwrap(), 0x4f); // little-endian low byte
        assert_eq!(b.read_u16(0).unwrap(), 0x494f);
    }

    #[test]
    fn bounds_and_alignment_checked() {
        let mut b = RegisterBank::new(16);
        assert_eq!(b.read_u32(16), Err(RegError::OutOfBounds)); // aligned, past end
        assert_eq!(b.read_u16(16), Err(RegError::OutOfBounds));
        assert_eq!(b.read_u32(2), Err(RegError::Misaligned)); // alignment checked first
        assert_eq!(b.write_u16(3, 0), Err(RegError::Misaligned));
    }

    #[test]
    fn readonly_enforced() {
        let mut b = RegisterBank::new(16);
        b.mark_readonly(0, 4);
        assert_eq!(b.write_u32(0, 1), Err(RegError::ReadOnly));
        // poke bypasses (device-side).
        b.poke_u32(0, 0x1234).unwrap();
        assert_eq!(b.read_u32(0).unwrap(), 0x1234);
        // A different register is writable.
        b.write_u32(4, 9).unwrap();
        assert_eq!(b.read_u32(4).unwrap(), 9);
    }
}
