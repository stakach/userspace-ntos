//! The driver-local guest-memory arena (spec §7.4).
//!
//! A bump allocator over a byte buffer that models the Driver Host address space
//! the loaded driver sees. Objects are addressed by [`GuestAddr`] (`base +
//! offset`); reads/writes are bounds-checked and use unaligned access (the byte
//! buffer is not guaranteed aligned to a projection's alignment).

use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;

use bytemuck::Pod;
use nt_kernel_abi::GuestAddr;

fn align_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

/// A driver-local memory arena.
pub struct Arena {
    base: u64,
    bytes: Vec<u8>,
    cursor: usize,
}

impl Arena {
    /// A fresh arena of `capacity` bytes whose guest base address is `base`.
    pub fn new(base: u64, capacity: usize) -> Self {
        Self {
            base,
            bytes: vec![0u8; capacity],
            cursor: 0,
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn used(&self) -> usize {
        self.cursor
    }
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    /// Reset the bump cursor (drops all allocations; spec §7.4 "restartable").
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.bytes.iter_mut().for_each(|b| *b = 0);
    }

    /// Bump-allocate `size` bytes aligned to `align`; returns the guest address.
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<GuestAddr> {
        let start = align_up(self.cursor, align.max(1));
        let end = start.checked_add(size.max(1))?;
        if end > self.bytes.len() {
            return None;
        }
        self.cursor = end;
        Some(GuestAddr(self.base + start as u64))
    }

    /// The buffer offset of `addr` if `[addr, addr+len)` is inside the arena.
    fn offset(&self, addr: GuestAddr, len: usize) -> Option<usize> {
        let off = addr.0.checked_sub(self.base)? as usize;
        let end = off.checked_add(len)?;
        (end <= self.bytes.len()).then_some(off)
    }

    /// True if `[addr, addr+len)` lies within the arena.
    pub fn contains(&self, addr: GuestAddr, len: usize) -> bool {
        self.offset(addr, len).is_some()
    }

    /// Read a `Pod` value at `addr` (unaligned, bounds-checked).
    pub fn read<T: Pod>(&self, addr: GuestAddr) -> Option<T> {
        let off = self.offset(addr, size_of::<T>())?;
        Some(bytemuck::pod_read_unaligned(
            &self.bytes[off..off + size_of::<T>()],
        ))
    }

    /// Write a `Pod` value at `addr` (bounds-checked). Returns `false` if out of
    /// range.
    pub fn write<T: Pod>(&mut self, addr: GuestAddr, val: T) -> bool {
        match self.offset(addr, size_of::<T>()) {
            Some(off) => {
                self.bytes[off..off + size_of::<T>()].copy_from_slice(bytemuck::bytes_of(&val));
                true
            }
            None => false,
        }
    }

    pub fn slice(&self, addr: GuestAddr, len: usize) -> Option<&[u8]> {
        self.offset(addr, len).map(|o| &self.bytes[o..o + len])
    }

    pub fn write_bytes(&mut self, addr: GuestAddr, data: &[u8]) -> bool {
        match self.offset(addr, data.len()) {
            Some(off) => {
                self.bytes[off..off + data.len()].copy_from_slice(data);
                true
            }
            None => false,
        }
    }
}
