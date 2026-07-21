//! `Rtl*Bit*` bitmap primitives — reused from [`nt_kernel_exec::rtl_bitmap`].
//!
//! `RtlInitializeBitMap`, `RtlSetBits`/`RtlClearBits`, `RtlAreBitsSet`/`RtlAreBitsClear`,
//! `RtlFindClearBitsAndSet`, etc. already exist as host-tested raw-pointer primitives in
//! `nt-kernel-exec` (win32k's GDI pool needs them). We re-export the raw API and add a small owned
//! [`BitMap`] wrapper so the ntdll surface is usable + testable without hand-rolling the
//! `RTL_BITMAP` header.

pub use nt_kernel_exec::rtl_bitmap::{
    are_bits_clear, clear_all, clear_bit, clear_bits, find_clear_bits, find_clear_bits_and_set,
    find_first_run_clear, find_last_backward_run_clear, find_next_forward_run_clear,
    find_next_forward_run_set, find_set_bits, find_set_bits_and_clear, initialize,
    number_of_clear_bits, number_of_set_bits, set_all, set_bit, set_bits, test_bit, BITMAP_NONE,
};

use alloc::vec;
use alloc::vec::Vec;
use nt_kernel_exec::rtl_bitmap::bitmap;

/// An owned `RTL_BITMAP` — the 16-byte header plus its backing word array, kept together so the
/// pointers the raw API needs stay valid. Mirrors how a caller would allocate + `RtlInitializeBitMap`
/// in one shot.
pub struct BitMap {
    hdr: [u8; bitmap::SIZE_OF],
    words: Vec<u32>,
}

impl BitMap {
    /// Allocate a bitmap of `size` bits, all clear.
    pub fn new(size: u32) -> Self {
        let mut words = vec![0u32; size.div_ceil(32) as usize];
        let mut hdr = [0u8; bitmap::SIZE_OF];
        let buf = words.as_mut_ptr() as u64;
        // SAFETY: `hdr` is a `SIZE_OF`-byte writable header; `words` backs `size` bits.
        unsafe { initialize(hdr.as_mut_ptr(), buf, size) };
        BitMap { hdr, words }
    }

    /// `RtlAreBitsSet`.
    pub fn are_bits_set(&self, start: u32, count: u32) -> bool {
        // "all set" == none clear in the range, and the range is valid.
        if count == 0 {
            return false;
        }
        (start..start.saturating_add(count)).all(|i| self.test(i))
    }

    /// `RtlAreBitsClear`.
    pub fn are_bits_clear(&self, start: u32, count: u32) -> bool {
        // SAFETY: initialised header.
        unsafe { are_bits_clear(self.hdr.as_ptr(), start, count) }
    }

    /// `RtlTestBit`.
    pub fn test(&self, i: u32) -> bool {
        // SAFETY: initialised header.
        unsafe { test_bit(self.hdr.as_ptr(), i) }
    }

    /// `RtlSetBit`.
    pub fn set(&mut self, i: u32) {
        // SAFETY: initialised header.
        unsafe { set_bit(self.hdr.as_mut_ptr(), i) };
    }

    /// `RtlClearBit`.
    pub fn clear(&mut self, i: u32) {
        // SAFETY: initialised header.
        unsafe { clear_bit(self.hdr.as_mut_ptr(), i) };
    }

    /// `RtlSetBits`.
    pub fn set_range(&mut self, start: u32, count: u32) {
        // SAFETY: initialised header.
        unsafe { set_bits(self.hdr.as_mut_ptr(), start, count) };
    }

    /// `RtlClearBits`.
    pub fn clear_range(&mut self, start: u32, count: u32) {
        // SAFETY: initialised header.
        unsafe { clear_bits(self.hdr.as_mut_ptr(), start, count) };
    }

    /// `RtlFindClearBitsAndSet`.
    pub fn find_clear_and_set(&mut self, count: u32, hint: u32) -> u32 {
        // SAFETY: initialised header.
        unsafe { find_clear_bits_and_set(self.hdr.as_mut_ptr(), count, hint) }
    }

    /// `RtlFindClearBits`.
    pub fn find_clear(&self, count: u32, hint: u32) -> u32 {
        // SAFETY: initialised header.
        unsafe { find_clear_bits(self.hdr.as_ptr(), count, hint) }
    }

    /// `RtlFindSetBits`.
    pub fn find_set(&self, count: u32, hint: u32) -> u32 {
        // SAFETY: initialised header.
        unsafe { find_set_bits(self.hdr.as_ptr(), count, hint) }
    }

    /// `RtlFindSetBitsAndClear`.
    pub fn find_set_and_clear(&mut self, count: u32, hint: u32) -> u32 {
        // SAFETY: initialised header.
        unsafe { find_set_bits_and_clear(self.hdr.as_mut_ptr(), count, hint) }
    }

    /// `RtlFindNextForwardRunClear`.
    pub fn find_next_forward_clear(&self, from: u32, start: &mut u32) -> u32 {
        // SAFETY: initialised header; `start` is writable.
        unsafe { find_next_forward_run_clear(self.hdr.as_ptr(), from, start) }
    }

    /// `RtlFindNextForwardRunSet`.
    pub fn find_next_forward_set(&self, from: u32, start: &mut u32) -> u32 {
        // SAFETY: initialised header; `start` is writable.
        unsafe { find_next_forward_run_set(self.hdr.as_ptr(), from, start) }
    }

    /// `RtlFindFirstRunClear`.
    pub fn find_first_clear_run(&self, start: &mut u32) -> u32 {
        // SAFETY: initialised header; `start` is writable.
        unsafe { find_first_run_clear(self.hdr.as_ptr(), start) }
    }

    /// `RtlFindLastBackwardRunClear`.
    pub fn find_last_backward_clear(&self, from: u32, start: &mut u32) -> u32 {
        // SAFETY: initialised header; `start` is writable.
        unsafe { find_last_backward_run_clear(self.hdr.as_ptr(), from, start) }
    }

    /// `RtlNumberOfSetBits`.
    pub fn count_set(&self) -> u32 {
        // SAFETY: initialised header.
        unsafe { number_of_set_bits(self.hdr.as_ptr()) }
    }

    /// `RtlNumberOfClearBits`.
    pub fn count_clear(&self) -> u32 {
        // SAFETY: initialised header.
        unsafe { number_of_clear_bits(self.hdr.as_ptr()) }
    }

    /// The number of bits covered.
    pub fn len_bits(&self) -> u32 {
        self.words.len() as u32 * 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_bitmap_alloc_free() {
        let mut b = BitMap::new(64);
        assert_eq!(b.find_clear_and_set(1, 0), 0);
        assert_eq!(b.find_clear_and_set(1, 0), 1);
        assert_eq!(b.count_set(), 2);
        assert!(b.are_bits_set(0, 2));
        assert!(b.are_bits_clear(2, 10));
        b.clear(0);
        assert_eq!(b.find_clear_and_set(1, 0), 0); // reuses freed slot
    }

    #[test]
    fn ranges() {
        let mut b = BitMap::new(128);
        b.set_range(10, 20);
        assert_eq!(b.count_set(), 20);
        assert!(b.are_bits_set(10, 20));
        b.clear_range(10, 5);
        assert_eq!(b.count_set(), 15);
    }

    #[test]
    fn find_and_count_clear_set_runs() {
        let mut b = BitMap::new(32);
        b.set_range(8, 4);
        b.set_range(20, 3);
        assert_eq!(b.count_set(), 7);
        assert_eq!(b.count_clear(), 25);
        assert_eq!(b.find_set(4, 0), 8);
        assert_eq!(b.find_clear(8, 16), 23);
        assert_eq!(b.find_set_and_clear(3, 16), 20);
        assert!(b.are_bits_clear(20, 3));
    }

    #[test]
    fn forward_and_backward_clear_runs() {
        let mut b = BitMap::new(32);
        b.set_range(0, 32);
        b.clear_range(3, 4);
        b.clear_range(12, 2);

        let mut start = u32::MAX;
        assert_eq!(b.find_first_clear_run(&mut start), 4);
        assert_eq!(start, 3);
        assert_eq!(b.find_next_forward_clear(7, &mut start), 2);
        assert_eq!(start, 12);
        assert_eq!(b.find_next_forward_set(7, &mut start), 5);
        assert_eq!(start, 7);
        assert_eq!(b.find_last_backward_clear(31, &mut start), 2);
        assert_eq!(start, 12);
        assert_eq!(b.find_last_backward_clear(11, &mut start), 4);
        assert_eq!(start, 3);
    }
}
