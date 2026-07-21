//! `RTL_BITMAP` primitives as a raw-memory operation (the `Rtl*Bit*` ntoskrnl exports).
//!
//! win32k's GDI attribute pool ([`GdiPoolAllocate`], win32ss/gdi/ntgdi/gdipool.c) manages each
//! 64 KiB section's slots with an `RTL_BITMAP`: `RtlInitializeBitMap` + `RtlClearAllBits` at section
//! creation, then `RtlFindClearBitsAndSet(&bitmap, 1, 0)` per allocation and `RtlClearBit` per free,
//! with `RtlNumberOfSetBits` / `RtlTestBit` guarding the ASSERTs. Stubbing these to no-ops made every
//! allocation return slot 0 (so every DC_ATTR / RGN_ATTR aliased) and tripped the count ASSERTs — so
//! DC/RGN attribute allocation never produced distinct storage. These are pure functions over the
//! caller's `RTL_BITMAP` + backing words, so they live here as raw-pointer primitives (mirroring
//! [`session_section`](crate::session_section)) with host tests, reused by every hosted binary.
//!
//! `RTL_BITMAP` layout (Windows x64 ABI):
//! ```c
//! typedef struct _RTL_BITMAP {
//!     ULONG SizeOfBitMap;  // +0x00  number of bits
//!     PULONG Buffer;       // +0x08  bit array (LSB-first within each 32-bit word)
//! } RTL_BITMAP;
//! ```

/// `RTL_BITMAP` field offsets.
pub mod bitmap {
    /// `ULONG SizeOfBitMap` — number of bits the bitmap covers.
    pub const SIZE_OF_BITMAP: usize = 0x00;
    /// `PULONG Buffer` — pointer to the bit array (32-bit words, LSB-first).
    pub const BUFFER: usize = 0x08;
    /// Total `RTL_BITMAP` struct size.
    pub const SIZE_OF: usize = 0x10;
}

/// Returned by [`find_clear_bits_and_set`] when no run is found (Windows `0xFFFFFFFF`).
pub const BITMAP_NONE: u32 = 0xFFFF_FFFF;

#[inline]
unsafe fn hdr_size(bm: *const u8) -> u32 {
    core::ptr::read_unaligned(bm.add(bitmap::SIZE_OF_BITMAP) as *const u32)
}
#[inline]
unsafe fn hdr_buffer(bm: *const u8) -> *mut u32 {
    core::ptr::read_unaligned(bm.add(bitmap::BUFFER) as *const u64) as *mut u32
}
#[inline]
unsafe fn get_bit(buf: *const u32, i: u32) -> bool {
    let word = core::ptr::read_unaligned(buf.add((i / 32) as usize));
    (word >> (i % 32)) & 1 != 0
}
#[inline]
unsafe fn set_bit_raw(buf: *mut u32, i: u32) {
    let p = buf.add((i / 32) as usize);
    core::ptr::write_unaligned(p, core::ptr::read_unaligned(p) | (1u32 << (i % 32)));
}
#[inline]
unsafe fn clear_bit_raw(buf: *mut u32, i: u32) {
    let p = buf.add((i / 32) as usize);
    core::ptr::write_unaligned(p, core::ptr::read_unaligned(p) & !(1u32 << (i % 32)));
}

/// `RtlInitializeBitMap(RTL_BITMAP*, PULONG buffer, ULONG size)` — record the backing array and bit
/// count. Does NOT clear the bits (matches Windows).
///
/// # Safety
/// `bm` must be writable for [`bitmap::SIZE_OF`] bytes; `buffer` must back at least `size` bits.
pub unsafe fn initialize(bm: *mut u8, buffer: u64, size: u32) {
    core::ptr::write_unaligned(bm.add(bitmap::SIZE_OF_BITMAP) as *mut u32, size);
    core::ptr::write_unaligned(bm.add(bitmap::BUFFER) as *mut u64, buffer);
}

/// `RtlClearAllBits(RTL_BITMAP*)` — clear every bit.
///
/// # Safety
/// `bm` must be an initialized bitmap (see [`initialize`]).
pub unsafe fn clear_all(bm: *mut u8) {
    let n_words = ((hdr_size(bm) + 31) / 32) as usize;
    let buf = hdr_buffer(bm);
    for w in 0..n_words {
        core::ptr::write_unaligned(buf.add(w), 0);
    }
}

/// `RtlSetAllBits(RTL_BITMAP*)` — set every bit.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn set_all(bm: *mut u8) {
    let n_words = ((hdr_size(bm) + 31) / 32) as usize;
    let buf = hdr_buffer(bm);
    for w in 0..n_words {
        core::ptr::write_unaligned(buf.add(w), 0xFFFF_FFFF);
    }
}

/// `RtlTestBit(RTL_BITMAP*, ULONG i)` — read bit `i`.
///
/// # Safety
/// `bm` must be an initialized bitmap; `i < SizeOfBitMap`.
pub unsafe fn test_bit(bm: *const u8, i: u32) -> bool {
    if i >= hdr_size(bm) {
        return false;
    }
    get_bit(hdr_buffer(bm), i)
}

/// `RtlSetBit(RTL_BITMAP*, ULONG i)`.
///
/// # Safety
/// `bm` must be an initialized bitmap; `i < SizeOfBitMap`.
pub unsafe fn set_bit(bm: *mut u8, i: u32) {
    if i < hdr_size(bm) {
        set_bit_raw(hdr_buffer(bm), i);
    }
}

/// `RtlClearBit(RTL_BITMAP*, ULONG i)`.
///
/// # Safety
/// `bm` must be an initialized bitmap; `i < SizeOfBitMap`.
pub unsafe fn clear_bit(bm: *mut u8, i: u32) {
    if i < hdr_size(bm) {
        clear_bit_raw(hdr_buffer(bm), i);
    }
}

/// `RtlNumberOfSetBits(RTL_BITMAP*)` — count set bits.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn number_of_set_bits(bm: *const u8) -> u32 {
    let size = hdr_size(bm);
    let buf = hdr_buffer(bm);
    let mut n = 0u32;
    let mut i = 0u32;
    while i < size {
        if get_bit(buf, i) {
            n += 1;
        }
        i += 1;
    }
    n
}

/// `RtlNumberOfClearBits(RTL_BITMAP*)` — count clear bits.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn number_of_clear_bits(bm: *const u8) -> u32 {
    unsafe { hdr_size(bm).saturating_sub(number_of_set_bits(bm)) }
}

/// `RtlAreBitsClear(RTL_BITMAP*, ULONG start, ULONG count)` — `true` if `[start, start+count)` are
/// all clear (and in range).
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn are_bits_clear(bm: *const u8, start: u32, count: u32) -> bool {
    let size = hdr_size(bm);
    if count == 0 || start.checked_add(count).map_or(true, |e| e > size) {
        return false;
    }
    let buf = hdr_buffer(bm);
    for i in start..start + count {
        if get_bit(buf, i) {
            return false;
        }
    }
    true
}

unsafe fn find_bits(bm: *const u8, count: u32, hint: u32, want_set: bool) -> u32 {
    if bm.is_null() {
        return BITMAP_NONE;
    }
    let size = unsafe { hdr_size(bm) };
    if count > size {
        return BITMAP_NONE;
    }
    let start_at = if hint >= size { 0 } else { hint };
    if count == 0 {
        return start_at & !7;
    }
    let buf = unsafe { hdr_buffer(bm) };
    let mut probed = 0u32;
    let mut i = start_at;
    while probed < size {
        if let Some(end) = i.checked_add(count) {
            if end <= size {
                let mut matched = true;
                for bit in i..end {
                    if unsafe { get_bit(buf, bit) } != want_set {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return i;
                }
            }
        }
        i += 1;
        if i >= size {
            i = 0;
        }
        probed += 1;
    }
    BITMAP_NONE
}

/// `RtlFindClearBits(RTL_BITMAP*, ULONG count, ULONG hint)` — find a clear run, wrapping once.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn find_clear_bits(bm: *const u8, count: u32, hint: u32) -> u32 {
    unsafe { find_bits(bm, count, hint, false) }
}

/// `RtlFindSetBits(RTL_BITMAP*, ULONG count, ULONG hint)` — find a set run, wrapping once.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn find_set_bits(bm: *const u8, count: u32, hint: u32) -> u32 {
    unsafe { find_bits(bm, count, hint, true) }
}

/// `RtlFindClearBitsAndSet(RTL_BITMAP*, ULONG count, ULONG hint)` — find a clear run, set it, and
/// return the run's start index. Returns [`BITMAP_NONE`] if no such run exists.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn find_clear_bits_and_set(bm: *mut u8, count: u32, hint: u32) -> u32 {
    let position = unsafe { find_clear_bits(bm, count, hint) };
    if position != BITMAP_NONE {
        unsafe { set_bits(bm, position, count) };
    }
    position
}

/// `RtlFindSetBitsAndClear(RTL_BITMAP*, ULONG count, ULONG hint)` — find a set run, clear it, and
/// return the run's start index.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn find_set_bits_and_clear(bm: *mut u8, count: u32, hint: u32) -> u32 {
    let position = unsafe { find_set_bits(bm, count, hint) };
    if position != BITMAP_NONE {
        unsafe { clear_bits(bm, position, count) };
    }
    position
}

/// `RtlClearBits(RTL_BITMAP*, ULONG start, ULONG count)`.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn clear_bits(bm: *mut u8, start: u32, count: u32) {
    let size = hdr_size(bm);
    let buf = hdr_buffer(bm);
    let end = start.saturating_add(count).min(size);
    for i in start..end {
        clear_bit_raw(buf, i);
    }
}

/// `RtlSetBits(RTL_BITMAP*, ULONG start, ULONG count)`.
///
/// # Safety
/// `bm` must be an initialized bitmap.
pub unsafe fn set_bits(bm: *mut u8, start: u32, count: u32) {
    let size = hdr_size(bm);
    let buf = hdr_buffer(bm);
    let end = start.saturating_add(count).min(size);
    for i in start..end {
        set_bit_raw(buf, i);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    struct Bm {
        hdr: [u8; bitmap::SIZE_OF],
        words: std::vec::Vec<u32>,
    }
    impl Bm {
        fn new(size: u32) -> Self {
            let words = std::vec![0u32; ((size + 31) / 32) as usize];
            let mut b = Bm {
                hdr: [0xAA; bitmap::SIZE_OF],
                words,
            };
            let buf = b.words.as_mut_ptr() as u64;
            unsafe { initialize(b.hdr.as_mut_ptr(), buf, size) };
            b
        }
        fn p(&mut self) -> *mut u8 {
            self.hdr.as_mut_ptr()
        }
        fn c(&self) -> *const u8 {
            self.hdr.as_ptr()
        }
    }

    #[test]
    fn init_records_size_and_buffer() {
        let b = Bm::new(96);
        unsafe {
            assert_eq!(hdr_size(b.c()), 96);
            assert_eq!(hdr_buffer(b.c()) as u64, b.words.as_ptr() as u64);
        }
    }

    #[test]
    fn single_bit_alloc_returns_distinct_slots() {
        // The GDI-pool usage: RtlFindClearBitsAndSet(&bitmap, 1, 0) per allocation must hand out a
        // fresh index each time (the bug: no-op stubs returned 0 every time).
        let mut b = Bm::new(64);
        unsafe {
            clear_all(b.p());
            assert_eq!(find_clear_bits_and_set(b.p(), 1, 0), 0);
            assert_eq!(find_clear_bits_and_set(b.p(), 1, 0), 1);
            assert_eq!(find_clear_bits_and_set(b.p(), 1, 0), 2);
            assert_eq!(number_of_set_bits(b.c()), 3);
            assert!(test_bit(b.c(), 0) && test_bit(b.c(), 1) && test_bit(b.c(), 2));
            assert!(!test_bit(b.c(), 3));
        }
    }

    #[test]
    fn clear_bit_frees_and_realloc_reuses() {
        let mut b = Bm::new(64);
        unsafe {
            clear_all(b.p());
            let a = find_clear_bits_and_set(b.p(), 1, 0);
            let c = find_clear_bits_and_set(b.p(), 1, 0);
            assert_eq!((a, c), (0, 1));
            clear_bit(b.p(), 0);
            assert_eq!(number_of_set_bits(b.c()), 1);
            // Next alloc reuses freed slot 0.
            assert_eq!(find_clear_bits_and_set(b.p(), 1, 0), 0);
        }
    }

    #[test]
    fn contiguous_run_and_exhaustion() {
        let mut b = Bm::new(8);
        unsafe {
            clear_all(b.p());
            assert_eq!(find_clear_bits(b.c(), 3, 0), 0);
            assert_eq!(find_clear_bits_and_set(b.p(), 3, 0), 0); // bits 0,1,2
            assert_eq!(find_clear_bits_and_set(b.p(), 3, 0), 3); // bits 3,4,5
                                                                 // Only bits 6,7 left -> no run of 3.
            assert_eq!(find_clear_bits_and_set(b.p(), 3, 0), BITMAP_NONE);
            assert_eq!(find_clear_bits_and_set(b.p(), 2, 0), 6); // bits 6,7
            assert_eq!(find_clear_bits_and_set(b.p(), 1, 0), BITMAP_NONE);
        }
    }

    #[test]
    fn are_bits_clear_bounds() {
        let mut b = Bm::new(64);
        unsafe {
            clear_all(b.p());
            assert!(are_bits_clear(b.c(), 0, 64));
            set_bit(b.p(), 10);
            assert!(!are_bits_clear(b.c(), 8, 4));
            assert!(are_bits_clear(b.c(), 0, 8));
            assert!(!are_bits_clear(b.c(), 60, 8)); // out of range
            assert!(!are_bits_clear(b.c(), 0, 0)); // zero count
        }
    }

    #[test]
    fn set_and_clear_ranges() {
        let mut b = Bm::new(64);
        unsafe {
            clear_all(b.p());
            set_bits(b.p(), 4, 8);
            assert_eq!(number_of_set_bits(b.c()), 8);
            assert!(test_bit(b.c(), 4) && test_bit(b.c(), 11));
            clear_bits(b.p(), 4, 4);
            assert_eq!(number_of_set_bits(b.c()), 4);
            set_all(b.p());
            assert_eq!(number_of_set_bits(b.c()), 64);
        }
    }

    #[test]
    fn count_clear_find_set_and_clear() {
        let mut b = Bm::new(16);
        unsafe {
            clear_all(b.p());
            set_bits(b.p(), 4, 4);
            set_bits(b.p(), 12, 2);
            assert_eq!(number_of_set_bits(b.c()), 6);
            assert_eq!(number_of_clear_bits(b.c()), 10);
            assert_eq!(find_set_bits(b.c(), 4, 0), 4);
            assert_eq!(find_set_bits(b.c(), 2, 8), 12);
            assert_eq!(find_set_bits_and_clear(b.p(), 4, 0), 4);
            assert_eq!(number_of_set_bits(b.c()), 2);
            assert!(are_bits_clear(b.c(), 4, 4));
        }
    }

    #[test]
    fn find_bits_wraps_and_zero_count_rounds_hint() {
        let mut b = Bm::new(16);
        unsafe {
            clear_all(b.p());
            set_bits(b.p(), 0, 2);
            set_bits(b.p(), 10, 2);
            assert_eq!(find_set_bits(b.c(), 2, 8), 10);
            assert_eq!(find_set_bits(b.c(), 2, 12), 0);
            assert_eq!(find_clear_bits(b.c(), 3, 14), 2);
            assert_eq!(find_set_bits(b.c(), 0, 13), 8);
            assert_eq!(find_clear_bits(b.c(), 0, 99), 0);
        }
    }
}
