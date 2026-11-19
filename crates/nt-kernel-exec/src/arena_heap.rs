//! A general-purpose heap laid over a caller-provided arena (win32k's USER/desktop heaps).
//!
//! The arena header occupies the first [`DATA_OFFSET`] bytes; blocks follow it and the
//! untouched tail above a bump offset is handed out last. Every block has a 16-byte header:
//! the payload capacity (a multiple of 16, low bit = "previous block is free") and a marker
//! word. A free block also stores its list links at the start of its payload and its capacity
//! in its last word (a boundary tag), so freeing coalesces with both neighbours in O(1) and
//! no free-list walk is ever needed. Free blocks sit in segregated bins: exact 16-byte classes
//! up to 1 KiB, then one bin per power of two. Allocation and free therefore never fail or slow
//! down because many blocks are free.
//!
//! Header words other than those listed below belong to the caller (a nested heap stores its
//! handle magic and size at +0x10/+0x18; the outer USER heap publishes a high-water mark at
//! +0x10).

/// First block header offset within the arena.
pub const DATA_OFFSET: u64 = 0x1000;
/// Bytes of block header preceding every payload.
pub const HEADER_SIZE: u64 = 16;
/// Second header word of an allocated block.
pub const ALLOC_MARKER: u64 = 0xffff_ffff_ffff_fffd;
/// Second header word of a free block.
const FREE_MARKER: u64 = 0xffff_ffff_ffff_fffb;
/// A free block holds two links and a boundary tag.
const MIN_CAPACITY: u64 = 32;
const PREV_FREE: u64 = 1;

mod hdr {
    /// Bump offset of the first never-used byte (relative to the arena base).
    pub const BUMP: u64 = 0x00;
    /// Retired single free-list head from the previous layout; always zero.
    pub const LEGACY_FREE_HEAD: u64 = 0x08;
    /// Non-empty-bin bitmap words.
    pub const BITMAP: u64 = 0x20;
    /// Bin list heads (block header addresses).
    pub const BINS: u64 = 0x100;
}
const EXACT_BINS: usize = 64; // capacities 0..=1008 by 16; 1024 starts the power-of-two bins
const BINS: usize = EXACT_BINS + 22; // 2^10 ..= 2^31
const _: () = assert!(hdr::BINS + BINS as u64 * 8 <= DATA_OFFSET);
const _: () = assert!(BINS <= 128);

#[inline]
unsafe fn rd(address: u64) -> u64 {
    unsafe { core::ptr::read_volatile(address as *const u64) }
}

#[inline]
unsafe fn wr(address: u64, value: u64) {
    unsafe { core::ptr::write_volatile(address as *mut u64, value) }
}

const fn bin_of(capacity: u64) -> usize {
    if capacity < 1024 {
        (capacity / 16) as usize
    } else {
        let log = 63 - capacity.leading_zeros() as usize; // >= 10
        let index = EXACT_BINS + (log - 10);
        if index >= BINS { BINS - 1 } else { index }
    }
}

/// Prepare an empty heap over `[base, base + bytes)`. Caller-owned header words are untouched.
///
/// # Safety
/// The arena must be writable for at least [`DATA_OFFSET`] bytes.
pub unsafe fn init(base: u64) {
    unsafe {
        wr(base + hdr::BUMP, DATA_OFFSET);
        wr(base + hdr::LEGACY_FREE_HEAD, 0);
        wr(base + hdr::BITMAP, 0);
        wr(base + hdr::BITMAP + 8, 0);
        for bin in 0..BINS as u64 {
            wr(base + hdr::BINS + bin * 8, 0);
        }
    }
}

/// Offset one past the highest block ever handed out (the USER heap's published high water).
///
/// # Safety
/// `base` must be an initialized heap.
pub unsafe fn bump(base: u64) -> u64 {
    unsafe { rd(base + hdr::BUMP).max(DATA_OFFSET) }
}

/// Capacity of the allocated block whose payload is `p`, or `None` if `p` is not one.
///
/// # Safety
/// `base` must be an initialized heap of `bytes` bytes.
pub unsafe fn capacity(base: u64, bytes: u64, p: u64) -> Option<u64> {
    let start = base + DATA_OFFSET;
    let top = base + unsafe { bump(base) };
    if p < start + HEADER_SIZE || p > top || p & 15 != 0 || top > base + bytes {
        return None;
    }
    let header = p - HEADER_SIZE;
    if unsafe { rd(header + 8) } != ALLOC_MARKER {
        return None;
    }
    let capacity = unsafe { rd(header) } & !15;
    (capacity != 0 && header + HEADER_SIZE + capacity <= top).then_some(capacity)
}

unsafe fn set_bit(base: u64, bin: usize, on: bool) {
    let word = base + hdr::BITMAP + (bin as u64 / 64) * 8;
    let bit = 1u64 << (bin % 64);
    unsafe {
        let value = rd(word);
        wr(word, if on { value | bit } else { value & !bit });
    }
}

unsafe fn link(base: u64, block: u64, capacity: u64) {
    let bin = bin_of(capacity);
    let head = base + hdr::BINS + bin as u64 * 8;
    unsafe {
        let first = rd(head);
        wr(block + HEADER_SIZE, first);
        wr(block + HEADER_SIZE + 8, 0);
        if first != 0 {
            wr(first + HEADER_SIZE + 8, block);
        }
        wr(head, block);
        set_bit(base, bin, true);
    }
}

unsafe fn unlink(base: u64, block: u64, capacity: u64) {
    let bin = bin_of(capacity);
    let head = base + hdr::BINS + bin as u64 * 8;
    unsafe {
        let next = rd(block + HEADER_SIZE);
        let prev = rd(block + HEADER_SIZE + 8);
        if prev == 0 { wr(head, next); } else { wr(prev + HEADER_SIZE, next); }
        if next != 0 { wr(next + HEADER_SIZE + 8, prev); }
        if rd(head) == 0 { set_bit(base, bin, false); }
    }
}

/// Mark `[block, block + 16 + capacity)` free, publish its tag and tell its successor.
unsafe fn make_free(base: u64, block: u64, capacity: u64, prev_free: bool) {
    unsafe {
        wr(block, capacity | if prev_free { PREV_FREE } else { 0 });
        wr(block + 8, FREE_MARKER);
        wr(block + HEADER_SIZE + capacity - 8, capacity);
        link(base, block, capacity);
        let next = block + HEADER_SIZE + capacity;
        if next < base + bump(base) {
            wr(next, rd(next) | PREV_FREE);
        }
    }
}

unsafe fn take(base: u64, want: u64) -> Option<(u64, u64)> {
    let first = bin_of(want);
    unsafe {
        // The want's own bin: exact classes match outright; a power-of-two bin needs a fit.
        let mut block = rd(base + hdr::BINS + first as u64 * 8);
        while block != 0 {
            let capacity = rd(block) & !15;
            if capacity >= want {
                unlink(base, block, capacity);
                return Some((block, capacity));
            }
            block = rd(block + HEADER_SIZE);
        }
        for word in 0..2 {
            let mut bits = rd(base + hdr::BITMAP + word * 8);
            if (word as usize) * 64 <= first {
                let skip = first + 1 - word as usize * 64;
                bits &= if skip >= 64 { 0 } else { !0u64 << skip };
            }
            if bits != 0 {
                let bin = word as usize * 64 + bits.trailing_zeros() as usize;
                let block = rd(base + hdr::BINS + bin as u64 * 8);
                let capacity = rd(block) & !15;
                unlink(base, block, capacity);
                return Some((block, capacity));
            }
        }
    }
    None
}

/// Allocate `size` bytes (rounded up to 16, minimum 32); 0 when the arena is exhausted.
///
/// # Safety
/// `base` must be an initialized heap of `bytes` bytes, used by one owner at a time.
pub unsafe fn alloc(base: u64, bytes: u64, size: u64, zero: bool) -> u64 {
    if size == 0 {
        return 0;
    }
    let Some(want) = size.checked_add(15).map(|value| (value & !15).max(MIN_CAPACITY)) else {
        return 0;
    };
    let payload = unsafe {
        if let Some((block, capacity)) = take(base, want) {
            let flags = rd(block) & PREV_FREE;
            let next = block + HEADER_SIZE + capacity;
            if capacity - want >= HEADER_SIZE + MIN_CAPACITY {
                wr(block, want | flags);
                wr(block + 8, ALLOC_MARKER);
                make_free(base, block + HEADER_SIZE + want, capacity - want - HEADER_SIZE, false);
            } else {
                wr(block, capacity | flags);
                wr(block + 8, ALLOC_MARKER);
                if next < base + bump(base) {
                    wr(next, rd(next) & !PREV_FREE);
                }
            }
            block + HEADER_SIZE
        } else {
            let top = bump(base);
            let Some(end) = top.checked_add(HEADER_SIZE + want).filter(|end| *end <= bytes) else {
                return 0;
            };
            let block = base + top;
            wr(block, want);
            wr(block + 8, ALLOC_MARKER);
            wr(base + hdr::BUMP, end);
            block + HEADER_SIZE
        }
    };
    if zero {
        unsafe { core::ptr::write_bytes(payload as *mut u8, 0, size as usize) };
    }
    payload
}

/// Free the allocated block at payload `p`, coalescing with free neighbours and returning a
/// free tail to the bump region. `false` only for a pointer that is not an allocated block.
///
/// # Safety
/// As for [`alloc`].
pub unsafe fn free(base: u64, bytes: u64, p: u64) -> bool {
    let Some(mut capacity) = (unsafe { capacity(base, bytes, p) }) else {
        return false;
    };
    unsafe {
        let mut block = p - HEADER_SIZE;
        let mut prev_free = false;
        if rd(block) & PREV_FREE != 0 {
            let prev_capacity = rd(block - 8);
            let prev = block - HEADER_SIZE - prev_capacity;
            unlink(base, prev, prev_capacity);
            capacity += HEADER_SIZE + prev_capacity;
            prev_free = rd(prev) & PREV_FREE != 0;
            block = prev;
        }
        let top = base + bump(base);
        let next = block + HEADER_SIZE + capacity;
        if next == top {
            // The merged block ends at the bump offset: give it back to the untouched tail.
            debug_assert!(!prev_free, "a free block never precedes the bump tail's free block");
            wr(base + hdr::BUMP, block - base);
            return true;
        }
        if rd(next + 8) == FREE_MARKER {
            let next_capacity = rd(next) & !15;
            unlink(base, next, next_capacity);
            capacity += HEADER_SIZE + next_capacity;
            if block + HEADER_SIZE + capacity == top {
                wr(base + hdr::BUMP, block - base);
                return true;
            }
        }
        make_free(base, block, capacity, prev_free);
    }
    true
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct Arena(Vec<u128>);

    impl Arena {
        fn new(bytes: usize) -> Self {
            let arena = Self(vec![0xAAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAA_AAAAu128; bytes / 16]);
            unsafe { init(arena.base()) };
            arena
        }
        fn base(&self) -> u64 { self.0.as_ptr() as u64 }
        fn bytes(&self) -> u64 { (self.0.len() * 16) as u64 }
        fn alloc(&self, size: u64) -> u64 { unsafe { alloc(self.base(), self.bytes(), size, false) } }
        fn free(&self, p: u64) -> bool { unsafe { free(self.base(), self.bytes(), p) } }
        fn bump(&self) -> u64 { unsafe { bump(self.base()) } }
    }

    /// Boot 44416320584: the previous allocator kept one address-ordered free list and
    /// refused a free (RtlFreeHeap returned FALSE, leaking the block) once that list was
    /// longer than 4096 entries. Every free must succeed however fragmented the heap is.
    #[test]
    fn freeing_into_a_heavily_fragmented_heap_always_succeeds() {
        let arena = Arena::new(16 << 20);
        let blocks: Vec<u64> = (0..40_000).map(|_| arena.alloc(48)).collect();
        assert!(blocks.iter().all(|p| *p != 0));
        // Free every other block: 20,000 non-adjacent free blocks.
        for p in blocks.iter().step_by(2) {
            assert!(arena.free(*p));
        }
        // The rest must still free (and coalesce) with 20,000 entries already free.
        for p in blocks.iter().skip(1).step_by(2) {
            assert!(arena.free(*p), "free refused with a long free list");
        }
        assert_eq!(arena.bump(), DATA_OFFSET, "everything coalesced back into the tail");
    }

    #[test]
    fn freed_blocks_are_reused_before_the_tail_grows() {
        let arena = Arena::new(1 << 20);
        let a = arena.alloc(100);
        let _guard = arena.alloc(16);
        let high = arena.bump();
        assert!(arena.free(a));
        let b = arena.alloc(100);
        assert_eq!(b, a);
        assert_eq!(arena.bump(), high);
        assert_eq!(unsafe { capacity(arena.base(), arena.bytes(), b) }, Some(112));
    }

    #[test]
    fn neighbours_coalesce_and_large_requests_split_a_merged_block() {
        let arena = Arena::new(1 << 20);
        let blocks: Vec<u64> = (0..8).map(|_| arena.alloc(64)).collect();
        let _guard = arena.alloc(64);
        for p in &blocks[1..7] {
            assert!(arena.free(*p));
        }
        // Six adjacent 64-byte blocks merged into one: 6*64 + 5*16 = 464 bytes.
        let big = arena.alloc(400);
        assert_eq!(big, blocks[1]);
        let rest = arena.alloc(32);
        assert!(rest > big && rest < blocks[7], "the split remainder is reused");
    }

    #[test]
    fn invalid_and_double_frees_are_refused_without_corruption() {
        let arena = Arena::new(1 << 20);
        let a = arena.alloc(64);
        let b = arena.alloc(64);
        assert!(!arena.free(a + 16));
        assert!(!arena.free(arena.base()));
        assert!(arena.free(a));
        assert!(!arena.free(a), "double free");
        assert!(arena.free(b));
        assert_eq!(arena.bump(), DATA_OFFSET);
    }

    #[test]
    fn exhaustion_returns_null_and_random_churn_stays_consistent() {
        let arena = Arena::new(256 << 10);
        let mut live: Vec<(u64, u64)> = Vec::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
        for _ in 0..50_000 {
            if live.len() > 64 && next() % 2 == 0 {
                let index = (next() as usize) % live.len();
                let (p, fill) = live.swap_remove(index);
                let size = unsafe { capacity(arena.base(), arena.bytes(), p) }.unwrap();
                assert!((0..size / 8).all(|word| unsafe { rd(p + word * 8) } == fill));
                assert!(arena.free(p));
            } else {
                let size = 16 + next() % 3000;
                let p = arena.alloc(size);
                if p == 0 {
                    continue; // exhausted: a clean refusal, never a corrupt block
                }
                let fill = next();
                let size = unsafe { capacity(arena.base(), arena.bytes(), p) }.unwrap();
                for word in 0..size / 8 {
                    unsafe { wr(p + word * 8, fill) };
                }
                live.push((p, fill));
            }
        }
        for (p, _) in live {
            assert!(arena.free(p));
        }
        assert_eq!(arena.bump(), DATA_OFFSET);
    }
}
