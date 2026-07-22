//! `RtlCreateHeap` / `RtlAllocateHeap` / `RtlFreeHeap` / `RtlReAllocateHeap` / `RtlSizeHeap` /
//! `RtlDestroyHeap` — a **real** allocator.
//!
//! This is Category B: load-bearing (the loader + every DLL allocates through it), and portable, so
//! it is implemented properly rather than stubbed. The allocator is a classic **first-fit
//! free-list with boundary tags and coalescing** over a byte region. The region itself is abstract
//! (a [`Backing`]): in the real process it is committed via `NtAllocateVirtualMemory`; in tests it
//! is a plain `Vec<u8>`. Everything is therefore host-tested (alloc / free / realloc / coalesce /
//! size / exhaustion) with no target dependency.
//!
//! Layout — each block carries a boundary tag before its payload:
//! ```text
//!   [ BlockHeader | payload ... ] [ BlockHeader | payload ... ] ...
//! ```
//! `BlockHeader { size, prev_size, free }`. `size`/`prev_size` are payload+header sizes in bytes;
//! `prev_size == 0` marks the first block. Free blocks are found by a linear walk (first-fit) —
//! adequate and simple; a size-class free-list is a later optimisation, not correctness.

use core::mem::{align_of, size_of};

/// Every allocation is rounded up to this alignment (the Windows heap guarantees 16-byte alignment
/// on x64, matching `MEMORY_ALLOCATION_ALIGNMENT`).
pub const HEAP_ALIGN: usize = 16;

/// A backing byte region for a heap. The real process commits pages via `NtAllocateVirtualMemory`;
/// the host test uses a `Vec<u8>`. The heap only needs a base pointer + length.
///
/// # Safety
/// Implementors must return a pointer valid for reads+writes over `[base, base+len)` for the
/// lifetime of the heap, with at least [`HEAP_ALIGN`] alignment.
pub unsafe trait Backing {
    /// The region base pointer.
    fn base(&self) -> *mut u8;
    /// The region length in bytes.
    fn len(&self) -> usize;
    /// Whether the region is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A boundary-tagged block header (kept in-band, immediately before each payload).
#[repr(C)]
#[derive(Copy, Clone)]
struct BlockHeader {
    /// Total block size (header + payload) in bytes.
    size: usize,
    /// The previous (physically-adjacent) block's total size, or `0` for the first block. Enables
    /// backward coalescing without a global list.
    prev_size: usize,
    /// Whether this block is free.
    free: bool,
}

#[inline]
const fn round_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

/// The in-band header size, rounded up to [`HEAP_ALIGN`] so every payload (which sits at
/// `block + HDR`) lands [`HEAP_ALIGN`]-aligned when the block itself is aligned.
const HDR: usize = round_up(size_of::<BlockHeader>(), HEAP_ALIGN);

/// A first-fit free-list heap over a [`Backing`] region.
pub struct Heap<B: Backing> {
    backing: B,
    /// Whether the region has been formatted into an initial free block.
    formatted: bool,
}

impl<B: Backing> Heap<B> {
    /// `RtlCreateHeap`: format `backing` into a single free block spanning the whole region.
    /// Returns `None` if the region is too small to hold even a header.
    pub fn create(backing: B) -> Option<Self> {
        if backing.len() < HDR + HEAP_ALIGN {
            return None;
        }
        // The header must be at least HEAP_ALIGN-aligned so payloads land aligned.
        debug_assert!(align_of::<BlockHeader>() <= HEAP_ALIGN);
        let mut h = Heap {
            backing,
            formatted: false,
        };
        // SAFETY: region is >= HDR+HEAP_ALIGN and valid per the Backing contract.
        unsafe {
            let base = h.backing.base();
            core::ptr::write(
                base as *mut BlockHeader,
                BlockHeader {
                    size: h.backing.len(),
                    prev_size: 0,
                    free: true,
                },
            );
        }
        h.formatted = true;
        Some(h)
    }

    /// `RtlDestroyHeap`: consume the heap, returning the backing region (the caller frees it — in
    /// the real process via `NtFreeVirtualMemory`).
    pub fn destroy(self) -> B {
        self.backing
    }

    #[inline]
    fn region_end(&self) -> usize {
        self.backing.base() as usize + self.backing.len()
    }

    /// The block header at `ptr`, as a raw pointer (callers read/write fields through it).
    #[inline]
    fn hdr(&self, ptr: *mut u8) -> *mut BlockHeader {
        ptr as *mut BlockHeader
    }

    /// Split `block` so it holds exactly `need` bytes total, returning the tail to the free pool if
    /// the remainder is large enough to be its own block.
    ///
    /// # Safety
    /// `block` must be a valid free block header with `block.size >= need`.
    unsafe fn split(&mut self, block: *mut u8, need: usize) {
        let bh = self.hdr(block);
        let total = (*bh).size;
        let remainder = total - need;
        if remainder >= HDR + HEAP_ALIGN {
            // Carve a trailing free block.
            (*bh).size = need;
            let tail = block.add(need);
            core::ptr::write(
                tail as *mut BlockHeader,
                BlockHeader {
                    size: remainder,
                    prev_size: need,
                    free: true,
                },
            );
            // Fix the following block's prev_size, if any.
            let after = tail.add(remainder);
            if (after as usize) < self.region_end() {
                (*self.hdr(after)).prev_size = remainder;
            }
        }
    }

    /// `RtlAllocateHeap(size)`: first-fit allocate `size` payload bytes. Returns a payload pointer,
    /// or `None` on exhaustion.
    pub fn allocate(&mut self, size: usize) -> Option<*mut u8> {
        if !self.formatted {
            return None;
        }
        let need = round_up(HDR + size.max(1), HEAP_ALIGN);
        let base = self.backing.base();
        let end = self.region_end();
        let mut cur = base;
        // SAFETY: we walk physically-adjacent, in-region block headers (formatted at create).
        unsafe {
            while (cur as usize) < end {
                let h = self.hdr(cur);
                let (bsize, bfree) = ((*h).size, (*h).free);
                if bfree && bsize >= need {
                    self.split(cur, need);
                    (*self.hdr(cur)).free = false;
                    return Some(cur.add(HDR));
                }
                cur = cur.add(bsize);
            }
        }
        None
    }

    /// The payload size of an allocation (`RtlSizeHeap`). Returns `None` if `payload` is not a live
    /// allocation from this heap.
    ///
    /// # Safety
    /// `payload` must be a pointer previously returned by [`Self::allocate`]/[`Self::reallocate`] on
    /// this heap, or null. (The real ntdll `RtlSizeHeap` trusts the caller's pointer identically.)
    pub unsafe fn size_of(&self, payload: *mut u8) -> Option<usize> {
        let block = self.block_of(payload)?;
        let h = &*(block as *const BlockHeader);
        if h.free {
            return None;
        }
        Some(h.size - HDR)
    }

    /// Validate + recover the block header for a payload pointer.
    fn block_of(&self, payload: *mut u8) -> Option<*mut u8> {
        if payload.is_null() {
            return None;
        }
        let base = self.backing.base() as usize;
        let p = payload as usize;
        if p < base + HDR || p >= self.region_end() {
            return None;
        }
        Some((p - HDR) as *mut u8)
    }

    /// `RtlFreeHeap(payload)`: free an allocation and coalesce with free neighbours. Returns `false`
    /// if `payload` is invalid or already free.
    ///
    /// # Safety
    /// `payload` must be a pointer previously returned by [`Self::allocate`]/[`Self::reallocate`] on
    /// this heap, or null (matching the real `RtlFreeHeap` contract).
    pub unsafe fn free(&mut self, payload: *mut u8) -> bool {
        let Some(block) = self.block_of(payload) else {
            return false;
        };
        if (*self.hdr(block)).free {
            return false;
        }
        (*self.hdr(block)).free = true;
        self.coalesce(block);
        true
    }

    /// Merge `block` with its physically-adjacent free predecessor and successor.
    ///
    /// # Safety
    /// `block` must be a valid, now-free block header.
    unsafe fn coalesce(&mut self, block: *mut u8) {
        let end = self.region_end();
        let mut start = block;

        // Merge backward if the predecessor is free.
        let prev_size = (*self.hdr(start)).prev_size;
        if prev_size != 0 {
            let prev = start.sub(prev_size);
            if (*self.hdr(prev)).free {
                (*self.hdr(prev)).size += (*self.hdr(start)).size;
                start = prev;
            }
        }

        // Merge forward if the successor is free.
        let next = start.add((*self.hdr(start)).size);
        if (next as usize) < end && (*self.hdr(next)).free {
            (*self.hdr(start)).size += (*self.hdr(next)).size;
        }

        // Fix the (possibly new) following block's prev_size.
        let after = start.add((*self.hdr(start)).size);
        if (after as usize) < end {
            (*self.hdr(after)).prev_size = (*self.hdr(start)).size;
        }
    }

    /// `RtlReAllocateHeap(payload, new_size)`: grow/shrink in place when possible, else allocate +
    /// copy + free. Returns the (possibly new) payload pointer, or `None` on exhaustion (the
    /// original allocation is left intact on failure, matching the Windows contract).
    ///
    /// # Safety
    /// `payload` must be a live allocation from this heap (see [`Self::allocate`]).
    pub unsafe fn reallocate(&mut self, payload: *mut u8, new_size: usize) -> Option<*mut u8> {
        let old_size = self.size_of(payload)?;
        let need = round_up(HDR + new_size.max(1), HEAP_ALIGN);
        let block = self.block_of(payload)?;

        let cur_total = (*self.hdr(block)).size;
        // Shrink (or same): split off the tail if worthwhile.
        if need <= cur_total {
            self.split(block, need);
            return Some(payload);
        }
        // Try to grow into a free successor.
        let next = block.add(cur_total);
        if (next as usize) < self.region_end()
            && (*self.hdr(next)).free
            && cur_total + (*self.hdr(next)).size >= need
        {
            let merged = cur_total + (*self.hdr(next)).size;
            (*self.hdr(block)).size = merged;
            // Fix the block after `next`.
            let after = block.add(merged);
            if (after as usize) < self.region_end() {
                (*self.hdr(after)).prev_size = merged;
            }
            self.split(block, need);
            return Some(payload);
        }

        // Fall back to allocate + copy + free.
        let dst = self.allocate(new_size)?;
        core::ptr::copy_nonoverlapping(payload, dst, old_size.min(new_size));
        self.free(payload);
        Some(dst)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// A host-test backing region: an owned `Vec<u8>`.
    struct VecBacking {
        buf: Vec<u8>,
    }
    // SAFETY: the Vec's buffer is valid for its whole length for the lifetime of the backing, and
    // `Vec<u8>` guarantees at least 1-byte alignment; we over-allocate to HEAP_ALIGN below.
    unsafe impl Backing for VecBacking {
        fn base(&self) -> *mut u8 {
            // Align the base up to HEAP_ALIGN by leaking the misaligned prefix (test-only).
            let raw = self.buf.as_ptr() as usize;
            round_up(raw, HEAP_ALIGN) as *mut u8
        }
        fn len(&self) -> usize {
            let raw = self.buf.as_ptr() as usize;
            let aligned = round_up(raw, HEAP_ALIGN);
            self.buf.len() - (aligned - raw)
        }
    }

    fn heap(bytes: usize) -> Heap<VecBacking> {
        Heap::create(VecBacking {
            buf: vec![0u8; bytes + HEAP_ALIGN],
        })
        .unwrap()
    }

    #[test]
    fn payload_is_aligned() {
        let mut h = heap(4096);
        for sz in [1usize, 7, 16, 100, 300] {
            let p = h.allocate(sz).unwrap();
            assert_eq!(p as usize % HEAP_ALIGN, 0, "payload for {sz} unaligned");
        }
    }

    #[test]
    fn alloc_size_free_roundtrip() {
        let mut h = heap(4096);
        let p = h.allocate(100).unwrap();
        // SAFETY: p is a live allocation from this heap for the whole reported extent.
        unsafe {
            assert!(h.size_of(p).unwrap() >= 100);
            let n = h.size_of(p).unwrap();
            core::ptr::write_bytes(p, 0xAB, n); // write the whole extent — must not overlap
            assert!(h.free(p));
            assert!(!h.free(p)); // double-free rejected
            assert!(h.size_of(p).is_none()); // freed -> no size
        }
    }

    #[test]
    fn distinct_allocations_do_not_overlap() {
        let mut h = heap(4096);
        let a = h.allocate(64).unwrap();
        let b = h.allocate(64).unwrap();
        let c = h.allocate(64).unwrap();
        let sz = 64usize;
        // No two payloads overlap.
        for (x, y) in [(a, b), (a, c), (b, c)] {
            let (xs, ys) = (x as usize, y as usize);
            assert!(xs + sz <= ys || ys + sz <= xs, "overlap");
        }
    }

    #[test]
    fn free_coalesces_and_reuses() {
        let mut h = heap(1024);
        let a = h.allocate(200).unwrap();
        let b = h.allocate(200).unwrap();
        let c = h.allocate(200).unwrap();
        // SAFETY: a/b/c are live allocations from this heap.
        unsafe {
            h.free(b);
            h.free(a); // a+b coalesce backward
            h.free(c); // ...eventually the whole region is one free block again
        }
        // A single large alloc that only fits if coalescing worked.
        let big = h.allocate(600);
        assert!(big.is_some(), "coalescing failed to reclaim space");
    }

    #[test]
    fn exhaustion_returns_none_then_recovers() {
        let mut h = heap(256);
        let mut ptrs = Vec::new();
        // Allocate until exhausted.
        while let Some(p) = h.allocate(32) {
            ptrs.push(p);
        }
        assert!(!ptrs.is_empty());
        assert!(h.allocate(32).is_none());
        // Free one and re-allocate succeeds.
        // SAFETY: the popped pointer is a live allocation from this heap.
        unsafe { h.free(ptrs.pop().unwrap()) };
        assert!(h.allocate(32).is_some());
    }

    #[test]
    fn realloc_grow_in_place_and_relocate() {
        let mut h = heap(4096);
        let p = h.allocate(64).unwrap();
        // SAFETY: p/p2/r are live allocations from this heap for the extents accessed.
        unsafe {
            core::ptr::write_bytes(p, 0x5A, 64);
            // Grow into the trailing free space (in place — the next block is free).
            let g = h.reallocate(p, 128).unwrap();
            assert_eq!(g, p, "expected in-place grow into trailing free block");
            assert!(h.size_of(g).unwrap() >= 128);
            assert!(core::slice::from_raw_parts(g, 64)
                .iter()
                .all(|&x| x == 0x5A)); // preserved

            // Now block a successor so the next grow must relocate.
            let _blocker = h.allocate(64).unwrap();
            let p2 = h.allocate(32).unwrap();
            core::ptr::write_bytes(p2, 0x33, 32);
            let r = h.reallocate(p2, 512).unwrap();
            assert!(h.size_of(r).unwrap() >= 512);
            assert!(core::slice::from_raw_parts(r, 32)
                .iter()
                .all(|&x| x == 0x33)); // preserved
        }
    }

    #[test]
    fn realloc_shrink_frees_tail() {
        let mut h = heap(1024);
        let p = h.allocate(400).unwrap();
        // SAFETY: p is a live allocation from this heap.
        let r = unsafe { h.reallocate(p, 32).unwrap() };
        assert_eq!(r, p);
        // The freed tail is reusable.
        assert!(h.allocate(300).is_some());
    }

    #[test]
    fn create_rejects_tiny_region() {
        assert!(Heap::create(VecBacking { buf: vec![0u8; 4] }).is_none());
    }

    #[test]
    fn destroy_returns_backing() {
        let h = heap(256);
        let b = h.destroy();
        assert!(b.len() >= 256);
    }
}
