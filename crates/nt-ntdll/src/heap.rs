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
//! `BlockHeader` holds boundary sizes, live/free state, and the allocation's optional user metadata.
//! `size`/`prev_size` are payload+header sizes in bytes; `prev_size == 0` marks the first block. Free
//! blocks are found by a linear walk (first-fit) -- adequate and simple; a size-class free-list is a
//! later optimisation, not correctness.

use core::mem::{align_of, size_of};

/// Every allocation is rounded up to this alignment (the Windows heap guarantees 16-byte alignment
/// on x64, matching `MEMORY_ALLOCATION_ALIGNMENT`).
pub const HEAP_ALIGN: usize = 16;
/// Zero newly allocated or grown payload bytes.
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

/// Request per-allocation storage for `RtlSetUserValueHeap`.
pub const HEAP_SETTABLE_USER_VALUE: u32 = 0x0000_0100;
/// The three caller-controlled heap-entry flags returned by `RtlGetUserInfoHeap`.
pub const HEAP_SETTABLE_USER_FLAGS: u32 = 0x0000_0e00;

/// User metadata associated with one live heap allocation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HeapUserInfo {
    /// Whether the allocation requested storage for a user value.
    pub has_user_value: bool,
    /// The stored opaque user value. Meaningful only when [`Self::has_user_value`] is true.
    pub user_value: usize,
    /// The allocation's `HEAP_SETTABLE_USER_FLAG{1,2,3}` bits.
    pub user_flags: u32,
}

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
    /// Opaque value stored by `RtlSetUserValueHeap`.
    user_value: usize,
    /// Caller-controlled `HEAP_SETTABLE_USER_FLAGS` bits.
    user_flags: u32,
    /// Whether this block is free.
    free: bool,
    /// Whether this allocation requested user-value storage.
    has_user_value: bool,
}

#[inline]
const fn round_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

/// The in-band header size, rounded up to [`HEAP_ALIGN`] so every payload (which sits at
/// `block + HDR`) lands [`HEAP_ALIGN`]-aligned when the block itself is aligned.
const HDR: usize = round_up(size_of::<BlockHeader>(), HEAP_ALIGN);

fn checked_block_size(payload_size: usize) -> Option<usize> {
    HDR.checked_add(payload_size.max(1))?
        .checked_add(HEAP_ALIGN - 1)
        .map(|size| size & !(HEAP_ALIGN - 1))
}

/// A first-fit free-list heap over a [`Backing`] region.
pub struct Heap<B: Backing> {
    backing: B,
    /// Aligned prefix of the backing used for physical blocks.
    region_len: usize,
    /// Whether the region has been formatted into an initial free block.
    formatted: bool,
}

impl<B: Backing> Heap<B> {
    /// `RtlCreateHeap`: format `backing` into a single free block spanning the whole region.
    /// Returns `None` if the region is too small to hold even a header.
    pub fn create(backing: B) -> Option<Self> {
        let region_len = backing.len() & !(HEAP_ALIGN - 1);
        if region_len < HDR + HEAP_ALIGN {
            return None;
        }
        // The header must be at least HEAP_ALIGN-aligned so payloads land aligned.
        debug_assert!(align_of::<BlockHeader>() <= HEAP_ALIGN);
        let mut h = Heap {
            backing,
            region_len,
            formatted: false,
        };
        // SAFETY: region is >= HDR+HEAP_ALIGN and valid per the Backing contract.
        unsafe {
            let base = h.backing.base();
            core::ptr::write(
                base as *mut BlockHeader,
                BlockHeader {
                    size: h.region_len,
                    prev_size: 0,
                    user_value: 0,
                    user_flags: 0,
                    free: true,
                    has_user_value: false,
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
        self.backing.base() as usize + self.region_len
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
    /// `block` must be a valid block header with `block.size >= need`.
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
                    user_value: 0,
                    user_flags: 0,
                    free: true,
                    has_user_value: false,
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
        self.allocate_with_flags(size, 0)
    }

    /// Allocate a block and capture the per-allocation user metadata requested in `flags`.
    pub fn allocate_with_flags(&mut self, size: usize, flags: u32) -> Option<*mut u8> {
        if !self.formatted {
            return None;
        }
        let need = checked_block_size(size)?;
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
                    let allocated = self.hdr(cur);
                    (*allocated).user_value = 0;
                    (*allocated).user_flags = flags & HEAP_SETTABLE_USER_FLAGS;
                    (*allocated).free = false;
                    (*allocated).has_user_value = flags & HEAP_SETTABLE_USER_VALUE != 0;
                    let payload = cur.add(HDR);
                    if flags & HEAP_ZERO_MEMORY != 0 && size != 0 {
                        core::ptr::write_bytes(payload, 0, size);
                    }
                    return Some(payload);
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

        let mut current = base;
        while current < self.region_end() {
            // SAFETY: current begins at the formatted base and advances only through validated
            // physical block sizes.
            let block_size = unsafe { (*self.hdr(current as *mut u8)).size };
            if block_size < HDR
                || block_size % HEAP_ALIGN != 0
                || current.saturating_add(block_size) > self.region_end()
            {
                return None;
            }
            if current + HDR == p {
                return Some(current as *mut u8);
            }
            current += block_size;
        }
        None
    }

    /// Return the user metadata for a live allocation.
    ///
    /// # Safety
    /// `payload` follows the same contract as [`Self::size_of`].
    pub unsafe fn user_info(&self, payload: *mut u8) -> Option<HeapUserInfo> {
        let block = self.block_of(payload)?;
        let header = &*self.hdr(block);
        if header.free {
            return None;
        }
        Some(HeapUserInfo {
            has_user_value: header.has_user_value,
            user_value: header.user_value,
            user_flags: header.user_flags,
        })
    }

    /// Store an opaque user value when the allocation requested user-value metadata.
    ///
    /// # Safety
    /// `payload` follows the same contract as [`Self::size_of`].
    pub unsafe fn set_user_value(&mut self, payload: *mut u8, value: usize) -> bool {
        let Some(block) = self.block_of(payload) else {
            return false;
        };
        let header = &mut *self.hdr(block);
        if header.free || !header.has_user_value {
            return false;
        }
        header.user_value = value;
        true
    }

    /// Reset and set the three caller-controlled per-allocation user flags.
    ///
    /// # Safety
    /// `payload` follows the same contract as [`Self::size_of`].
    pub unsafe fn set_user_flags(&mut self, payload: *mut u8, reset: u32, set: u32) -> bool {
        if (reset | set) & !HEAP_SETTABLE_USER_FLAGS != 0 {
            return false;
        }
        let Some(block) = self.block_of(payload) else {
            return false;
        };
        let header = &mut *self.hdr(block);
        if header.free {
            return false;
        }
        header.user_flags = (header.user_flags & !reset) | set;
        true
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
        let block = self.block_of(payload)?;
        let header = &*self.hdr(block);
        if header.free {
            return None;
        }
        let flags = header.user_flags
            | if header.has_user_value {
                HEAP_SETTABLE_USER_VALUE
            } else {
                0
            };
        self.reallocate_with_flags(payload, new_size, flags, false)
    }

    /// Reallocate with the native heap flags that affect user metadata and relocation. Shrinking
    /// preserves user flags; in-place growth replaces them with the supplied bits; relocation of a
    /// block with user-value storage preserves its old flags. The stored user value always survives.
    ///
    /// # Safety
    /// `payload` must be a live allocation from this heap.
    pub unsafe fn reallocate_with_flags(
        &mut self,
        payload: *mut u8,
        new_size: usize,
        flags: u32,
        in_place_only: bool,
    ) -> Option<*mut u8> {
        let old_size = self.size_of(payload)?;
        let need = checked_block_size(new_size)?;
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
            (*self.hdr(block)).user_flags = flags & HEAP_SETTABLE_USER_FLAGS;
            if flags & HEAP_ZERO_MEMORY != 0 && new_size > old_size {
                core::ptr::write_bytes(payload.add(old_size), 0, new_size - old_size);
            }
            return Some(payload);
        }

        // Fall back to allocate + copy + free.
        if in_place_only {
            return None;
        }
        let old_header = *self.hdr(block);
        let allocation_flags = if old_header.has_user_value {
            (flags & !HEAP_SETTABLE_USER_FLAGS) | HEAP_SETTABLE_USER_VALUE | old_header.user_flags
        } else {
            flags
        };
        let dst = self.allocate_with_flags(new_size, allocation_flags)?;
        let dst_block = self.block_of(dst)?;
        (*self.hdr(dst_block)).user_value = old_header.user_value;
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
    fn user_metadata_requires_live_exact_allocation() {
        let mut h = heap(1024);
        let plain = h.allocate_with_flags(64, 0x400).unwrap();
        let with_value = h
            .allocate_with_flags(64, HEAP_SETTABLE_USER_VALUE | 0x200)
            .unwrap();
        // SAFETY: both pointers are live allocations; the interior pointer is deliberately invalid.
        unsafe {
            assert_eq!(
                h.user_info(plain),
                Some(HeapUserInfo {
                    has_user_value: false,
                    user_value: 0,
                    user_flags: 0x400,
                })
            );
            assert!(!h.set_user_value(plain, 0x1234));
            assert!(h.set_user_value(with_value, 0x1234));
            assert_eq!(h.user_info(with_value).unwrap().user_value, 0x1234);
            assert!(h.user_info(plain.add(1)).is_none());
            assert!(h.free(plain));
            assert!(h.user_info(plain).is_none());
        }
    }

    #[test]
    fn set_user_flags_validates_mask_and_applies_reset_before_set() {
        let mut h = heap(1024);
        let p = h.allocate_with_flags(64, 0x600).unwrap();
        // SAFETY: p is a live allocation from this heap.
        unsafe {
            assert!(h.set_user_flags(p, 0x600, 0x800));
            assert_eq!(h.user_info(p).unwrap().user_flags, 0x800);
            assert!(!h.set_user_flags(p, HEAP_SETTABLE_USER_VALUE, 0));
            assert!(!h.set_user_flags(p, 0, 0x1000));
            assert_eq!(h.user_info(p).unwrap().user_flags, 0x800);
        }
    }

    #[test]
    fn realloc_preserves_value_and_updates_flags_only_when_growing() {
        let mut h = heap(4096);
        let p = h
            .allocate_with_flags(256, HEAP_SETTABLE_USER_VALUE | 0x400)
            .unwrap();
        // SAFETY: each pointer used below is the current live allocation from this heap.
        unsafe {
            assert!(h.set_user_value(p, 0xfeed));
            let shrunk = h.reallocate_with_flags(p, 128, 0x200, true).unwrap();
            assert_eq!(shrunk, p);
            assert_eq!(
                h.user_info(shrunk).unwrap(),
                HeapUserInfo {
                    has_user_value: true,
                    user_value: 0xfeed,
                    user_flags: 0x400,
                }
            );

            let grown = h.reallocate_with_flags(shrunk, 192, 0x200, true).unwrap();
            assert_eq!(grown, p);
            assert_eq!(
                h.user_info(grown).unwrap(),
                HeapUserInfo {
                    has_user_value: true,
                    user_value: 0xfeed,
                    user_flags: 0x200,
                }
            );

            let blocker = h.allocate(64).unwrap();
            assert!(h.reallocate_with_flags(grown, 1024, 0x800, true).is_none());
            assert_eq!(h.user_info(grown).unwrap().user_value, 0xfeed);
            let relocated = h.reallocate_with_flags(grown, 1024, 0x800, false).unwrap();
            assert_ne!(relocated, grown);
            assert_eq!(
                h.user_info(relocated).unwrap(),
                HeapUserInfo {
                    has_user_value: true,
                    user_value: 0xfeed,
                    user_flags: 0x200,
                }
            );
            assert!(h.free(blocker));
        }
    }

    #[test]
    fn create_rejects_tiny_region() {
        assert!(Heap::create(VecBacking { buf: vec![0u8; 4] }).is_none());
    }

    #[test]
    fn oversized_alloc_and_realloc_fail_without_mutating_the_heap() {
        let mut h = heap(1024);
        let p = h.allocate(64).unwrap();
        assert!(h.allocate(usize::MAX).is_none());
        // SAFETY: p remains a live allocation after the failed reallocation.
        unsafe {
            assert!(h.reallocate(p, usize::MAX).is_none());
            assert!(h.size_of(p).is_some());
            assert!(h.free(p));
        }
    }

    #[test]
    fn zero_memory_covers_reused_allocations_and_grown_tails() {
        let mut h = heap(4096);
        let dirty = h.allocate(64).unwrap();
        // SAFETY: every pointer below is live for the byte range accessed.
        unsafe {
            core::ptr::write_bytes(dirty, 0xaa, 64);
            assert!(h.free(dirty));
        }
        let reused = h.allocate_with_flags(64, HEAP_ZERO_MEMORY).unwrap();
        // SAFETY: reused is live for at least 64 bytes.
        unsafe {
            assert!(core::slice::from_raw_parts(reused, 64)
                .iter()
                .all(|byte| *byte == 0));
            core::ptr::write_bytes(reused, 0x5a, 64);
            let grown = h
                .reallocate_with_flags(reused, 128, HEAP_ZERO_MEMORY, true)
                .unwrap();
            assert!(core::slice::from_raw_parts(grown, 64)
                .iter()
                .all(|byte| *byte == 0x5a));
            assert!(core::slice::from_raw_parts(grown.add(64), 64)
                .iter()
                .all(|byte| *byte == 0));
            let _blocker = h.allocate(64).unwrap();
            let relocated = h
                .reallocate_with_flags(grown, 512, HEAP_ZERO_MEMORY, false)
                .unwrap();
            assert_ne!(relocated, grown);
            assert!(core::slice::from_raw_parts(relocated, 64)
                .iter()
                .all(|byte| *byte == 0x5a));
            assert!(core::slice::from_raw_parts(relocated.add(64), 512 - 64)
                .iter()
                .all(|byte| *byte == 0));
        }
    }

    #[test]
    fn destroy_returns_backing() {
        let h = heap(256);
        let b = h.destroy();
        assert!(b.len() >= 256);
    }
}
