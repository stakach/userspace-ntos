//! Exact-size LIFO caches for small durable blocks, ahead of the address-ordered free list.
//!
//! The address-ordered first-fit list costs a walk per allocation and per release; boot
//! 44647857225 spent ~316 G TSC ticks walking it (more than all native dispatch), crossing an
//! average of ~170 nodes per allocation. A released block of 16..=[`QUICK_MAX_BLOCK`] bytes is
//! therefore not threaded back into that list as one more fragment: it is pushed onto
//! the cache of its exact size and the next allocation of that size pops it, both without a
//! walk. Each cache holds at most [`QUICK_CLASS_BYTES`]; a full cache, a misaligned head or an
//! exhausted heap falls back to (or drains into) the address-ordered list, which coalesces.
//! Metadata lives in caller-supplied words so isolated heaps keep it out of the shared image.

use core::ptr::{read_volatile, write_volatile};

const WORD: usize = core::mem::size_of::<usize>();
const GRANULE: usize = core::mem::align_of::<usize>();
const MIN_BLOCK: usize = WORD * 2;
pub(super) const QUICK_MAX_BLOCK: usize = 256;
pub(super) const QUICK_CLASSES: usize = (QUICK_MAX_BLOCK - MIN_BLOCK) / GRANULE + 1;
/// Bytes each exact-size cache may hold; smaller sizes cache proportionally more blocks.
pub(super) const QUICK_CLASS_BYTES: usize = 128 * 1024;

/// Blocks the cache of `size` may hold.
pub(super) const fn class_cap(size: usize) -> usize { QUICK_CLASS_BYTES / size }
/// A head and a count per class.
pub(super) const QUICK_WORDS: usize = QUICK_CLASSES * 2;

/// A cached node failed validation; the caller reports it as allocator corruption.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct QuickCorruption {
    pub node: usize,
    pub size: usize,
    pub next: usize,
}

pub(super) struct QuickLists {
    /// Address of [`QUICK_WORDS`] zero-initialized words.
    pub meta: usize,
    /// Lowest valid block address.
    pub data: usize,
}

impl QuickLists {
    unsafe fn read(addr: usize) -> usize { unsafe { read_volatile(addr as *const usize) } }
    unsafe fn write(addr: usize, value: usize) {
        unsafe { write_volatile(addr as *mut usize, value) }
    }

    fn class(size: usize) -> Option<usize> {
        (size >= MIN_BLOCK && size <= QUICK_MAX_BLOCK && size % GRANULE == 0)
            .then(|| (size - MIN_BLOCK) / GRANULE)
    }
    fn head_addr(&self, class: usize) -> usize { self.meta + class * 2 * WORD }
    fn count_addr(&self, class: usize) -> usize { self.head_addr(class) + WORD }

    /// Whether a block of exactly `size` bytes has a cache. A realloc that grows to such a size
    /// moves through the caches instead of walking the list for an adjacent free block.
    pub(super) fn serves(size: usize) -> bool { Self::class(size).is_some() }

    /// Cache a released block. `false` leaves it for the address-ordered list.
    pub(super) unsafe fn push(&self, start: usize, size: usize) -> bool {
        let Some(class) = Self::class(size) else { return false; };
        let count = unsafe { Self::read(self.count_addr(class)) };
        if count >= class_cap(size) { return false; }
        unsafe {
            Self::write(start, size);
            Self::write(start + WORD, Self::read(self.head_addr(class)));
            Self::write(self.head_addr(class), start);
            Self::write(self.count_addr(class), count + 1);
        }
        true
    }

    /// Pop a cached block of exactly `size` bytes aligned to `align`, below `top`. A
    /// misaligned head is left in place; the caller then uses the address-ordered list.
    pub(super) unsafe fn pop(&self, size: usize, align: usize, top: usize)
        -> Result<Option<usize>, QuickCorruption> {
        let Some(class) = Self::class(size) else { return Ok(None); };
        let node = unsafe { Self::read(self.head_addr(class)) };
        if node == 0 { return Ok(None); }
        let node_size = unsafe { Self::read(node) };
        let next = unsafe { Self::read(node + WORD) };
        let count = unsafe { Self::read(self.count_addr(class)) };
        let valid = |addr: usize| addr >= self.data && addr % GRANULE == 0
            && addr.checked_add(size).is_some_and(|end| end <= top);
        if !valid(node) || node_size != size || (next != 0 && !valid(next)) || count == 0 {
            return Err(QuickCorruption { node, size: node_size, next });
        }
        if node % align.max(GRANULE) != 0 { return Ok(None); }
        unsafe {
            Self::write(self.head_addr(class), next);
            Self::write(self.count_addr(class), count - 1);
        }
        Ok(Some(node))
    }

    /// Hand every cached block to `release` (the address-ordered insertion) and empty the caches.
    pub(super) unsafe fn drain(&self, mut release: impl FnMut(usize, usize)) -> usize {
        let mut drained = 0;
        for class in 0..QUICK_CLASSES {
            let size = MIN_BLOCK + class * GRANULE;
            let mut node = unsafe { Self::read(self.head_addr(class)) };
            unsafe {
                Self::write(self.head_addr(class), 0);
                Self::write(self.count_addr(class), 0);
            }
            while node != 0 {
                let next = unsafe { Self::read(node + WORD) };
                release(node, size);
                drained += 1;
                node = next;
            }
        }
        drained
    }

    /// Cached bytes and the largest cached block, from the counts alone.
    pub(super) unsafe fn cached(&self) -> (usize, usize) {
        let mut bytes = 0;
        let mut largest = 0;
        for class in 0..QUICK_CLASSES {
            let count = unsafe { Self::read(self.count_addr(class)) };
            if count != 0 {
                let size = MIN_BLOCK + class * GRANULE;
                bytes += count * size;
                largest = size;
            }
        }
        (bytes, largest)
    }
}
