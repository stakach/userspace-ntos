//! Address-ordered durable free-list insertion. The addresses are supplied by the owning heap so
//! the same list operations can be exercised against ordinary aligned memory on the host.

use core::mem::{align_of, size_of};
use core::ptr::{read_volatile, write_volatile};

const WORD: usize = size_of::<usize>();
const NODE_SIZE: usize = WORD * 2;
const GRANULE: usize = align_of::<usize>();

#[derive(Debug)]
pub(super) struct Corruption {
    pub operation: &'static [u8],
    pub node: usize,
    pub size: usize,
    pub next: usize,
}

pub(super) struct FreeList {
    pub data: usize,
    pub counter: usize,
    pub head: usize,
}

impl FreeList {
    unsafe fn read(addr: usize) -> usize {
        unsafe { read_volatile(addr as *const usize) }
    }

    unsafe fn write(addr: usize, value: usize) {
        unsafe { write_volatile(addr as *mut usize, value) };
    }

    fn corrupt(operation: &'static [u8], node: usize, size: usize, next: usize) -> Corruption {
        Corruption { operation, node, size, next }
    }

    /// Insert one dead allocation and immediately trim the coalesced node if it reaches the bump
    /// top. The ordered insertion walk already knows the link preceding that node; no second walk
    /// is needed. Returns the visited-node count in host tests only.
    pub(super) unsafe fn insert(&self, start: usize, size: usize) -> Result<usize, Corruption> {
        let top = self.data + unsafe { Self::read(self.counter) };
        if size < NODE_SIZE
            || size % GRANULE != 0
            || start < self.data
            || start % GRANULE != 0
            || start.checked_add(size).is_none_or(|end| end > top)
        {
            return Err(Self::corrupt(b"insert", start, size, 0));
        }
        #[allow(unused_mut)]
        let mut visits = 0;
        let mut prev = 0usize;
        let mut link = self.head;
        let mut prev_link = self.head;
        let mut cur = unsafe { Self::read(self.head) };
        while cur != 0 {
            if cur < self.data
                || cur % GRANULE != 0
                || cur.checked_add(NODE_SIZE).is_none_or(|end| end > top)
            {
                return Err(Self::corrupt(b"insert-walk", cur, 0, 0));
            }
            let cur_size = unsafe { Self::read(cur) };
            let next = unsafe { Self::read(cur + WORD) };
            let Some(cur_end) = cur.checked_add(cur_size) else {
                return Err(Self::corrupt(b"insert-walk", cur, cur_size, next));
            };
            if cur_size < NODE_SIZE
                || cur_size % GRANULE != 0
                || cur_end > top
                || (next != 0
                    && (next <= cur_end || next >= top || next % GRANULE != 0))
            {
                return Err(Self::corrupt(b"insert-walk", cur, cur_size, next));
            }
            #[cfg(test)]
            { visits += 1; }
            if cur >= start {
                break;
            }
            prev = cur;
            prev_link = link;
            link = cur + WORD;
            cur = next;
        }
        if cur == start {
            return Ok(visits);
        }
        let end = start + size;
        if (prev != 0
            && prev
                .checked_add(unsafe { Self::read(prev) })
                .is_none_or(|prev_end| prev_end > start))
            || (cur != 0 && end > cur)
        {
            return Err(Self::corrupt(b"insert-overlap", cur, 0, 0));
        }
        let mut final_start = start;
        let mut final_size = size;
        let mut final_next = cur;
        let mut final_link = link;
        if cur != 0 && end == cur {
            final_size = size.checked_add(unsafe { Self::read(cur) })
                .ok_or_else(|| Self::corrupt(b"insert-merge", start, size, cur))?;
            final_next = unsafe { Self::read(cur + WORD) };
        }
        if prev != 0 {
            let prev_size = unsafe { Self::read(prev) };
            if prev.checked_add(prev_size) == Some(start) {
                final_start = prev;
                final_size = prev_size.checked_add(final_size)
                    .ok_or_else(|| Self::corrupt(b"insert-merge", prev, prev_size, final_next))?;
                final_link = prev_link;
            }
        }
        let final_end = final_start.checked_add(final_size)
            .ok_or_else(|| Self::corrupt(b"insert-merge", final_start, final_size, final_next))?;
        if final_end > top || (final_end == top && final_next != 0) {
            return Err(Self::corrupt(b"insert-merge", final_start, final_size, final_next));
        }
        unsafe {
            Self::write(final_start, final_size);
            Self::write(final_start + WORD, final_next);
            Self::write(final_link, final_start);
        }
        if final_end == top {
            unsafe {
                Self::write(final_link, final_next);
                Self::write(self.counter, final_start - self.data);
            }
        }
        Ok(visits)
    }
}
