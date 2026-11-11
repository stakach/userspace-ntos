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

pub(super) struct AdjacentGrowth {
    pub grown: bool,
    pub inspected: usize,
}

#[derive(Debug)]
pub(super) struct TakeFit {
    pub address: Option<usize>,
    pub inspected: usize,
    pub prefix_reinsert_visits: Option<usize>,
    pub suffix_reinsert_visits: Option<usize>,
}

#[derive(Debug)]
pub(super) struct TakeFitError {
    pub corruption: Corruption,
    pub owner_start: usize,
    pub owner_size: usize,
}

pub(super) fn align_up(value: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    Some(value.checked_add(align - 1)? & !(align - 1))
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

    /// Check a node before a split uses its links or publishes a replacement.
    unsafe fn checked_node(
        &self,
        node: usize,
        top: usize,
    ) -> Result<(usize, usize, usize), Corruption> {
        if node < self.data
            || node % GRANULE != 0
            || node.checked_add(NODE_SIZE).is_none_or(|end| end > top)
        {
            return Err(Self::corrupt(b"take-fit-walk", node, 0, 0));
        }
        let size = unsafe { Self::read(node) };
        let next = unsafe { Self::read(node + WORD) };
        let Some(end) = node.checked_add(size) else {
            return Err(Self::corrupt(b"take-fit-walk", node, size, next));
        };
        if size < NODE_SIZE
            || size % GRANULE != 0
            || end > top
            || (next != 0 && (next <= end || next >= top || next % GRANULE != 0))
        {
            return Err(Self::corrupt(b"take-fit-walk", node, size, next));
        }
        Ok((size, next, end))
    }

    /// First-fit selection. The split already knows the predecessor and successor, so unused
    /// fragments can be linked in place without searching the ordered list a second time.
    pub(super) unsafe fn take_fit(
        &self,
        align: usize,
        needed: usize,
    ) -> Result<TakeFit, TakeFitError> {
        let align = align.max(GRANULE);
        let top = self.data.checked_add(unsafe { Self::read(self.counter) })
            .ok_or_else(|| TakeFitError {
                corruption: Self::corrupt(b"take-fit-top", self.data, 0, 0),
                owner_start: self.data, owner_size: 0,
            })?;
        let mut prev_link = self.head;
        let mut cur = unsafe { Self::read(self.head) };
        let mut previous_end = self.data;
        let mut inspected = 0usize;
        while cur != 0 {
            inspected += 1;
            let (size, next, cur_end) = unsafe { self.checked_node(cur, top) }
                .map_err(|corruption| TakeFitError {
                    corruption, owner_start: cur, owner_size: 0,
                })?;
            if inspected > 1 && cur <= previous_end {
                return Err(TakeFitError {
                    corruption: Self::corrupt(b"take-fit-order", cur, size, next),
                    owner_start: cur, owner_size: size,
                });
            }
            let mut start = match align_up(cur, align) {
                Some(start) => start,
                None => return Ok(TakeFit {
                    address: None, inspected,
                    prefix_reinsert_visits: None, suffix_reinsert_visits: None,
                }),
            };
            let mut prefix = start - cur;
            if prefix != 0 && prefix < NODE_SIZE {
                start = match align_up(cur + NODE_SIZE, align) {
                    Some(start) => start,
                    None => return Ok(TakeFit {
                        address: None, inspected,
                        prefix_reinsert_visits: None, suffix_reinsert_visits: None,
                    }),
                };
                prefix = start - cur;
            }
            if prefix.checked_add(needed).is_some_and(|total| total <= size) {
                let suffix_start = start + needed;
                let suffix = cur_end - suffix_start;
                if next != 0 {
                    unsafe { self.checked_node(next, top) }
                        .map_err(|corruption| TakeFitError {
                            corruption, owner_start: cur, owner_size: size,
                        })?;
                }
                let keep_prefix = prefix >= NODE_SIZE;
                // Insertion immediately trims a top-ending suffix. Publish the same bump
                // position without first writing and walking an unreachable free node.
                let keep_suffix = suffix >= NODE_SIZE && cur_end != top;
                let first = if keep_prefix { cur }
                    else if keep_suffix { suffix_start }
                    else { next };
                unsafe {
                    if keep_suffix {
                        Self::write(suffix_start, suffix);
                        Self::write(suffix_start + WORD, next);
                    }
                    if keep_prefix {
                        Self::write(cur, prefix);
                        Self::write(cur + WORD, if keep_suffix { suffix_start } else { next });
                    }
                    Self::write(prev_link, first);
                    if suffix >= NODE_SIZE && cur_end == top {
                        Self::write(self.counter, suffix_start - self.data);
                    }
                }
                return Ok(TakeFit {
                    address: Some(start), inspected,
                    prefix_reinsert_visits: keep_prefix.then_some(0),
                    suffix_reinsert_visits: (suffix >= NODE_SIZE).then_some(0),
                });
            }
            prev_link = cur + WORD;
            previous_end = cur_end;
            cur = next;
        }
        Ok(TakeFit {
            address: None, inspected,
            prefix_reinsert_visits: None, suffix_reinsert_visits: None,
        })
    }

    /// Insert one dead allocation and immediately trim the coalesced node if it reaches the bump
    /// top. The ordered insertion walk already knows the link preceding that node; no second walk
    /// is needed. Returns the visited-node count for bounded allocator telemetry.
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
            visits += 1;
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

    /// Consume a free node that starts exactly where the allocation ends. Nodes are ordered by
    /// address, so the first node past that address also proves that no later node can match.
    pub(super) unsafe fn grow_adjacent(
        &self,
        start: usize,
        old_size: usize,
        new_size: usize,
    ) -> AdjacentGrowth {
        let mut inspected = 0;
        let Some(adjacent) = start.checked_add(old_size) else {
            return AdjacentGrowth { grown: false, inspected };
        };
        let Some(need) = new_size.checked_sub(old_size) else {
            return AdjacentGrowth { grown: false, inspected };
        };
        let mut prev_link = self.head;
        let mut cur = unsafe { Self::read(self.head) };
        while cur != 0 {
            inspected += 1;
            if cur > adjacent {
                break;
            }
            let size = unsafe { Self::read(cur) };
            let next = unsafe { Self::read(cur + WORD) };
            if cur == adjacent && size >= need {
                if size - need >= NODE_SIZE {
                    let new_free = cur + need;
                    unsafe {
                        Self::write(new_free, size - need);
                        Self::write(new_free + WORD, next);
                        Self::write(prev_link, new_free);
                    }
                } else {
                    unsafe { Self::write(prev_link, next) };
                }
                return AdjacentGrowth { grown: true, inspected };
            }
            prev_link = cur + WORD;
            cur = next;
        }
        AdjacentGrowth { grown: false, inspected }
    }
}
