//! Resolve a range against the bump-allocation chain of a hosted driver pool.
//!
//! This proves allocation boundaries, not liveness. A caller must separately reject allocations
//! on the pool free list while holding the lock that protects that list and the bump cursor.

/// One allocation reached by walking the pool's bump-allocation headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedPoolAllocation {
    /// Offset of the payload from the start of the pool.
    pub base: u64,
    /// Capacity recorded in the allocation's 16-byte header.
    pub capacity: u64,
}

/// A page-granular large allocation still belongs to the ordinary header chain. The preceding
/// padding is a real, free-list eligible allocation, so range walks never skip unknown bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedPoolBumpPlan {
    pub padding: Option<HostedPoolAllocation>,
    pub payload: u64,
    pub capacity: u64,
    pub used: u64,
}

/// Validate exact allocation bases in increasing address order against one locked pool snapshot.
/// The cursor re-reads the current header chain for each operation; it never trusts a cached
/// provider-writable boundary from an earlier lock acquisition.
pub struct HostedPoolChainCursor {
    used: u64,
    next_header: u64,
    last_base: u64,
    invalid: bool,
}

impl HostedPoolChainCursor {
    pub fn new(arena_bytes: u64, used: u64, data_offset: u64) -> Option<Self> {
        (data_offset <= used && used <= arena_bytes).then_some(Self {
            used,
            next_header: data_offset,
            last_base: 0,
            invalid: false,
        })
    }

    pub fn seek_exact_base(
        &mut self,
        target: u64,
        mut read_capacity: impl FnMut(u64) -> Option<u64>,
    ) -> Option<HostedPoolAllocation> {
        if self.invalid || target <= self.last_base || target >= self.used {
            self.invalid = true;
            return None;
        }
        while self.next_header < self.used {
            let Some(header) = self.next_header.checked_add(15).map(|at| at & !15) else {
                self.invalid = true;
                return None;
            };
            let Some(base) = header.checked_add(16) else {
                self.invalid = true;
                return None;
            };
            if base > self.used {
                self.invalid = true;
                return None;
            }
            let Some(capacity) = read_capacity(header) else {
                self.invalid = true;
                return None;
            };
            let Some(next) = base.checked_add(capacity) else {
                self.invalid = true;
                return None;
            };
            if capacity == 0 || next > self.used || target < base {
                self.invalid = true;
                return None;
            }
            self.next_header = next;
            if target == base {
                self.last_base = base;
                return Some(HostedPoolAllocation { base, capacity });
            }
            if target < next {
                self.invalid = true;
                return None;
            }
        }
        self.invalid = true;
        None
    }
}

/// One free node, with the preceding node needed to unlink it after validation finishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedPoolFreeNode {
    pub base: u64,
    pub next: u64,
    pub previous: Option<u64>,
}

/// Results from validating a sorted free list against the current allocation-header chain.
/// All addresses are offsets from the pool base; zero is the empty-list sentinel.
pub struct HostedPoolFreeListScan {
    pub first_fit: Option<HostedPoolFreeNode>,
    pub insertion_previous: Option<u64>,
    pub insertion_next: u64,
    pub target_is_free: bool,
    pub tail: Option<u64>,
    pub nodes: u64,
}

/// Scan the entire address-ordered free list before its caller changes any links. This combines
/// the header walk, optional exact target proof, insertion lookup, and first-fit search in one
/// monotonic pass. `read_capacity` and `read_next` must observe the same locked pool snapshot.
pub fn scan_hosted_pool_free_list(
    arena_bytes: u64,
    used: u64,
    data_offset: u64,
    head: u64,
    target: Option<u64>,
    max_nodes: u64,
    mut read_capacity: impl FnMut(u64) -> Option<u64>,
    mut read_next: impl FnMut(u64) -> Option<u64>,
    mut fits: impl FnMut(HostedPoolAllocation) -> bool,
) -> Option<HostedPoolFreeListScan> {
    let mut cursor = HostedPoolChainCursor::new(arena_bytes, used, data_offset)?;
    let mut current = head;
    let mut previous = None;
    let mut first_fit = None;
    let mut insertion = None;
    let mut target_is_free = false;
    let mut steps = 0;
    while current != 0 {
        if steps >= max_nodes || previous.is_some_and(|prior| current <= prior) {
            return None;
        }
        if let Some(target_base) = target {
            if insertion.is_none() && current >= target_base {
                insertion = Some((previous, current));
                if current > target_base {
                    cursor.seek_exact_base(target_base, &mut read_capacity)?;
                } else {
                    target_is_free = true;
                }
            }
        }
        let allocation = cursor.seek_exact_base(current, &mut read_capacity)?;
        let next = read_next(current)?;
        if first_fit.is_none() && fits(allocation) {
            first_fit = Some(HostedPoolFreeNode { base: current, next, previous });
        }
        previous = Some(current);
        current = next;
        steps += 1;
    }
    let (insertion_previous, insertion_next) = if let Some(target_base) = target {
        if let Some((prior, next)) = insertion {
            (prior, next)
        } else {
            cursor.seek_exact_base(target_base, &mut read_capacity)?;
            (previous, 0)
        }
    } else {
        (previous, 0)
    };
    Some(HostedPoolFreeListScan {
        first_fit,
        insertion_previous,
        insertion_next,
        target_is_free,
        tail: previous,
        nodes: steps,
    })
}

pub fn plan_hosted_pool_bump(
    cursor: u64,
    requested: u64,
    arena_bytes: u64,
    page_align_large: bool,
) -> Option<HostedPoolBumpPlan> {
    if requested == 0 || cursor >= arena_bytes {
        return None;
    }
    let header = cursor.checked_add(15)? & !15;
    let ordinary_payload = header.checked_add(16)?;
    let (padding, payload, capacity) = if page_align_large {
        let capacity = requested.checked_add(0xfff)? & !0xfff;
        if ordinary_payload & 0xfff == 0 {
            (None, ordinary_payload, capacity)
        } else {
            let payload = ordinary_payload.checked_add(16)?.checked_add(0xfff)? & !0xfff;
            let padding_capacity = payload.checked_sub(16)?.checked_sub(ordinary_payload)?;
            if padding_capacity == 0 { return None; }
            (
                Some(HostedPoolAllocation { base: ordinary_payload, capacity: padding_capacity }),
                payload,
                capacity,
            )
        }
    } else {
        (None, ordinary_payload, requested)
    };
    let used = payload.checked_add(capacity)?;
    if used > arena_bytes { return None; }
    Some(HostedPoolBumpPlan { padding, payload, capacity, used })
}

/// Locate the one bump allocation containing `[target_offset, target_offset + length)`.
///
/// `arena_bytes` is the immutable mapped extent. `used` is the provider-writable high-water
/// offset, and `data_offset` is its first possible header offset. Refuse an invalid high-water
/// offset before invoking the reader, even if the requested target appears to be in bounds.
/// The reader receives only aligned header offsets whose eight-byte capacity slot lies below
/// `used`. It must read from the same locked pool snapshot as those offsets. An arbitrary aligned
/// value inside a payload is never treated as a header.
pub fn walk_hosted_pool_allocation(
    arena_bytes: u64,
    used: u64,
    data_offset: u64,
    target_offset: u64,
    length: u64,
    mut read_capacity: impl FnMut(u64) -> Option<u64>,
) -> Option<HostedPoolAllocation> {
    if data_offset > used || used > arena_bytes {
        return None;
    }
    let target_end = target_offset.checked_add(length)?;
    if length == 0 || target_offset < data_offset || target_end > used {
        return None;
    }

    let mut cursor = data_offset;
    while cursor < used {
        let header = cursor.checked_add(15)? & !15;
        let payload = header.checked_add(16)?;
        if payload > used {
            return None;
        }
        let capacity = read_capacity(header)?;
        if capacity == 0 {
            return None;
        }
        let next = payload.checked_add(capacity)?;
        if next > used {
            return None;
        }
        if target_offset >= payload && target_end <= next {
            return Some(HostedPoolAllocation {
                base: payload,
                capacity,
            });
        }
        if target_offset < next {
            return None;
        }
        cursor = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_bump_keeps_header_chain_and_grants_only_complete_pages() {
        let plan = plan_hosted_pool_bump(0x1127, 0x300001, 0x800000, true).unwrap();
        assert_eq!(plan.payload & 0xfff, 0);
        assert_eq!(plan.capacity, 0x301000);
        let padding = plan.padding.unwrap();
        assert_eq!(padding.base + padding.capacity, plan.payload - 16);
        let headers = [
            ((padding.base - 16), padding.capacity),
            ((plan.payload - 16), plan.capacity),
        ];
        assert_eq!(
            walk_hosted_pool_allocation(0x800000, plan.used, 0x1127, plan.payload, 0x300001,
                |at| headers.iter().find(|(offset, _)| *offset == at).map(|(_, size)| *size)),
            Some(HostedPoolAllocation { base: plan.payload, capacity: plan.capacity })
        );
    }

    #[test]
    fn large_bump_rejects_arena_overrun_before_writing_padding() {
        assert!(plan_hosted_pool_bump(0x1127, 0x300001, 0x300000, true).is_none());
        assert!(plan_hosted_pool_bump(u64::MAX - 8, 0x10000, u64::MAX, true).is_none());
    }

    fn find(
        headers: &[(u64, u64)],
        used: u64,
        target: u64,
        length: u64,
    ) -> Option<HostedPoolAllocation> {
        walk_hosted_pool_allocation(0x2000, used, 0x1000, target, length, |at| {
            headers
                .iter()
                .find(|(offset, _)| *offset == at)
                .map(|(_, cap)| *cap)
        })
    }

    #[test]
    fn finds_allocation_start_and_interior() {
        let headers = [(0x1000, 24), (0x1030, 32)];
        let expected = Some(HostedPoolAllocation {
            base: 0x1010,
            capacity: 24,
        });
        assert_eq!(find(&headers, 0x1060, 0x1010, 24), expected);
        assert_eq!(find(&headers, 0x1060, 0x1017, 9), expected);
        assert_eq!(
            find(&headers, 0x1060, 0x1040, 32),
            Some(HostedPoolAllocation {
                base: 0x1040,
                capacity: 32
            })
        );
    }

    #[test]
    fn aligned_interior_value_cannot_impersonate_a_header() {
        // The aligned 0x1020 word lies inside the first allocation, not in the header chain.
        let headers = [(0x1000, 48), (0x1020, 0x1000), (0x1040, 16)];
        assert_eq!(
            find(&headers, 0x1060, 0x1030, 8),
            Some(HostedPoolAllocation {
                base: 0x1010,
                capacity: 48
            })
        );
        assert_eq!(
            find(&headers, 0x1060, 0x1050, 8),
            Some(HostedPoolAllocation {
                base: 0x1050,
                capacity: 16
            })
        );
    }

    #[test]
    fn rejects_cross_boundary_and_non_payload_ranges() {
        let headers = [(0x1000, 24), (0x1030, 32)];
        assert_eq!(find(&headers, 0x1060, 0x1020, 0x20), None);
        assert_eq!(find(&headers, 0x1060, 0x1030, 8), None); // second header
        assert_eq!(find(&headers, 0x1060, 0x1010, 0), None);
        assert_eq!(find(&headers, 0x1060, 0x1060, 1), None);
    }

    #[test]
    fn rejects_missing_zero_and_overrunning_headers() {
        assert_eq!(find(&[], 0x1020, 0x1010, 1), None);
        assert_eq!(find(&[(0x1000, 0)], 0x1020, 0x1010, 1), None);
        assert_eq!(find(&[(0x1000, 32)], 0x1020, 0x1010, 1), None);
        assert_eq!(find(&[(0x1000, 1)], 0x1010, 0x1010, 1), None);
    }

    #[test]
    fn rejects_arithmetic_overflow() {
        assert_eq!(find(&[(0x1000, 24)], 0x1028, u64::MAX, 2), None);
        assert_eq!(
            walk_hosted_pool_allocation(u64::MAX, u64::MAX, u64::MAX - 7, u64::MAX - 7, 1, |_| Some(1)),
            None
        );
        assert_eq!(
            walk_hosted_pool_allocation(u64::MAX, u64::MAX, u64::MAX - 31, u64::MAX - 15, 1, |_| Some(
                u64::MAX
            )),
            None
        );
    }

    #[test]
    fn rejects_provider_cursor_beyond_immutable_arena_before_reading() {
        let mut reads = 0;
        let found = walk_hosted_pool_allocation(
            0x2000,
            0x2020,
            0x1000,
            0x2010,
            1,
            |_| {
                reads += 1;
                Some(0x1000)
            },
        );
        assert_eq!(found, None);
        assert_eq!(reads, 0, "invalid provider cursor must not reach the reader");

        let in_arena = walk_hosted_pool_allocation(0x2000, 0x2020, 0x1000, 0x1010, 1, |_| {
            reads += 1;
            Some(0x10)
        });
        assert_eq!(in_arena, None, "an in-arena target cannot validate a corrupt cursor");
        assert_eq!(reads, 0);
    }

    #[test]
    fn ordered_pool_lookup_reads_each_header_once_and_rechecks_mutated_boundaries() {
        const COUNT: u64 = 400;
        let used = 0x1000 + COUNT * 32;
        let mut reads = 0;
        let mut cursor = HostedPoolChainCursor::new(0x8000, used, 0x1000).unwrap();
        for index in 0..COUNT {
            let target = 0x1010 + index * 32;
            assert_eq!(
                cursor.seek_exact_base(target, |header| {
                    reads += 1;
                    (header >= 0x1000 && header < used && header & 31 == 0).then_some(16)
                }),
                Some(HostedPoolAllocation { base: target, capacity: 16 })
            );
        }
        assert_eq!(reads, COUNT, "ordered free nodes must not restart the header walk");

        let mut changed = HostedPoolChainCursor::new(0x8000, used, 0x1000).unwrap();
        assert_eq!(
            changed.seek_exact_base(0x1030, |header| {
                (header == 0x1000).then_some(48).or_else(||
                    (header >= 0x1000 && header < used && header & 31 == 0).then_some(16))
            }),
            None,
            "an earlier capacity change must invalidate the old interior header"
        );
    }

    #[test]
    fn sorted_free_list_inserts_between_nodes_and_rejects_duplicate() {
        let mut links = [(0x1010, 0x1070), (0x1050, 0), (0x1070, 0)];
        let mut reads = 0;
        let mut scan = || {
            scan_hosted_pool_free_list(
                0x2000, 0x1080, 0x1000, 0x1010, Some(0x1050), 64,
                |header| {
                    reads += 1;
                    (header >= 0x1000 && header < 0x1080 && header & 31 == 0).then_some(16)
                },
                |base| links.iter().find(|(at, _)| *at == base).map(|(_, next)| *next),
                |_| false,
            ).unwrap()
        };
        let position = scan();
        assert_eq!(position.insertion_previous, Some(0x1010));
        assert_eq!(position.insertion_next, 0x1070);
        assert!(!position.target_is_free);
        drop(scan);
        assert_eq!(reads, 4, "the sorted list and target share one header walk");
        links[0].1 = 0x1050;
        links[1].1 = 0x1070;
        let duplicate = scan_hosted_pool_free_list(
            0x2000, 0x1080, 0x1000, 0x1010, Some(0x1050), 64,
            |header| (header >= 0x1000 && header < 0x1080 && header & 31 == 0).then_some(16),
            |base| links.iter().find(|(at, _)| *at == base).map(|(_, next)| *next),
            |_| false,
        ).unwrap();
        assert!(duplicate.target_is_free);
        assert_eq!(duplicate.nodes, 3);
    }

    #[test]
    fn first_fit_does_not_escape_a_corrupt_tail_or_forged_header() {
        let links = [(0x1010, 0x1070), (0x1070, 0x1070)];
        let result = scan_hosted_pool_free_list(
            0x2000, 0x1080, 0x1000, 0x1010, None, 64,
            |header| (header >= 0x1000 && header < 0x1080 && header & 31 == 0).then_some(16),
            |base| links.iter().find(|(at, _)| *at == base).map(|(_, next)| *next),
            |allocation| allocation.capacity >= 16,
        );
        assert!(result.is_none(), "a fitting head cannot authorize mutation before tail proof");
        assert_eq!(links[0].1, 0x1070);

        let forged = scan_hosted_pool_free_list(
            0x2000, 0x1080, 0x1000, 0x1030, None, 64,
            |header| match header { 0x1000 => Some(48), 0x1040 => Some(16), _ => None },
            |_| Some(0),
            |_| true,
        );
        assert!(forged.is_none(), "an aligned interior word cannot become a free-list node");
    }
}
