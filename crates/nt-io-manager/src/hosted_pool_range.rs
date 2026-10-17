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
}
