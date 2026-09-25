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

/// Locate the one bump allocation containing `[target_offset, target_offset + length)`.
///
/// `used` is the pool's high-water offset, and `data_offset` is its first possible header offset.
/// The reader receives only aligned header offsets whose eight-byte capacity slot lies below
/// `used`. It must read from the same locked pool snapshot as those offsets. An arbitrary aligned
/// value inside a payload is never treated as a header.
pub fn walk_hosted_pool_allocation(
    used: u64,
    data_offset: u64,
    target_offset: u64,
    length: u64,
    mut read_capacity: impl FnMut(u64) -> Option<u64>,
) -> Option<HostedPoolAllocation> {
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

    fn find(
        headers: &[(u64, u64)],
        used: u64,
        target: u64,
        length: u64,
    ) -> Option<HostedPoolAllocation> {
        walk_hosted_pool_allocation(used, 0x1000, target, length, |at| {
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
            walk_hosted_pool_allocation(u64::MAX, u64::MAX - 7, u64::MAX - 7, 1, |_| Some(1)),
            None
        );
        assert_eq!(
            walk_hosted_pool_allocation(u64::MAX, u64::MAX - 31, u64::MAX - 15, 1, |_| Some(
                u64::MAX
            )),
            None
        );
    }
}
