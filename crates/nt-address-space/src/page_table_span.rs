//! The leaf page tables that back a virtual range.

use crate::PAGE_TABLE_SPAN;

/// Base of every `PAGE_TABLE_SPAN`-aligned leaf page table that covers any byte of
/// `[base, base + size)`. An empty or overflowing range is covered by none.
pub fn covering_page_tables(base: u64, size: u64) -> impl Iterator<Item = u64> {
    let range = size
        .checked_sub(1)
        .and_then(|last| base.checked_add(last))
        .map(|last| (base & !(PAGE_TABLE_SPAN - 1), last & !(PAGE_TABLE_SPAN - 1)));
    let count = range.map_or(0, |(first, last)| (last - first) / PAGE_TABLE_SPAN + 1);
    let first = range.map_or(0, |(first, _)| first);
    (0..count).map(move |index| first + index * PAGE_TABLE_SPAN)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn an_image_larger_than_one_span_needs_every_table_it_touches() {
        // The source-built ntdll at 0x100_0080_0000 with SizeOfImage 0x226000: its .data
        // pages from RVA 0x200000 on lie in the second leaf table.
        let tables: Vec<u64> = covering_page_tables(0x100_0080_0000, 0x22_6000).collect();
        assert_eq!(tables, vec![0x100_0080_0000, 0x100_00a0_0000]);
        assert!(tables.contains(&(0x100_00a0_b000 & !(PAGE_TABLE_SPAN - 1))));
    }

    #[test]
    fn boundaries_empty_and_overflowing_ranges() {
        assert_eq!(covering_page_tables(0x20_0000, 0x20_0000).collect::<Vec<_>>(), vec![0x20_0000]);
        assert_eq!(
            covering_page_tables(0x3f_f000, 0x2000).collect::<Vec<_>>(),
            vec![0x20_0000, 0x40_0000]
        );
        assert_eq!(covering_page_tables(0x1000, 0).count(), 0);
        assert_eq!(covering_page_tables(u64::MAX - 0xfff, 0x2000).count(), 0);
    }
}
