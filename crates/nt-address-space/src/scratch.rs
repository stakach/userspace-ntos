//! Disjoint demand, persistent-alias, and temporary regions within one executive scratch window.

use crate::PAGE_SIZE;

#[derive(Clone, Copy)]
pub struct ScratchWindowLayout {
    window_bytes: u64,
    demand_pages: u64,
    temporary_pages: u64,
}

impl ScratchWindowLayout {
    pub const fn new(window_bytes: u64, demand_pages: u64, temporary_pages: u64) -> Option<Self> {
        if window_bytes == 0 || window_bytes % PAGE_SIZE != 0 {
            return None;
        }
        let pages = window_bytes / PAGE_SIZE;
        if demand_pages > pages || temporary_pages > pages - demand_pages {
            return None;
        }
        Some(Self {
            window_bytes,
            demand_pages,
            temporary_pages,
        })
    }

    pub const fn alias_capacity(self) -> u64 {
        self.window_bytes / PAGE_SIZE - self.demand_pages - self.temporary_pages
    }

    fn window_end(self, base: u64) -> Option<u64> {
        if base % PAGE_SIZE != 0 {
            return None;
        }
        base.checked_add(self.window_bytes)
    }

    /// Persistent aliases grow downward immediately below the reserved temporary region.
    pub fn alias_address(self, base: u64, index: u64) -> Option<u64> {
        if index >= self.alias_capacity() {
            return None;
        }
        self.window_end(base)?
            .checked_sub((self.temporary_pages + index + 1) * PAGE_SIZE)
    }

    /// Temporary slots are numbered from one at the top of the window.
    pub fn temporary_address(self, base: u64, from_top: u64) -> Option<u64> {
        if from_top == 0 || from_top > self.temporary_pages {
            return None;
        }
        self.window_end(base)?.checked_sub(from_top * PAGE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_window_keeps_every_persistent_alias_disjoint_from_demand_and_temporary_pages() {
        let layout = ScratchWindowLayout::new(0x400_0000, 15_000, 8).unwrap();
        let base = 0x1_0000_0000;
        assert_eq!(layout.alias_capacity(), 1376);
        assert_eq!(
            layout.alias_address(base, 0),
            Some(base + 0x400_0000 - 0x9000)
        );
        assert_eq!(
            layout.alias_address(base, 1375),
            Some(base + 15_000 * PAGE_SIZE)
        );
        assert_eq!(layout.alias_address(base, 1376), None);
        for index in 0..layout.alias_capacity() {
            let address = layout.alias_address(base, index).unwrap();
            assert!(address >= base + 15_000 * PAGE_SIZE);
            assert_eq!(address % PAGE_SIZE, 0);
            for slot in 1..=8 {
                assert_ne!(Some(address), layout.temporary_address(base, slot));
            }
        }
    }

    #[test]
    fn invalid_or_overcommitted_layouts_are_rejected() {
        for (size, demand, temporary) in [
            (0, 0, 0),
            (4097, 0, 0),
            (4096, 2, 0),
            (4096, 1, 1),
            (4096, u64::MAX, 1),
            (4096, 1, u64::MAX),
        ] {
            assert!(ScratchWindowLayout::new(size, demand, temporary).is_none());
        }
        let full = ScratchWindowLayout::new(8192, 1, 1).unwrap();
        assert_eq!(full.alias_capacity(), 0);
        assert_eq!(full.alias_address(0, 0), None);
        assert_eq!(full.temporary_address(0, 1), Some(4096));
    }

    #[test]
    fn malformed_bases_and_indices_cannot_escape_the_window() {
        let layout = ScratchWindowLayout::new(0x400_0000, 15_000, 8).unwrap();
        for base in [1, 4095, u64::MAX - 4095] {
            assert_eq!(layout.alias_address(base, 0), None);
            assert_eq!(layout.temporary_address(base, 1), None);
        }
        assert_eq!(layout.alias_address(0, u64::MAX), None);
        for slot in [0, 9, u64::MAX] {
            assert_eq!(layout.temporary_address(0, slot), None);
        }
    }

    #[test]
    fn neighbouring_windows_and_layout_changes_remain_disjoint() {
        for temporary in [8, 24, 64] {
            let layout = ScratchWindowLayout::new(0x400_0000, 15_000, temporary).unwrap();
            let lower = layout.alias_address(0x400_0000, 0).unwrap();
            let upper = layout
                .alias_address(0x800_0000, layout.alias_capacity() - 1)
                .unwrap();
            assert!(lower < 0x800_0000);
            assert!(upper >= 0x800_0000);
            assert!(
                layout.alias_address(0, 0).unwrap()
                    < layout.temporary_address(0, temporary).unwrap()
            );
        }
    }
}
