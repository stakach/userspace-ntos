//! A named address band and the checks a table of bands must pass.

/// `[base, base + len)` of one VSpace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub name: &'static str,
    pub base: u64,
    pub len: u64,
}

impl Region {
    /// A page-aligned, non-empty band that does not wrap.
    pub const fn new(name: &'static str, base: u64, len: u64) -> Self {
        assert!(len != 0);
        assert!(base & 0xfff == 0 && len & 0xfff == 0);
        assert!(base.checked_add(len).is_some());
        Self { name, base, len }
    }

    /// The band from `base` up to `end`.
    pub const fn spanning(name: &'static str, base: u64, end: u64) -> Self {
        assert!(end > base);
        Self::new(name, base, end - base)
    }

    pub const fn end(&self) -> u64 {
        self.base + self.len
    }

    pub const fn frames(&self) -> u64 {
        self.len / 0x1000
    }

    pub const fn overlaps(&self, other: &Region) -> bool {
        self.base < other.end() && other.base < self.end()
    }

    /// Whether `[base, base + len)` lies inside this band.
    pub const fn contains(&self, base: u64, len: u64) -> bool {
        match base.checked_add(len) {
            Some(end) => base >= self.base && end <= self.end(),
            None => false,
        }
    }
}

/// The first pair of bands that share an address, by index.
pub const fn first_overlap(regions: &[Region]) -> Option<(usize, usize)> {
    let mut first = 0;
    while first < regions.len() {
        let mut second = first + 1;
        while second < regions.len() {
            if regions[first].overlaps(&regions[second]) {
                return Some((first, second));
            }
            second += 1;
        }
        first += 1;
    }
    None
}

/// Whether each band ends at or before the next begins. An ascending table has no overlap.
pub const fn is_ascending(regions: &[Region]) -> bool {
    let mut index = 1;
    while index < regions.len() {
        if regions[index - 1].end() > regions[index].base {
            return false;
        }
        index += 1;
    }
    true
}
