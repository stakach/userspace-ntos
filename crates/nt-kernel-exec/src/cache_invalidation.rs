//! Cache-line range selection for the native x86 coherent flush adapter.

/// Every aligned line that intersects one checked byte range.
pub struct CacheLines {
    next: Option<u64>,
    last: u64,
    step: u64,
}

impl Iterator for CacheLines {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next?;
        self.next = if current == self.last {
            None
        } else {
            current.checked_add(self.step)
        };
        Some(current)
    }
}

/// Reject invalid line geometry or an overflowing virtual address range.
pub fn cache_lines(base: u64, length: u32, line_size: u64) -> Option<CacheLines> {
    if !line_size.is_power_of_two() || !(8..=4096).contains(&line_size) {
        return None;
    }
    let end = base.checked_add(u64::from(length))?;
    let mask = !(line_size - 1);
    Some(CacheLines {
        next: (length != 0).then_some(base & mask),
        last: if length == 0 { 0 } else { (end - 1) & mask },
        step: line_size,
    })
}
