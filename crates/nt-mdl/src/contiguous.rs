//! Physical admission for a contiguous component allocation.

/// Validates actual frame addresses for one page-aligned physical run.
/// `high` is inclusive, as in NT's PHYSICAL_ADDRESS allocation limit.
pub fn validate_page_run(
    pages: &[u64], low: u64, high: u64, boundary: u64,
) -> Option<(u64, u64)> {
    let &first = pages.first()?;
    if first & 0xfff != 0 || low > high || first < low
        || (boundary != 0 && (!boundary.is_power_of_two() || boundary < 4096))
    { return None; }
    let mut expected = first;
    for &physical in pages {
        if physical & 0xfff != 0 || physical != expected { return None; }
        expected = expected.checked_add(4096)?;
    }
    let last = expected.checked_sub(1)?;
    if last > high || (boundary != 0 && first / boundary != last / boundary) {
        return None;
    }
    Some((first, last))
}
