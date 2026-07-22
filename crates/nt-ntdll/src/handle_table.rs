//! Pure arithmetic for the target-side `RTL_HANDLE_TABLE` implementation.
//!
//! The DLL wrapper owns the virtual-memory calls and raw table layout. Keeping bounds and index
//! calculations here makes the failure-prone part host-testable.

/// Size of an x64 `RTL_HANDLE_TABLE`.
pub const RTL_HANDLE_TABLE_SIZE: usize = 0x30;

/// Return the byte reservation required for a table, rejecting unusable and overflowing inputs.
pub fn reservation_size(max_handles: u32, entry_size: u32) -> Option<usize> {
    if max_handles == 0 || entry_size == 0 {
        return None;
    }
    (max_handles as usize).checked_mul(entry_size as usize)
}

/// Return the byte offset of `index`, provided it names an entry in the table.
pub fn entry_offset(index: u32, max_handles: u32, entry_size: u32) -> Option<usize> {
    if index >= max_handles || entry_size == 0 {
        return None;
    }
    (index as usize).checked_mul(entry_size as usize)
}

/// Convert an entry address back to an index, requiring an aligned address inside the reservation.
pub fn entry_index(base: usize, end: usize, entry: usize, entry_size: u32) -> Option<u32> {
    let entry_size = entry_size as usize;
    if entry_size == 0 || entry < base || entry >= end {
        return None;
    }
    let offset = entry.checked_sub(base)?;
    if offset % entry_size != 0 {
        return None;
    }
    u32::try_from(offset / entry_size).ok()
}

/// Resolve an index to an entry address inside a live table reservation.
pub fn indexed_entry_address(
    base: usize,
    end: usize,
    index: u32,
    max_handles: u32,
    entry_size: u32,
) -> Option<usize> {
    if base == 0 {
        return None;
    }
    let entry = base.checked_add(entry_offset(index, max_handles, entry_size)?)?;
    (entry < end).then_some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel32_global_handle_table_reservation_fits() {
        assert_eq!(reservation_size(0xffff, 0x10), Some(0x0f_fff0));
    }

    #[test]
    fn reservation_rejects_empty_tables() {
        assert_eq!(reservation_size(0, 0x10), None);
        assert_eq!(reservation_size(8, 0), None);
    }

    #[test]
    fn entry_offsets_are_bounded() {
        assert_eq!(entry_offset(0, 4, 0x10), Some(0));
        assert_eq!(entry_offset(3, 4, 0x10), Some(0x30));
        assert_eq!(entry_offset(4, 4, 0x10), None);
    }

    #[test]
    fn entry_indices_require_aligned_in_range_addresses() {
        assert_eq!(entry_index(0x1000, 0x1040, 0x1020, 0x10), Some(2));
        assert_eq!(entry_index(0x1000, 0x1040, 0x1021, 0x10), None);
        assert_eq!(entry_index(0x1000, 0x1040, 0x1040, 0x10), None);
        assert_eq!(entry_index(0x1000, 0x1040, 0x0ff0, 0x10), None);
    }

    #[test]
    fn indexed_addresses_are_checked_against_table_bounds() {
        assert_eq!(
            indexed_entry_address(0x1000, 0x1040, 2, 4, 0x10),
            Some(0x1020)
        );
        assert_eq!(indexed_entry_address(0x1000, 0x1040, 4, 4, 0x10), None);
        assert_eq!(indexed_entry_address(0x1000, 0x1020, 2, 4, 0x10), None);
        assert_eq!(indexed_entry_address(0, 0x1040, 0, 4, 0x10), None);
    }
}
