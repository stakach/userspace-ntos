//! Allocation-free address translation records for isolated kernel components.

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhysicalMapping {
    pub virtual_start: u64,
    pub physical_start: u64,
    pub length: u64,
}

/// Highest address accepted by NT's user-buffer probe helpers on this x64 target.
pub const MM_USER_PROBE_ADDRESS: u64 = 0x0000_7fff_ffff_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserProbeError {
    InvalidAlignment,
    DatatypeMisalignment,
    AccessViolation,
}

/// Validate the address, length, and alignment portion of `ProbeForRead`/`ProbeForWrite`.
/// A zero-length probe succeeds without inspecting either pointer or alignment, matching NT.
pub fn validate_user_probe(
    address: u64,
    length: u64,
    alignment: u64,
) -> Result<(), UserProbeError> {
    if length == 0 {
        return Ok(());
    }
    if !matches!(alignment, 1 | 2 | 4 | 8 | 16) {
        return Err(UserProbeError::InvalidAlignment);
    }
    if address & (alignment - 1) != 0 {
        return Err(UserProbeError::DatatypeMisalignment);
    }
    let last = address
        .checked_add(length - 1)
        .ok_or(UserProbeError::AccessViolation)?;
    if last >= MM_USER_PROBE_ADDRESS {
        return Err(UserProbeError::AccessViolation);
    }
    Ok(())
}

/// Append one mapped page, coalescing it with the preceding record only when both the virtual and
/// physical addresses are contiguous. Returns the new record count, or `None` when the fixed table
/// is full or the input is invalid.
pub fn append_physical_page(
    mappings: &mut [PhysicalMapping],
    count: usize,
    virtual_start: u64,
    physical_start: u64,
    page_size: u64,
) -> Option<usize> {
    if count > mappings.len()
        || page_size == 0
        || virtual_start & (page_size - 1) != 0
        || physical_start & (page_size - 1) != 0
        || !page_size.is_power_of_two()
    {
        return None;
    }
    if count != 0 {
        let previous = &mut mappings[count - 1];
        if previous.virtual_start.checked_add(previous.length) == Some(virtual_start)
            && previous.physical_start.checked_add(previous.length) == Some(physical_start)
        {
            previous.length = previous.length.checked_add(page_size)?;
            return Some(count);
        }
    }
    let record = mappings.get_mut(count)?;
    *record = PhysicalMapping {
        virtual_start,
        physical_start,
        length: page_size,
    };
    Some(count + 1)
}

/// Translate a byte address through a set of non-overlapping physical mapping records.
pub fn physical_address(mappings: &[PhysicalMapping], virtual_address: u64) -> Option<u64> {
    mappings.iter().find_map(|mapping| {
        let offset = virtual_address.checked_sub(mapping.virtual_start)?;
        (offset < mapping.length)
            .then(|| mapping.physical_start.checked_add(offset))
            .flatten()
    })
}

/// Resolve a physical byte range to an existing virtual mapping. The requested range must fit in a
/// single record; callers that need a new cross-record mapping must ask the memory manager to build
/// one instead of receiving a partial alias.
pub fn virtual_address(
    mappings: &[PhysicalMapping],
    physical_address: u64,
    length: u64,
) -> Option<u64> {
    if length == 0 {
        return None;
    }
    mappings.iter().find_map(|mapping| {
        let offset = physical_address.checked_sub(mapping.physical_start)?;
        let end = offset.checked_add(length)?;
        (end <= mapping.length)
            .then(|| mapping.virtual_start.checked_add(offset))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_pages_coalesce_and_translate_offsets() {
        let mut mappings = [PhysicalMapping::default(); 4];
        let count = append_physical_page(&mut mappings, 0, 0x1000, 0x9000, 0x1000).unwrap();
        let count = append_physical_page(&mut mappings, count, 0x2000, 0xa000, 0x1000).unwrap();
        assert_eq!(count, 1);
        assert_eq!(mappings[0].length, 0x2000);
        assert_eq!(physical_address(&mappings[..count], 0x2345), Some(0xa345));
        assert_eq!(physical_address(&mappings[..count], 0x3000), None);
        assert_eq!(
            virtual_address(&mappings[..count], 0x9345, 0x20),
            Some(0x1345)
        );
        assert_eq!(virtual_address(&mappings[..count], 0xaff0, 0x20), None);
        assert_eq!(virtual_address(&mappings[..count], 0x9000, 0), None);
    }

    #[test]
    fn physical_discontinuity_starts_a_new_extent() {
        let mut mappings = [PhysicalMapping::default(); 2];
        let count = append_physical_page(&mut mappings, 0, 0x4000, 0x10000, 0x1000).unwrap();
        let count = append_physical_page(&mut mappings, count, 0x5000, 0x14000, 0x1000).unwrap();
        assert_eq!(count, 2);
        assert_eq!(physical_address(&mappings[..count], 0x5008), Some(0x14008));
        assert_eq!(
            append_physical_page(&mut mappings, count, 0x6000, 0x15000, 0x1000),
            Some(2)
        );
        assert!(append_physical_page(&mut mappings, count, 0x7000, 0x18000, 0x1000).is_none());
    }

    #[test]
    fn invalid_page_geometry_is_rejected() {
        let mut mappings = [PhysicalMapping::default(); 1];
        assert!(append_physical_page(&mut mappings, 0, 0x1001, 0x2000, 0x1000).is_none());
        assert!(append_physical_page(&mut mappings, 0, 0x1000, 0x2000, 0x1800).is_none());
    }

    #[test]
    fn user_probe_matches_nt_range_and_alignment_rules() {
        assert_eq!(validate_user_probe(0, 0, 0), Ok(()));
        assert_eq!(validate_user_probe(0x1000, 8, 8), Ok(()));
        assert_eq!(
            validate_user_probe(0x1001, 8, 8),
            Err(UserProbeError::DatatypeMisalignment)
        );
        assert_eq!(
            validate_user_probe(0x1000, 8, 3),
            Err(UserProbeError::InvalidAlignment)
        );
        assert_eq!(
            validate_user_probe(MM_USER_PROBE_ADDRESS - 1, 2, 1),
            Err(UserProbeError::AccessViolation)
        );
        assert_eq!(
            validate_user_probe(u64::MAX - 3, 8, 1),
            Err(UserProbeError::AccessViolation)
        );
    }
}
