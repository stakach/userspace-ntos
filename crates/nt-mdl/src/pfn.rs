//! The PFN array that follows a driver-visible MDL header.
//!
//! `MmBuildMdlForNonPagedPool` and `MmProbeAndLockPages` write one PFN per page spanned by
//! `StartVa + ByteOffset .. + ByteCount` (ReactOS `mm/ARM3/mdlsup.c`). `IoBuildPartialMdl` copies
//! the source PFNs of the pages its subrange spans (`io/iomgr/iomdl.c`). The PFN array starts at
//! `MDL + sizeof(MDL)` and its capacity is fixed by the MDL's own `Size` field.

use crate::MDL_SIZE;

const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PfnError {
    /// The byte range is empty, overflows, or is not described by the MDL header.
    InvalidRange,
    /// `MDL.Size` cannot hold one PFN for every spanned page.
    Capacity,
    /// A spanned page has no owned physical frame; no PFN was written.
    Untranslated { page: u64 },
    /// A translation was not a page-aligned physical address; no PFN was written.
    Unaligned { page: u64 },
    /// A translation changed between validation and publication.
    Changed { page: u64 },
}

/// `ADDRESS_AND_SIZE_TO_SPAN_PAGES`.
pub fn span_pages(address: u64, length: u32) -> Option<u64> {
    if length == 0 {
        return None;
    }
    address.checked_add(u64::from(length) - 1)?;
    Some(((address & (PAGE - 1)) + u64::from(length)).div_ceil(PAGE))
}

/// PFN slots described by a declared `MDL.Size`.
pub fn pfn_capacity(mdl_size: i16) -> Option<u64> {
    let bytes = u64::try_from(mdl_size).ok()?.checked_sub(MDL_SIZE as u64)?;
    (bytes % 8 == 0).then_some(bytes / 8)
}

/// Translate every spanned page before writing any PFN. `translate` maps a page-aligned virtual
/// address to its physical address from an owned frame; `write` stores the PFN at an index.
pub fn populate(
    start_va: u64,
    byte_offset: u32,
    byte_count: u32,
    capacity: u64,
    translate: impl Fn(u64) -> Option<u64>,
    mut write: impl FnMut(u64, u64),
) -> Result<u64, PfnError> {
    if start_va & (PAGE - 1) != 0 || u64::from(byte_offset) >= PAGE {
        return Err(PfnError::InvalidRange);
    }
    let address = start_va
        .checked_add(u64::from(byte_offset))
        .ok_or(PfnError::InvalidRange)?;
    let pages = span_pages(address, byte_count).ok_or(PfnError::InvalidRange)?;
    if pages > capacity {
        return Err(PfnError::Capacity);
    }
    let page = |index: u64| start_va + index * PAGE;
    for index in 0..pages {
        let physical =
            translate(page(index)).ok_or(PfnError::Untranslated { page: page(index) })?;
        if physical & (PAGE - 1) != 0 {
            return Err(PfnError::Unaligned { page: page(index) });
        }
    }
    for index in 0..pages {
        let physical = translate(page(index)).ok_or(PfnError::Changed { page: page(index) })?;
        if physical & (PAGE - 1) != 0 {
            return Err(PfnError::Changed { page: page(index) });
        }
        write(index, physical / PAGE);
    }
    Ok(pages)
}

/// The source PFN index and count that a partial MDL over `target_address .. + target_length`
/// copies, as `IoBuildPartialMdl` computes them. The subrange must lie inside the source buffer.
pub fn partial_window(
    source_start_va: u64,
    source_byte_offset: u32,
    source_byte_count: u32,
    target_address: u64,
    target_length: u32,
) -> Result<(u64, u64), PfnError> {
    let source_address = source_start_va
        .checked_add(u64::from(source_byte_offset))
        .ok_or(PfnError::InvalidRange)?;
    let source_end = source_address
        .checked_add(u64::from(source_byte_count))
        .filter(|_| source_byte_count != 0)
        .ok_or(PfnError::InvalidRange)?;
    let target_end = target_address
        .checked_add(u64::from(target_length))
        .filter(|_| target_length != 0)
        .ok_or(PfnError::InvalidRange)?;
    if target_address < source_address || target_end > source_end {
        return Err(PfnError::InvalidRange);
    }
    let offset = ((target_address & !(PAGE - 1)) - source_start_va) / PAGE;
    let count = span_pages(target_address, target_length).ok_or(PfnError::InvalidRange)?;
    Ok((offset, count))
}

#[cfg(test)]
#[path = "pfn_tests.rs"]
mod tests;
