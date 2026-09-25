//! Admission policy for immutable, import-free PE support code in a hosted component.

use crate::{headers, PeError, PeFile};

const PAGE_SIZE: u64 = 0x1000;
const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImmutableSupportImageError {
    NotDll,
    EntryPoint,
    Imports(PeError),
    ImportDirectory,
    Tls,
    DelayImports,
    InvalidSection,
    SectionOverlap,
    NoExecutableSection,
}

fn directory_is_empty(pe: &PeFile<'_>, index: usize) -> bool {
    let directory = pe.headers().data_directory(index);
    directory.virtual_address == 0 && directory.size == 0
}

/// Admit only section-aligned, W^X code and read-only data. The caller must still map the
/// relocated bytes with RX for executable pages and RO_NX for every other page.
pub fn validate(pe: &PeFile<'_>) -> Result<(), ImmutableSupportImageError> {
    if !pe.headers().is_executable() || pe.headers().characteristics & IMAGE_FILE_DLL == 0 {
        return Err(ImmutableSupportImageError::NotDll);
    }
    if pe.entry_point_rva() != 0 {
        return Err(ImmutableSupportImageError::EntryPoint);
    }
    if !directory_is_empty(pe, headers::DIRECTORY_ENTRY_IMPORT)
        || !directory_is_empty(pe, headers::DIRECTORY_ENTRY_IAT)
    {
        return Err(ImmutableSupportImageError::ImportDirectory);
    }
    if !pe
        .imports()
        .map_err(ImmutableSupportImageError::Imports)?
        .is_empty()
    {
        return Err(ImmutableSupportImageError::ImportDirectory);
    }
    if !directory_is_empty(pe, headers::DIRECTORY_ENTRY_TLS) {
        return Err(ImmutableSupportImageError::Tls);
    }
    if !directory_is_empty(pe, headers::DIRECTORY_ENTRY_DELAY_IMPORT) {
        return Err(ImmutableSupportImageError::DelayImports);
    }

    let image_size = u64::from(pe.size_of_image());
    let headers_end = u64::from(pe.headers().size_of_headers)
        .checked_add(PAGE_SIZE - 1)
        .ok_or(ImmutableSupportImageError::InvalidSection)?
        & !(PAGE_SIZE - 1);
    if headers_end > image_size {
        return Err(ImmutableSupportImageError::InvalidSection);
    }
    let mut executable = false;
    for (index, section) in pe.sections().iter().enumerate() {
        let start = u64::from(section.virtual_address);
        let span = u64::from(section.virtual_size.max(section.size_of_raw_data));
        let end = start
            .checked_add(span)
            .and_then(|value| value.checked_add(PAGE_SIZE - 1))
            .map(|value| value & !(PAGE_SIZE - 1))
            .ok_or(ImmutableSupportImageError::InvalidSection)?;
        if span == 0
            || start < headers_end
            || start & (PAGE_SIZE - 1) != 0
            || end > image_size
            || !section.is_readable()
            || section.is_writable()
            || section.is_shared()
        {
            return Err(ImmutableSupportImageError::InvalidSection);
        }
        for prior in &pe.sections()[..index] {
            let prior_start = u64::from(prior.virtual_address);
            let prior_span = u64::from(prior.virtual_size.max(prior.size_of_raw_data));
            let prior_end = prior_start
                .checked_add(prior_span)
                .and_then(|value| value.checked_add(PAGE_SIZE - 1))
                .map(|value| value & !(PAGE_SIZE - 1))
                .ok_or(ImmutableSupportImageError::InvalidSection)?;
            if start < prior_end && prior_start < end {
                return Err(ImmutableSupportImageError::SectionOverlap);
            }
        }
        executable |= section.is_executable();
    }
    if !executable {
        return Err(ImmutableSupportImageError::NoExecutableSection);
    }
    Ok(())
}
