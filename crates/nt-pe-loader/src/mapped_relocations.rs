//! Checked relocation planning for a captured mapped-image directory.

use alloc::vec::Vec;

use crate::headers::DIRECTORY_ENTRY_BASERELOC;
use crate::relocs::parse_relocation_directory;
use crate::{Headers, PeError, Relocation, Section};

/// Value-only plan; the native loader separately owns and authenticates its mapped view.
pub struct MappedRelocationPlan {
    mapped_base: u64,
    image_size: u32,
    header_page_end: u64,
    delta: u64,
    fixups: Vec<Relocation>,
}

impl MappedRelocationPlan {
    pub fn mapped_base(&self) -> u64 {
        self.mapped_base
    }

    pub fn image_size(&self) -> u32 {
        self.image_size
    }

    pub fn delta(&self) -> u64 {
        self.delta
    }

    pub fn fixups(&self) -> &[Relocation] {
        &self.fixups
    }

    /// Admit targets only where NT5 already has writable pages or makes raw sections writable.
    /// This does not broaden header or readonly BSS permissions to accommodate fixups.
    pub fn validate_writable_targets(&self, sections: &[Section]) -> Result<(), PeError> {
        for section in sections {
            if section
                .virtual_address
                .checked_add(section.virtual_size.max(section.size_of_raw_data))
                .is_none_or(|end| end > self.image_size)
            {
                return Err(PeError::SectionOutOfBounds);
            }
        }
        for fixup in &self.fixups {
            let width = fixup.kind.width() as u64;
            if width == 0 {
                continue;
            }
            let mut cursor = u64::from(fixup.rva);
            let target_end = cursor + width;
            while cursor < target_end {
                let mut covered_end = cursor;
                for section in sections {
                    let length = if section.is_writable() {
                        section.virtual_size.max(section.size_of_raw_data)
                    } else {
                        section.size_of_raw_data
                    };
                    if length == 0 {
                        continue;
                    }
                    let (start, end) = if section.is_writable() {
                        // Canonical page faults classify at the page RVA. A partial first page
                        // precedes this section, and header pages always remain readonly.
                        let start = ((u64::from(section.virtual_address) + 0xfff) & !0xfff)
                            .max(self.header_page_end);
                        let mapped_length = (u64::from(length) + 0xfff) & !0xfff;
                        let end =
                            (u64::from(section.virtual_address) + mapped_length + 0xfff) & !0xfff;
                        (start, end)
                    } else {
                        // NtProtectVirtualMemory really rounds this raw section range down/up.
                        let start = u64::from(section.virtual_address) & !0xfff;
                        let end = (u64::from(section.virtual_address) + u64::from(length) + 0xfff)
                            & !0xfff;
                        (start, end)
                    };
                    if start <= cursor && cursor < end {
                        covered_end = covered_end.max(end);
                    }
                }
                if covered_end == cursor {
                    return Err(PeError::PatchOutOfBounds);
                }
                cursor = covered_end.min(target_end);
            }
        }
        Ok(())
    }
}

/// Validate the complete directory and all full-width target ranges before any writes.
/// Only headers and the captured directory are read, never image holes or target pages.
pub fn plan_mapped_relocations(
    headers: &Headers,
    captured_directory: &[u8],
    mapped_base: u64,
) -> Result<MappedRelocationPlan, PeError> {
    if headers.size_of_image == 0
        || headers.size_of_headers > headers.size_of_image
        || mapped_base
            .checked_add(u64::from(headers.size_of_image))
            .is_none()
    {
        return Err(PeError::BadImageSize);
    }
    let delta = mapped_base.wrapping_sub(headers.image_base);
    if delta != 0 && headers.characteristics & 1 != 0 {
        return Err(PeError::RelocationsStripped);
    }
    let directory = headers.data_directory(DIRECTORY_ENTRY_BASERELOC);
    let fixups = if directory.virtual_address == 0 || directory.size == 0 {
        if !captured_directory.is_empty() {
            return Err(PeError::RelocationInvalid);
        }
        Vec::new()
    } else {
        if captured_directory.len() != directory.size as usize
            || directory
                .virtual_address
                .checked_add(directory.size)
                .is_none_or(|end| end > headers.size_of_image)
        {
            return Err(PeError::RelocationInvalid);
        }
        let fixups = parse_relocation_directory(captured_directory)?;
        for fixup in &fixups {
            let width = fixup.kind.width() as u32;
            if width != 0
                && fixup
                    .rva
                    .checked_add(width)
                    .is_none_or(|end| end > headers.size_of_image)
            {
                return Err(PeError::PatchOutOfBounds);
            }
        }
        fixups
    };
    Ok(MappedRelocationPlan {
        mapped_base,
        image_size: headers.size_of_image,
        header_page_end: (u64::from(headers.size_of_headers) + 0xfff) & !0xfff,
        delta,
        fixups,
    })
}
