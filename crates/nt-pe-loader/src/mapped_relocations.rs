//! Checked relocation planning for a captured mapped-image directory.

use alloc::vec::Vec;

use crate::headers::DIRECTORY_ENTRY_BASERELOC;
use crate::relocs::parse_relocation_directory;
use crate::{Headers, PeError, Relocation};

/// Value-only plan; the native loader separately owns and authenticates its mapped view.
pub struct MappedRelocationPlan {
    mapped_base: u64,
    image_size: u32,
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
        delta,
        fixups,
    })
}
