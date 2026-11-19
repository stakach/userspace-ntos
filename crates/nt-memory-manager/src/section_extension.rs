//! NtExtendSection: a data section over a file grows, never shrinks (NT5 mm/extsect.c
//! MmExtendSection; ReactOS mm/section.c). When the file is smaller than the new size, the file's
//! filesystem must first set its end of file (FsRtlSetFileSize), which only a section created
//! with page-write protection may ask for.
use super::*;

pub const STATUS_SECTION_NOT_EXTENDED: u32 = 0xc000_0087;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionExtension {
    /// The section already covers the size; NtExtendSection reports its current size.
    Unchanged(u64),
    /// The file data already covers the new size.
    Grow { new_size: u64, end_of_file: u64 },
    /// The file must first grow to `new_size` through its own filesystem.
    ExtendFile { new_size: u64 },
}

impl GenericSectionTable {
    fn extendable(&self, section: SectionIdentity) -> Result<(GenericSection, ControlArea), u32> {
        let candidate = self
            .sections
            .get(section.index)
            .copied()
            .filter(|candidate| candidate.live && candidate.generation == section.generation)
            .ok_or(STATUS_NOT_MAPPED_VIEW)?;
        // Image and page-file-backed sections are not extendable.
        if candidate.allocation_attributes & SECTION_ATTR_SEC_IMAGE != 0
            || candidate.backing.file.is_none()
        {
            return Err(STATUS_SECTION_NOT_EXTENDED);
        }
        let area = self
            .control_areas
            .iter()
            .copied()
            .find(|area| area.id == candidate.control_area)
            .ok_or(STATUS_NOT_MAPPED_VIEW)?;
        Ok((candidate, area))
    }

    /// Decide what extending `section` to `requested` bytes needs, without any effect.
    pub fn plan_section_extension(
        &self,
        section: SectionIdentity,
        requested: u64,
    ) -> Result<SectionExtension, u32> {
        let (candidate, area) = self.extendable(section)?;
        if requested > crate::data_section::MAX_DATA_SECTION_SIZE {
            return Err(crate::STATUS_SECTION_TOO_BIG);
        }
        if requested <= candidate.size {
            return Ok(SectionExtension::Unchanged(candidate.size));
        }
        if requested <= area.extent {
            return Ok(SectionExtension::Grow { new_size: requested, end_of_file: area.extent });
        }
        // Only a section created with write access may extend its file.
        if !matches!(candidate.protection & 0xff, crate::PAGE_READWRITE | 0x40) {
            return Err(STATUS_SECTION_NOT_EXTENDED);
        }
        Ok(SectionExtension::ExtendFile { new_size: requested })
    }

    /// Publish the larger section once the file covers it; returns the section's new size.
    pub fn commit_section_extension(
        &mut self,
        section: SectionIdentity,
        new_size: u64,
        end_of_file: u64,
    ) -> Result<u64, u32> {
        let (candidate, area) = self.extendable(section)?;
        if end_of_file < new_size || end_of_file > crate::data_section::MAX_DATA_SECTION_SIZE {
            return Err(crate::data_section::STATUS_IO_DEVICE_ERROR);
        }
        if end_of_file > area.extent {
            self.refresh_file_extent(section.index, end_of_file)?;
        }
        let entry = &mut self.sections[section.index];
        entry.size = entry.size.max(new_size);
        entry.backing.file_extent = entry.backing.file_extent.max(end_of_file);
        Ok(entry.size)
    }
}

#[cfg(test)]
#[path = "section_extension_tests.rs"]
mod tests;
