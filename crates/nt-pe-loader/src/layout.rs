//! Owned PE headers and section table, independent of raw image payload bytes.

use crate::{
    headers, image_page_fill, Headers, ImagePageFillPlan, ImageProtection, PeError, Section,
};

#[derive(Clone, Debug)]
pub struct PeLayout {
    pub(crate) headers: Headers,
    pub(crate) sections: [Section; headers::MAX_SECTIONS],
    pub(crate) section_count: usize,
}

impl PeLayout {
    pub fn parse(bytes: &[u8]) -> Result<Self, PeError> {
        let headers = Headers::parse(bytes)?;
        Self::from_headers(bytes, headers)
    }

    pub(crate) fn from_headers(bytes: &[u8], headers: Headers) -> Result<Self, PeError> {
        let table = headers.section_table_offset();
        Self::from_section_window(bytes, headers, table)
    }

    pub(crate) fn from_section_window(
        bytes: &[u8],
        headers: Headers,
        table: usize,
    ) -> Result<Self, PeError> {
        let section_count = headers.number_of_sections as usize;
        let mut sections = [Section::default(); headers::MAX_SECTIONS];
        for (i, section) in sections.iter_mut().enumerate().take(section_count) {
            *section = Section::parse(bytes, table + i * 40)?;
        }
        Ok(Self {
            headers,
            sections,
            section_count,
        })
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections[..self.section_count]
    }

    pub fn size_of_image(&self) -> u32 {
        self.headers.size_of_image
    }

    /// Resolve one contiguous RVA range to its raw File offset. This is the same
    /// section/header lookup used by `PeFile::bytes_at_rva`, with the File extent
    /// supplied independently of any resident image buffer.
    pub fn file_span_at_rva(&self, rva: u32, len: usize, file_size: u64) -> Option<u64> {
        let length = u32::try_from(len).ok()?;
        let end_rva = rva.checked_add(length)?;
        let offset = if rva < self.headers.size_of_headers
            && end_rva <= self.headers.size_of_headers
        {
            u64::from(rva)
        } else {
            let section = self.sections().iter().find(|section| {
                rva.checked_sub(section.virtual_address).is_some_and(|delta| {
                    delta <= section.size_of_raw_data
                        && length <= section.size_of_raw_data.saturating_sub(delta)
                })
            })?;
            u64::from(section.pointer_to_raw_data)
                .checked_add(u64::from(rva - section.virtual_address))?
        };
        offset
            .checked_add(len as u64)
            .filter(|end| *end <= file_size)
            .map(|_| offset)
    }

    /// NT SEC_IMAGE protection for a page, including private write-copy sections.
    pub fn image_protection_at(&self, rva: u32) -> ImageProtection {
        if rva < page_align_up(self.headers.size_of_headers) {
            return ImageProtection::ReadOnly;
        }
        for section in self.sections() {
            let start = section.virtual_address;
            let size = page_align_up(section.virtual_size.max(section.size_of_raw_data));
            if rva >= start && rva - start < size {
                if !section.is_shared() {
                    return if section.is_executable() {
                        ImageProtection::ExecuteWriteCopy
                    } else {
                        ImageProtection::WriteCopy
                    };
                }
                return match (
                    section.is_executable(),
                    section.is_readable(),
                    section.is_writable(),
                ) {
                    (true, _, true) => ImageProtection::ExecuteReadWrite,
                    (true, true, false) => ImageProtection::ExecuteRead,
                    (true, false, false) => ImageProtection::Execute,
                    (false, _, true) => ImageProtection::ReadWrite,
                    (false, true, false) => ImageProtection::ReadOnly,
                    (false, false, false) => ImageProtection::ReadOnly,
                };
            }
        }
        ImageProtection::ReadOnly
    }

    /// Plan raw File reads using its authenticated extent, not metadata buffer length.
    pub fn image_page_fill_plan(
        &self,
        page_rva: u32,
        file_size: u64,
    ) -> Result<ImagePageFillPlan, PeError> {
        image_page_fill::plan(self, page_rva, file_size)
    }
}

fn page_align_up(value: u32) -> u32 {
    value.saturating_add(0x0fff) & !0x0fff
}
