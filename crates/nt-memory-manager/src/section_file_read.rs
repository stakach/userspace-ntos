//! Canonical resident reads with explicit-offset backing I/O for the gaps only.
use super::*;

const STATUS_END_OF_FILE: u32 = 0xc000_0011;

/// Synchronous and nonreentrant, like SectionFileWriteIo. The native owner retains the FILE_OBJECT
/// and owns logical position, access metadata, user copyout, IOSB, and completion. Raw fragments
/// must not advance the position or substitute for whole-operation read accounting.
pub trait SectionFileReadIo {
    fn begin(&mut self) -> Result<(), u32>;
    /// Prepare a read-only canonical mapping, excluding private COW frames.
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32>;
    /// Report exactly the initialized prefix, including on failure, leaving output[count..]
    /// unchanged. Never pend, advance logical file position, or recurse into cache policy.
    fn read_backing(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize);
    /// Infallible copy from an already-prepared canonical mapping.
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, output: &mut [u8]);
    /// Release preparation resources, retaining failed cleanup for begin to retry next time.
    fn finish(&mut self) -> Result<(), u32>;
}

impl GenericSectionTable {
    /// Read into kernel-owned output, not a faultable user buffer. Exclusive metadata ownership
    /// freezes residency through completion; it does not promise an atomic snapshot of CPU writes.
    pub fn read_file_coherent(
        &mut self,
        backing: GenericSectionBacking,
        offset: u64,
        output: &mut [u8],
        io: &mut impl SectionFileReadIo,
    ) -> (u32, usize) {
        let area = match self.file_io_area(backing) {
            Ok(area) => area,
            Err(status) => return (status, 0),
        };
        let Some(request_end) = offset.checked_add(output.len() as u64) else {
            return (STATUS_INVALID_PARAMETER, 0);
        };
        if output.is_empty() {
            return (0, 0);
        }
        if offset >= backing.file_extent {
            return (STATUS_END_OF_FILE, 0);
        }
        let end = request_end.min(backing.file_extent);
        let pages = match self.resident_file_pages(area, offset, end) {
            Ok(pages) => pages,
            Err(status) => return (status, 0),
        };
        if let Err(status) = io.begin() {
            return (status, 0);
        }
        for page in &pages {
            if let Err(status) = io.prepare_page(page.page) {
                let _ = io.finish(); // Failed cleanup stays adapter-owned; retain the original error.
                return (status, 0);
            }
        }
        let mut pages = pages.iter().peekable();
        let mut cursor = offset;
        let mut status = 0;
        while cursor < end {
            let completed = (cursor - offset) as usize;
            if let Some(page) = pages.peek().filter(|page| page.page.file_offset <= cursor) {
                let length = (end.min(page.page.file_offset + PAGE_SIZE) - cursor) as usize;
                io.copy_resident(
                    page.page,
                    (cursor - page.page.file_offset) as usize,
                    &mut output[completed..completed + length],
                );
                cursor += length as u64;
                pages.next();
            } else {
                let gap_end = pages
                    .peek()
                    .map_or(end, |page| page.page.file_offset.min(end));
                let length = (gap_end - cursor) as usize;
                let (read_status, read) =
                    io.read_backing(cursor, &mut output[completed..completed + length]);
                assert!(
                    read <= length,
                    "backing read violated exact-prefix contract"
                );
                cursor += read as u64;
                status = read_status;
                if status != 0 || read != length {
                    break;
                }
            }
        }
        if let Err(error) = io.finish() {
            if status == 0 {
                status = error;
            }
        }
        (status, (cursor - offset) as usize)
    }
}

#[cfg(test)]
#[path = "section_file_read_tests.rs"]
mod tests;
