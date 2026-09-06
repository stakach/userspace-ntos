//! Serialized resident-file I/O with prepared canonical mappings and exact byte progress.
use super::*;
use crate::writeback::SectionPageAlias;

const PAGE_SIZE: u64 = 0x1000;
const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
const STATUS_USER_MAPPED_FILE: u32 = 0xc000_0243;

#[path = "section_file_read.rs"]
mod read;
pub use read::SectionFileReadIo;

#[path = "section_file_resize.rs"]
mod resize;
pub use resize::SectionFileResizeIo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionFilePage {
    pub frame: u64,
    pub file_offset: u64,
}

/// A synchronous, nonreentrant operation on a retained FILE_OBJECT. Preparation must not mutate
/// file/page bytes. Prepared canonical aliases remain usable until finish, independently of users'
/// mappings; private COW frames must never be prepared as canonical file data.
pub trait SectionFileWriteIo {
    /// Drain prior failed cleanup before new preparation or backing I/O, including uncached files.
    fn begin(&mut self) -> Result<(), u32>;
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32>;
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32>;
    /// One raw backing write, reporting the exact accepted prefix even on error. Never pend or
    /// recurse into section/cache policy; all effects must be complete before returning. An accepted
    /// prefix extends EOF to max(old EOF, offset + accepted) and zeroes any newly valid gap.
    fn write_backing(&mut self, offset: u64, data: &[u8]) -> (u32, usize);
    /// Infallible copies through already prepared aliases. No allocation, mapping, or callbacks.
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, data: &[u8]);
    fn zero_resident(&mut self, page: SectionFilePage, offset: usize, length: usize);
    /// Release all preparation resources, including after a failed preparation. Failed cleanup
    /// remains owned by the adapter for retry; it must not recycle a still-mapped capability.
    fn finish(&mut self) -> Result<(), u32>;
}

struct ResidentFilePage {
    index: usize,
    page: SectionFilePage,
}

impl GenericSectionTable {
    /// Write through the canonical data owner while exclusively borrowing its state. No detached
    /// plan can race page retirement or be replayed against a replacement control area.
    pub fn write_file_coherent(
        &mut self,
        backing: GenericSectionBacking,
        offset: u64,
        data: &[u8],
        io: &mut impl SectionFileWriteIo,
    ) -> (u32, usize) {
        let plan = self.prepare_file_write(backing, offset, data.len());
        let (area_index, pages, aliases) = match plan {
            Ok(plan) => plan,
            Err(status) => return (status, 0),
        };
        if data.is_empty() {
            return (0, 0);
        }
        let Some(last_epoch) = self.dirty_epoch.checked_add(pages.len() as u64) else {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        };
        let first_epoch = self.dirty_epoch;
        if let Err(status) = io.begin() {
            return (status, 0);
        }
        // Reserve version space before any backing mutation. Failed preflight may consume epochs,
        // but never changes the existing pages' versions, dirty state, bytes, or file extent.
        self.dirty_epoch = last_epoch;
        let prepared = (|| {
            for alias in aliases {
                io.rearm_alias(alias)?;
            }
            for page in &pages {
                io.prepare_page(page.page)?;
            }
            Ok(())
        })();
        if let Err(status) = prepared {
            let _ = io.finish(); // The adapter retains failed cleanup; preserve the preflight error.
            return (status, 0);
        }
        let (mut status, accepted) = io.write_backing(offset, data);
        // This is an internal adapter invariant, not a caller error. Unknown backend effects
        // cannot be reported as recoverable zero progress while canonical pages remain stale.
        assert!(
            accepted <= data.len(),
            "backing write violated exact-prefix contract"
        );
        if accepted != 0 {
            let end = offset + accepted as u64; // The full request was overflow-checked in preflight.
            for (ordinal, page) in pages.iter().enumerate() {
                let start = page.page.file_offset;
                let limit = start + PAGE_SIZE;
                let zero_start = backing.file_extent.max(start);
                let zero_end = offset.min(limit);
                let copy_start = offset.max(start);
                let copy_end = end.min(limit);
                let mut changed = false;
                if zero_start < zero_end {
                    io.zero_resident(
                        page.page,
                        (zero_start - start) as usize,
                        (zero_end - zero_start) as usize,
                    );
                    changed = true;
                }
                if copy_start < copy_end {
                    io.copy_resident(
                        page.page,
                        (copy_start - start) as usize,
                        &data[(copy_start - offset) as usize..(copy_end - offset) as usize],
                    );
                    changed = true;
                }
                if changed {
                    let resident = &mut self.pages[page.index];
                    resident.dirty = true;
                    resident.dirty_epoch = first_epoch + ordinal as u64 + 1;
                }
            }
            if let Some(index) = area_index {
                self.control_areas[index].extent = backing.file_extent.max(end);
            }
        }
        if let Err(error) = io.finish() {
            if status == 0 {
                status = error;
            }
        }
        (status, accepted)
    }

    fn prepare_file_write(
        &self,
        backing: GenericSectionBacking,
        offset: u64,
        length: usize,
    ) -> Result<(Option<usize>, Vec<ResidentFilePage>, Vec<SectionPageAlias>), u32> {
        let area_index = self.file_io_area(backing)?;
        let end = offset
            .checked_add(length as u64)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if end > crate::data_section::MAX_DATA_SECTION_SIZE {
            return Err(crate::STATUS_SECTION_TOO_BIG);
        }
        let start = if length == 0 {
            end
        } else {
            offset.min(backing.file_extent)
        };
        let pages = self.resident_file_pages(area_index, start, end)?;
        let mut aliases = Vec::new();
        if let Some(index) = area_index {
            let area = self.control_areas[index];
            for page in &pages {
                let page_aliases = self.aliases_for_area_page(area.id, page.page.file_offset)?;
                aliases
                    .try_reserve(page_aliases.len())
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                aliases.extend(page_aliases);
            }
        }
        Ok((area_index, pages, aliases))
    }

    fn file_io_area(&self, backing: GenericSectionBacking) -> Result<Option<usize>, u32> {
        if backing.file.is_none()
            || !matches!(
                backing.kind,
                GENERIC_SECTION_BACKING_DISK | GENERIC_SECTION_BACKING_OVERLAY
            )
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if backing.file_extent > crate::data_section::MAX_DATA_SECTION_SIZE {
            return Err(crate::STATUS_SECTION_TOO_BIG);
        }
        let area_index = self.matching_control_area(backing);
        if let Some(index) = area_index {
            let area = self.control_areas[index];
            // Out-of-band mutation must not be disguised as coherent I/O. Activation requires
            // every ordinary/internal mutation to participate in this same ownership protocol.
            if area.extent != backing.file_extent {
                return Err(STATUS_USER_MAPPED_FILE);
            }
        }
        Ok(area_index)
    }

    fn resident_file_pages(
        &self,
        area_index: Option<usize>,
        start: u64,
        end: u64,
    ) -> Result<Vec<ResidentFilePage>, u32> {
        let mut pages = Vec::new();
        let Some(area) = area_index.map(|index| self.control_areas[index]) else {
            return Ok(pages);
        };
        if start >= end {
            return Ok(pages);
        }
        for (index, page) in self.pages.iter().enumerate() {
            if !page.live || page.control_area != area.id {
                continue;
            }
            let file_offset = page
                .page_index
                .checked_mul(PAGE_SIZE)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            let page_end = file_offset
                .checked_add(PAGE_SIZE)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if file_offset >= end || page_end <= start {
                continue;
            }
            pages
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            pages.push(ResidentFilePage {
                index,
                page: SectionFilePage {
                    frame: page.frame,
                    file_offset,
                },
            });
        }
        pages.sort_unstable_by_key(|page| page.page.file_offset);
        Ok(pages)
    }
}

#[cfg(test)]
#[path = "section_file_io_tests.rs"]
mod tests;
