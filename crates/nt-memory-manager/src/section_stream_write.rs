//! Coherence of a file's resident section pages with writes its own filesystem completed.
//!
//! NT keeps one copy of a file's cached data: a cached write lands in the very section pages
//! every view maps (CcCopyWrite through the cache's views of the file's data section, NT5
//! cache/copysup.c), and a non-cached write flushes and purges that data first
//! (CcFlushCache/MmFlushSection, CcPurgeCacheSection). A routed filesystem here writes its volume
//! directly, so after it accepts a write the I/O Manager copies the accepted bytes into every
//! resident page of the same file data. The write wins for the bytes it wrote; a page that still
//! owes or owns a page write is dirtied again so the next page write carries the new bytes, never
//! an older copy over them.
use super::*;

const PAGE_SIZE: u64 = 0x1000;

/// One resident page's share of a completed write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamWritePage {
    pub frame: u64,
    /// Where in the page the written bytes go.
    pub page_offset: usize,
    /// Where in the written data they come from.
    pub data_offset: usize,
    pub length: usize,
    page_index: u64,
}

/// The resident pages a completed write must update, planned before any byte is copied.
#[derive(Debug, PartialEq, Eq)]
pub struct StreamWrite {
    control_area: u64,
    end: u64,
    pages: Vec<StreamWritePage>,
}

impl StreamWrite {
    pub fn pages(&self) -> &[StreamWritePage] {
        &self.pages
    }
}

impl GenericSectionTable {
    /// Plan the resident pages of `section`'s file data that `length` bytes the filesystem wrote
    /// at `offset` overlap. The plan mutates nothing; the caller copies each page's bytes and
    /// then commits.
    pub fn plan_stream_write(
        &self,
        section: SectionIdentity,
        offset: u64,
        length: u64,
    ) -> Result<StreamWrite, u32> {
        let index = self
            .sections
            .get(section.index)
            .filter(|candidate| {
                candidate.backing.is_live() && candidate.generation == section.generation
            })
            .ok_or(STATUS_NOT_MAPPED_VIEW)?;
        let area = index.control_area;
        let end = offset.checked_add(length).ok_or(0xc000_000du32)?;
        let mut pages = Vec::new();
        if length != 0 {
            let first = offset / PAGE_SIZE;
            let last = (end - 1) / PAGE_SIZE;
            for page in &self.pages {
                if !page.live || page.control_area != area || page.page_index < first
                    || page.page_index > last
                {
                    continue;
                }
                let start = page.page_index * PAGE_SIZE;
                let copy_start = start.max(offset);
                let copy_end = (start + PAGE_SIZE).min(end);
                pages.try_reserve(1).map_err(|_| 0xc000_009au32)?;
                pages.push(StreamWritePage {
                    frame: page.frame,
                    page_offset: (copy_start - start) as usize,
                    data_offset: (copy_start - offset) as usize,
                    length: (copy_end - copy_start) as usize,
                    page_index: page.page_index,
                });
            }
        }
        Ok(StreamWrite { control_area: area, end, pages })
    }

    /// Publish a write whose bytes were copied into every planned page: a page that owes or owns
    /// a page write gets a new dirty version, and the file data's extent covers the write.
    /// Returns false, changing nothing, when the plan no longer names the resident pages.
    pub fn commit_stream_write(&mut self, write: StreamWrite) -> bool {
        let Some(area_index) =
            self.control_areas.iter().position(|area| area.id == write.control_area)
        else {
            return false;
        };
        let resident = |table: &Self, planned: &StreamWritePage| {
            table.pages.iter().position(|page| {
                page.live
                    && page.control_area == write.control_area
                    && page.page_index == planned.page_index
                    && page.frame == planned.frame
            })
        };
        if write.pages.iter().any(|planned| resident(self, planned).is_none()) {
            return false;
        }
        let redirty = write
            .pages
            .iter()
            .filter(|planned| {
                let page = self.pages[resident(self, planned).unwrap()];
                page.dirty || page.writer != PageWriter::Idle
            })
            .count() as u64;
        let Some(last_epoch) = self.dirty_epoch.checked_add(redirty) else {
            return false;
        };
        for planned in &write.pages {
            let index = resident(self, planned).unwrap();
            let page = &mut self.pages[index];
            if page.dirty || page.writer != PageWriter::Idle {
                self.dirty_epoch += 1;
                page.dirty = true;
                page.dirty_epoch = self.dirty_epoch;
                page.write_failures = 0;
                page.write_parked = false;
            }
        }
        debug_assert_eq!(self.dirty_epoch, last_epoch);
        let area = &mut self.control_areas[area_index];
        if write.end > area.extent && write.end <= crate::data_section::MAX_DATA_SECTION_SIZE {
            area.extent = write.end;
        }
        true
    }
}

#[cfg(test)]
#[path = "section_stream_write_tests.rs"]
mod tests;
