//! EOF mutation while holding canonical data ownership. Image-section admission belongs to the
//! caller's file mutation boundary; this module owns only data sections.
use super::*;

/// Uses the same prepared, infallible page writes as ordinary coherent I/O.
pub trait SectionFileResizeIo: SectionFileWriteIo {
    /// Synchronous all-or-nothing backing EOF update. Success means exactly `new_eof`; failure
    /// leaves EOF and bytes unchanged. Extension supplies zero bytes and never reenters MM.
    fn resize_backing(&mut self, new_eof: u64) -> u32;
}

impl GenericSectionTable {
    /// The caller retains the backing FILE_OBJECT and has checked image-section write ownership.
    /// Accepted EOF changes remain published even if subsequent alias cleanup fails.
    pub fn resize_file_coherent(
        &mut self,
        backing: GenericSectionBacking,
        new_eof: u64,
        io: &mut impl SectionFileResizeIo,
    ) -> u32 {
        let prepared = self.prepare_file_resize(backing, new_eof);
        let (area_index, pages, aliases) = match prepared {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        let first_epoch = self.dirty_epoch;
        let Some(last_epoch) = first_epoch.checked_add(pages.len() as u64) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        if let Err(status) = io.begin() {
            return status;
        }
        self.dirty_epoch = last_epoch;
        let admission = (|| {
            for alias in aliases {
                io.rearm_alias(alias)?;
            }
            for page in &pages {
                io.prepare_page(page.page)?;
            }
            Ok(())
        })();
        if let Err(status) = admission {
            let _ = io.finish(); // The owner retains failed cleanup; preserve admission failure.
            return status;
        }
        let mut status = io.resize_backing(new_eof);
        if status == 0 {
            for (ordinal, page) in pages.iter().enumerate() {
                let start = page.page.file_offset;
                let limit = start + PAGE_SIZE;
                let zero_start = start.max(new_eof.min(backing.file_extent));
                let zero_end = if new_eof < backing.file_extent {
                    limit // Truncated tail must not reappear through mapped padding or regrowth.
                } else {
                    limit.min(new_eof)
                };
                if zero_start < zero_end {
                    io.zero_resident(
                        page.page,
                        (zero_start - start) as usize,
                        (zero_end - zero_start) as usize,
                    );
                    let resident = &mut self.pages[page.index];
                    resident.dirty = true;
                    resident.dirty_epoch = first_epoch + ordinal as u64 + 1;
                }
            }
            if let Some(index) = area_index {
                self.control_areas[index].extent = new_eof;
            }
        }
        if let Err(cleanup) = io.finish() {
            if status == 0 {
                status = cleanup;
            }
        }
        status
    }

    fn prepare_file_resize(
        &self,
        backing: GenericSectionBacking,
        new_eof: u64,
    ) -> Result<(Option<usize>, Vec<ResidentFilePage>, Vec<SectionPageAlias>), u32> {
        if new_eof > i64::MAX as u64 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if new_eof > crate::data_section::MAX_DATA_SECTION_SIZE {
            return Err(crate::STATUS_SECTION_TOO_BIG);
        }
        let area_index = self.file_io_area(backing)?;
        if let Some(index) = area_index {
            if new_eof < self.control_areas[index].segment_extent {
                return Err(STATUS_USER_MAPPED_FILE);
            }
        }
        if self.control_areas.iter().enumerate().any(|(index, area)| {
            Some(index) != area_index
                && area.id != 0
                && area.file == backing.file
                && area.kind == backing.kind
        }) {
            // A retiring area still owns frames or backing references. Its checked cleanup must
            // finish before truncation can discard bytes or race a retained writeback, even if
            // a newly created section already owns a newer area for this same file.
            return Err(STATUS_USER_MAPPED_FILE);
        }
        let pages = self.resident_file_pages(
            area_index,
            backing.file_extent.min(new_eof),
            backing.file_extent.max(new_eof),
        )?;
        let mut aliases = Vec::new();
        if let Some(index) = area_index {
            let area = self.control_areas[index];
            for page in &pages {
                if new_eof < backing.file_extent && page.page.file_offset >= new_eof {
                    // Valid user-data residency fits the retained segment. Whole pages beyond
                    // the new EOF require retirement, never silent removal of owned frames.
                    return Err(STATUS_USER_MAPPED_FILE);
                }
                let page_aliases = self.aliases_for_area_page(area.id, page.page.file_offset)?;
                aliases
                    .try_reserve(page_aliases.len())
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                aliases.extend(page_aliases);
            }
        }
        Ok((area_index, pages, aliases))
    }
}
