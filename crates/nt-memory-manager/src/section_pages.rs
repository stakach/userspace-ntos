//! Canonical page residency, shared dirty tickets, and alias planning.
use super::*;

impl GenericSectionTable {
    pub fn page_frame(&self, section_index: usize, page_index: u64) -> Option<u64> {
        let area = self.control_area(section_index)?.id;
        self.pages
            .iter()
            .find(|page| page.live && page.control_area == area && page.page_index == page_index)
            .map(|page| page.frame)
            .filter(|frame| *frame != 0)
    }

    pub fn set_page_frame(&mut self, section_index: usize, page_index: u64, frame: u64) -> bool {
        let Some(area) = self.control_area(section_index).map(|area| area.id) else {
            return false;
        };
        if frame == 0 {
            return false;
        }
        if let Some(page) = self
            .pages
            .iter()
            .find(|page| page.live && page.control_area == area && page.page_index == page_index)
        {
            return page.frame == frame;
        }
        let Some(epoch) = self.dirty_epoch.checked_add(1) else {
            return false;
        };
        self.dirty_epoch = epoch;
        let page = GenericSectionPage {
            live: true,
            control_area: area,
            page_index,
            frame,
            dirty: false,
            dirty_epoch: epoch,
        };
        if let Some(index) = self.pages.iter().position(|entry| !entry.live) {
            self.pages[index] = page;
            true
        } else {
            self.append_page(page)
        }
    }

    pub fn mark_page_dirty(&mut self, section_index: usize, page_index: u64) -> bool {
        let Some(area) = self.control_area(section_index).map(|area| area.id) else {
            return false;
        };
        let Some(epoch) = self.dirty_epoch.checked_add(1) else {
            return false;
        };
        self.dirty_epoch = epoch;
        if let Some(page) = self
            .pages
            .iter_mut()
            .find(|page| page.live && page.control_area == area && page.page_index == page_index)
        {
            page.dirty = true;
            page.dirty_epoch = epoch;
            true
        } else {
            false
        }
    }

    /// Retire only the shared version that was copied and checkpointed. Later marks and reused
    /// control-area/page slots cannot be cleaned by an earlier completion.
    pub fn complete_writeback_page(
        &mut self,
        ticket: crate::writeback::SectionWritebackPage,
    ) -> bool {
        if !self.control_area_live(ticket.control_area)
            || !self
                .control_areas
                .iter()
                .any(|area| area.id == ticket.control_area && area.extent == ticket.file_extent)
        {
            return false;
        }
        if let Some(page) = self.pages.iter_mut().find(|page| {
            page.live
                && page.dirty
                && page.control_area == ticket.control_area
                && page.page_index == ticket.page_index
                && page.frame == ticket.frame
                && page.dirty_epoch == ticket.dirty_epoch
        }) {
            page.dirty = false;
            true
        } else {
            false
        }
    }

    pub fn prepare_writeback(
        &self,
        plan: GenericSectionFlushPlan,
    ) -> Result<Vec<crate::writeback::SectionWritebackPage>, u32> {
        if self.section(plan.view.section_index) != Some(plan.section)
            || !self.views.contains(&plan.view)
        {
            return Err(STATUS_NOT_MAPPED_VIEW);
        }
        let displacement = plan
            .base
            .checked_sub(plan.view.base)
            .ok_or(STATUS_INVALID_PARAMETER_2)?;
        if plan.size == 0
            || displacement
                .checked_add(plan.size)
                .is_none_or(|end| end > plan.view.size)
            || plan.view.section_offset.checked_add(displacement) != Some(plan.section_offset)
        {
            return Err(STATUS_INVALID_PARAMETER_2);
        }
        let end = plan
            .section_offset
            .checked_add(plan.size)
            .ok_or(STATUS_INVALID_PARAMETER_2)?;
        let area = self
            .control_area(plan.view.section_index)
            .ok_or(STATUS_NOT_MAPPED_VIEW)?;
        self.prepare_area_writeback(area, plan.section_offset, end)
    }

    fn prepare_area_writeback(
        &self,
        area: ControlArea,
        start: u64,
        end: u64,
    ) -> Result<Vec<crate::writeback::SectionWritebackPage>, u32> {
        let mut pages = Vec::new();
        for page in &self.pages {
            if !page.live || !page.dirty || page.control_area != area.id {
                continue;
            }
            let offset = page
                .page_index
                .checked_mul(0x1000)
                .ok_or(STATUS_INVALID_PARAMETER_2)?;
            if offset < start || offset >= end {
                continue;
            }
            let length = area.extent.saturating_sub(offset).min(0x1000) as usize;
            if length != 0 {
                pages.try_reserve(1).map_err(|_| 0xC000_009Au32)?; // STATUS_INSUFFICIENT_RESOURCES
                pages.push(crate::writeback::SectionWritebackPage {
                    control_area: area.id,
                    file_extent: area.extent,
                    page_index: page.page_index,
                    frame: page.frame,
                    file_offset: offset,
                    length,
                    dirty_epoch: page.dirty_epoch,
                });
            }
        }
        pages.sort_unstable_by_key(|page| page.page_index);
        Ok(pages)
    }

    pub fn writeback(
        &mut self,
        plan: GenericSectionFlushPlan,
        io: &mut impl crate::writeback::SectionWritebackIo,
    ) -> crate::writeback::WritebackResult {
        let pages = match self.prepare_writeback(plan) {
            Ok(pages) => pages,
            Err(status) => return crate::writeback::WritebackResult::failure(status),
        };
        self.writeback_batch(pages, io)
    }

    /// Flush all resident dirty data for the mounted file, not just a particular section or view.
    /// The caller supplies the current EOF and retains the FILE_OBJECT used by the I/O adapter.
    pub fn writeback_file(
        &mut self,
        backing: GenericSectionBacking,
        io: &mut impl crate::writeback::SectionWritebackIo,
    ) -> crate::writeback::WritebackResult {
        if backing.file.is_none()
            || !matches!(
                backing.kind,
                GENERIC_SECTION_BACKING_DISK | GENERIC_SECTION_BACKING_OVERLAY
            )
        {
            return crate::writeback::WritebackResult::failure(0xc000_000d); // STATUS_INVALID_PARAMETER
        }
        let pages = if let Some(index) = self.matching_control_area(backing) {
            if let Err(status) = self.validate_backing_extent(backing) {
                return crate::writeback::WritebackResult::failure(status);
            }
            self.control_areas[index].extent = backing.file_extent;
            match self.prepare_area_writeback(self.control_areas[index], 0, backing.file_extent) {
                Ok(pages) => pages,
                Err(status) => return crate::writeback::WritebackResult::failure(status),
            }
        } else {
            Vec::new()
        };
        // Even an uncached or clean file can have dirty filesystem metadata to persist.
        self.writeback_batch(pages, io)
    }

    fn writeback_batch(
        &mut self,
        pages: Vec<crate::writeback::SectionWritebackPage>,
        io: &mut impl crate::writeback::SectionWritebackIo,
    ) -> crate::writeback::WritebackResult {
        // Rearm the entire batch before the first copy. Faults after this point must dirty-admit
        // through the memory owner; no writable alias may outlive successful ticket retirement.
        for page in &pages {
            let aliases = match self.writeback_aliases(*page) {
                Ok(aliases) => aliases,
                Err(status) => return crate::writeback::WritebackResult::failure(status),
            };
            for alias in aliases {
                if let Err(status) = io.rearm_alias(alias) {
                    return crate::writeback::WritebackResult::failure(status);
                }
            }
        }
        let result = crate::writeback::writeback_pages(&pages, io);
        if result.status == 0 {
            for page in pages {
                let _ = self.complete_writeback_page(page);
            }
        }
        result
    }

    pub fn writeback_aliases(
        &self,
        ticket: crate::writeback::SectionWritebackPage,
    ) -> Result<Vec<crate::writeback::SectionPageAlias>, u32> {
        if !self.control_area_live(ticket.control_area)
            || !self
                .control_areas
                .iter()
                .any(|area| area.id == ticket.control_area && area.extent == ticket.file_extent)
            || !self.pages.iter().any(|page| {
                page.live
                    && page.dirty
                    && page.control_area == ticket.control_area
                    && page.page_index == ticket.page_index
                    && page.frame == ticket.frame
                    && page.dirty_epoch == ticket.dirty_epoch
            })
            || ticket.page_index.checked_mul(0x1000) != Some(ticket.file_offset)
        {
            return Err(STATUS_NOT_MAPPED_VIEW);
        }
        let mut aliases = Vec::new();
        for view in &self.views {
            if !view.live
                || self
                    .section(view.section_index)
                    .is_none_or(|section| section.control_area != ticket.control_area)
            {
                continue;
            }
            if view.base & 0xfff != 0
                || view.section_offset & 0xfff != 0
                || view.base.checked_add(view.size).is_none()
                || view.section_offset.checked_add(view.size).is_none()
            {
                return Err(STATUS_INVALID_PARAMETER_2);
            }
            let Some(displacement) = ticket.file_offset.checked_sub(view.section_offset) else {
                continue;
            };
            if displacement >= view.size {
                continue;
            }
            let page = view
                .base
                .checked_add(displacement)
                .ok_or(STATUS_INVALID_PARAMETER_2)?;
            aliases.try_reserve(1).map_err(|_| 0xC000_009Au32)?;
            aliases.push(crate::writeback::SectionPageAlias { pi: view.pi, page });
        }
        Ok(aliases)
    }

    pub fn next_dirty_page_for_view(
        &self,
        view: GenericSectionView,
        section: GenericSection,
    ) -> Option<(u64, u64, u64, usize)> {
        self.next_dirty_page_in_range(view.section_index, section, view.section_offset, view.size)
    }

    pub fn next_dirty_page_for_flush(
        &self,
        plan: GenericSectionFlushPlan,
    ) -> Option<(u64, u64, u64, usize)> {
        self.next_dirty_page_in_range(
            plan.view.section_index,
            plan.section,
            plan.section_offset,
            plan.size,
        )
    }

    fn next_dirty_page_in_range(
        &self,
        section_index: usize,
        section: GenericSection,
        range_start: u64,
        range_size: u64,
    ) -> Option<(u64, u64, u64, usize)> {
        if self.section(section_index) != Some(section) {
            return None;
        }
        let area = self.control_area(section_index)?;
        let range_end = range_start.saturating_add(range_size);
        for page in &self.pages {
            if !page.live || !page.dirty || page.control_area != area.id {
                continue;
            }
            let page_offset = page.page_index.saturating_mul(0x1000);
            if page_offset < range_start || page_offset >= range_end {
                continue;
            }
            let len = area.extent.saturating_sub(page_offset).min(0x1000) as usize;
            if len != 0 {
                return Some((page.page_index, page.frame, page_offset, len));
            }
        }
        None
    }
}

#[cfg(test)]
#[path = "section_file_flush_tests.rs"]
mod file_flush_tests;
