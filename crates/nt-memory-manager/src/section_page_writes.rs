//! Asynchronous paging writes of shared dirty pages through the backing file's own driver.
//!
//! NT writes a mapped file's modified pages with paging IRPs: `MmFlushSection` and `MiCleanSection`
//! through `IoSynchronousPageWrite`, the mapped page writer through `IoAsynchronousPageWrite`
//! (NT5 flushsec.c, sectsup.c, modwrite.c). A routed section's driver may complete such a write
//! long after dispatch, so each write owns its page from dispatch to the exact terminal outcome:
//! the frame and the issuing section's FILE_OBJECT stay resident, the page is offered to no other
//! writer, and a write whose effect is unknown is never issued again.
use super::*;
use crate::writeback::{
    PageWriteOutcome, PageWriteRefusal, PageWriteState, SectionPageWrite, SectionWritebackPage,
};

/// A modified page awaiting the page writer, and the section whose FILE_OBJECT writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnmappedPageWrite {
    pub via: SectionIdentity,
    pub ticket: SectionWritebackPage,
    /// Every section of the file data is released: `MiCleanSection`, a synchronous page write.
    pub released: bool,
}

impl GenericSectionTable {
    /// The exact section incarnation, including one released by its last handle and view whose
    /// backing has not yet retired.
    fn retained_section(&self, identity: SectionIdentity) -> Option<GenericSection> {
        self.sections
            .get(identity.index)
            .copied()
            .filter(|section| section.backing.is_live() && section.generation == identity.generation)
    }

    fn ticket_page(&self, ticket: SectionWritebackPage) -> Option<usize> {
        if !self
            .control_areas
            .iter()
            .any(|area| area.id == ticket.control_area && area.extent == ticket.file_extent)
            || ticket.page_index.checked_mul(0x1000) != Some(ticket.file_offset)
        {
            return None;
        }
        self.pages.iter().position(|page| {
            page.live
                && page.control_area == ticket.control_area
                && page.page_index == ticket.page_index
                && page.frame == ticket.frame
        })
    }

    /// The writer owning `ticket`'s page, or `None` when the ticket's page is no longer resident.
    pub fn page_write_state(&self, ticket: SectionWritebackPage) -> Option<PageWriteState> {
        self.ticket_page(ticket).map(|index| match self.pages[index].writer {
            PageWriter::Idle => PageWriteState::Idle,
            PageWriter::InFlight { .. } => PageWriteState::InFlight,
            PageWriter::Uncertain { .. } => PageWriteState::Uncertain,
        })
    }

    /// Take exclusive ownership of the dirty version `ticket` names before copying the frame into
    /// a paging write. `via` is the routed section, of the same file data, whose retained
    /// FILE_OBJECT issues the IRP.
    pub fn begin_page_write(
        &mut self,
        via: SectionIdentity,
        ticket: SectionWritebackPage,
    ) -> Result<SectionPageWrite, PageWriteRefusal> {
        self.retained_section(via)
            .filter(|section| {
                section.backing.kind == GENERIC_SECTION_BACKING_ROUTED
                    && section.backing.routed_lease.is_some()
                    && section.control_area == ticket.control_area
            })
            .ok_or(PageWriteRefusal::Stale)?;
        let index = self.ticket_page(ticket).ok_or(PageWriteRefusal::Stale)?;
        let page = self.pages[index];
        match page.writer {
            PageWriter::InFlight { .. } => return Err(PageWriteRefusal::InFlight),
            PageWriter::Uncertain { .. } => return Err(PageWriteRefusal::Uncertain),
            PageWriter::Idle => {}
        }
        if !page.dirty || page.dirty_epoch != ticket.dirty_epoch {
            return Err(PageWriteRefusal::Stale);
        }
        let generation = self
            .page_write_generation
            .checked_add(1)
            .ok_or(PageWriteRefusal::Exhausted)?;
        self.page_write_generation = generation;
        self.pages[index].writer = PageWriter::InFlight { generation, via };
        Ok(SectionPageWrite { ticket, via, generation })
    }

    /// Settle a write exactly once. Success cleans only the version that was copied; a failure
    /// leaves the page dirty for a later writer; an uncertain effect quarantines the page.
    pub fn finish_page_write(&mut self, write: SectionPageWrite, outcome: PageWriteOutcome) -> bool {
        let Some(index) = self.ticket_page(write.ticket) else {
            return false;
        };
        if self.pages[index].writer
            != (PageWriter::InFlight { generation: write.generation, via: write.via })
        {
            return false;
        }
        let page = &mut self.pages[index];
        match outcome {
            PageWriteOutcome::Written => {
                page.writer = PageWriter::Idle;
                if page.dirty && page.dirty_epoch == write.ticket.dirty_epoch {
                    page.dirty = false;
                }
            }
            PageWriteOutcome::Failed(_) => page.writer = PageWriter::Idle,
            PageWriteOutcome::Uncertain => {
                page.writer = PageWriter::Uncertain {
                    generation: write.generation,
                    via: write.via,
                }
            }
        }
        true
    }

    /// Every dirty page of the file data `section` maps, for a whole-file flush or the mapped
    /// page writer after an unmap.
    pub fn prepare_section_writeback(
        &self,
        section: SectionIdentity,
    ) -> Result<Vec<SectionWritebackPage>, u32> {
        let section = self.retained_section(section).ok_or(STATUS_NOT_MAPPED_VIEW)?;
        let area = self
            .control_areas
            .iter()
            .copied()
            .find(|area| area.id == section.control_area)
            .ok_or(STATUS_NOT_MAPPED_VIEW)?;
        self.prepare_area_writeback(area, 0, area.extent)
    }

    /// The next dirty page no view maps any longer, with a section that still retains a
    /// FILE_OBJECT for its file data. Such a page is NT's modified-list page: the mapped page
    /// writer writes it after an unmap, and `MiCleanSection` once every section is released
    /// (`released`). A page still mapped is written by an explicit flush or after its last unmap.
    pub fn next_unmapped_page_write(&self) -> Option<UnmappedPageWrite> {
        for page in &self.pages {
            if !page.live || page.writer != PageWriter::Idle {
                continue;
            }
            let Some(area) =
                self.control_areas.iter().copied().find(|area| area.id == page.control_area)
            else {
                continue;
            };
            if area.kind != GENERIC_SECTION_BACKING_ROUTED
                || !Self::page_needs_write(area, page)
                || self.area_page_mapped(area.id, page.page_index)
            {
                continue;
            }
            // Prefer a section a handle still holds; a released one retains its FILE_OBJECT
            // until this write settles.
            let via = self
                .sections
                .iter()
                .enumerate()
                .filter(|(_, section)| {
                    section.backing.is_live()
                        && section.control_area == area.id
                        && section.backing.kind == GENERIC_SECTION_BACKING_ROUTED
                        && section.backing.routed_lease.is_some()
                })
                .max_by_key(|(_, section)| section.live)
                .map(|(index, section)| SectionIdentity { index, generation: section.generation });
            let Some(via) = via else {
                continue;
            };
            let file_offset = page.page_index * 0x1000;
            return Some(UnmappedPageWrite {
                via,
                released: !self.control_area_live(area.id),
                ticket: SectionWritebackPage {
                    control_area: area.id,
                    file_extent: area.extent,
                    page_index: page.page_index,
                    frame: page.frame,
                    file_offset,
                    length: area.extent.saturating_sub(file_offset).min(0x1000) as usize,
                    dirty_epoch: page.dirty_epoch,
                },
            });
        }
        None
    }

    fn area_page_mapped(&self, area: u64, page_index: u64) -> bool {
        let Some(offset) = page_index.checked_mul(0x1000) else {
            return true;
        };
        let covers = |section_index: usize, section_offset: u64, size: u64| {
            self.sections
                .get(section_index)
                .is_some_and(|section| section.control_area == area)
                && offset >= section_offset
                && section_offset.checked_add(size).is_none_or(|end| offset < end)
        };
        self.views
            .iter()
            .any(|view| view.live && covers(view.section_index, view.section_offset, view.size))
            || self
                .provider_views
                .iter()
                .any(|view| covers(view.section.index, view.section_offset, view.size))
    }

    /// Whether any routed page still owes, or is owned by, an asynchronous paging write. The
    /// page writer keeps scanning until this is false, as a mapped dirty page becomes writable
    /// work as soon as its last view is unmapped.
    pub fn has_async_dirty_pages(&self) -> bool {
        self.pages.iter().any(|page| {
            page.live
                && self.control_areas.iter().any(|area| {
                    area.id == page.control_area
                        && area.kind == GENERIC_SECTION_BACKING_ROUTED
                        && (matches!(page.writer, PageWriter::InFlight { .. })
                            || (page.writer == PageWriter::Idle && Self::page_needs_write(*area, page)))
                })
        })
    }

    /// Every routed section that still retains its FILE_OBJECT, including released sections
    /// whose file data has not yet retired, with that retained lease.
    pub fn retained_routed_sections(&self) -> Vec<(SectionIdentity, RoutedSectionLease)> {
        let mut sections = Vec::new();
        for (index, section) in self.sections.iter().enumerate() {
            if let (true, GENERIC_SECTION_BACKING_ROUTED, Some(lease)) =
                (section.backing.is_live(), section.backing.kind, section.backing.routed_lease)
            {
                if sections.try_reserve(1).is_err() {
                    break;
                }
                sections.push((SectionIdentity { index, generation: section.generation }, lease));
            }
        }
        sections
    }

    /// The FILE_OBJECT lease of the exact retained routed section incarnation.
    pub fn routed_lease_exact(&self, section: SectionIdentity) -> Option<RoutedSectionLease> {
        self.retained_section(section)
            .filter(|section| section.backing.kind == GENERIC_SECTION_BACKING_ROUTED)
            .and_then(|section| section.backing.routed_lease)
    }

    /// The current dirty-version counter. A flush writes the versions dirtied before it began.
    pub fn dirty_epoch(&self) -> u64 {
        self.dirty_epoch
    }

    /// Every view alias of a page whose write this caller owns, to write-protect before the
    /// frame is copied so a later store dirties a new version.
    pub fn page_write_aliases(
        &self,
        write: SectionPageWrite,
    ) -> Result<Vec<crate::writeback::SectionPageAlias>, u32> {
        let index = self.ticket_page(write.ticket).ok_or(STATUS_NOT_MAPPED_VIEW)?;
        if self.pages[index].writer
            != (PageWriter::InFlight { generation: write.generation, via: write.via })
        {
            return Err(STATUS_NOT_MAPPED_VIEW);
        }
        self.aliases_for_area_page(write.ticket.control_area, write.ticket.file_offset)
    }

    fn page_needs_write(area: ControlArea, page: &GenericSectionPage) -> bool {
        page.dirty
            && page
                .page_index
                .checked_mul(0x1000)
                .is_some_and(|offset| offset < area.extent)
    }

    /// Whether retirement must keep this section: a write it issues still owns its FILE_OBJECT,
    /// or its released file data still has asynchronously written pages to settle.
    pub(super) fn retirement_held(&self, section_index: usize) -> bool {
        let section = self.sections[section_index];
        let identity = SectionIdentity { index: section_index, generation: section.generation };
        if self.pages.iter().any(|page| {
            page.live
                && matches!(page.writer,
                    PageWriter::InFlight { via, .. } | PageWriter::Uncertain { via, .. }
                        if via == identity)
        }) {
            return true;
        }
        if self.control_area_live(section.control_area) {
            return false;
        }
        let Some(area) =
            self.control_areas.iter().copied().find(|area| area.id == section.control_area)
        else {
            return false;
        };
        self.pages.iter().any(|page| {
            page.live
                && page.control_area == area.id
                && (page.writer != PageWriter::Idle
                    || (area.kind == GENERIC_SECTION_BACKING_ROUTED
                        && Self::page_needs_write(area, page)))
        })
    }
}

#[cfg(test)]
#[path = "section_page_writes_tests.rs"]
mod tests;
