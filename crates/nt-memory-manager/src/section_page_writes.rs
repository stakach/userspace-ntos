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

/// A retired routed section reduced to the FILE_OBJECT reference its file data's page writes
/// still need. NT keeps a page's PFN and the FILE_OBJECT its paging IRP references until the
/// write completes (MiWriteComplete, NT5 modwrite.c), not the section object: the section
/// retires while this owner settles its pages independently. A page whose write is uncertain
/// never settles, so its owner, frame and FILE_OBJECT are retained and never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetiredPageWriter {
    pub(crate) identity: SectionIdentity,
    pub(crate) control_area: u64,
    pub(crate) backing: GenericSectionBacking,
}

/// MmIsRetryIoStatus (NT5 mi.h): a transient shortage, retried rather than lost.
const fn retryable_write_status(status: u32) -> bool {
    matches!(status, 0xC000_009A | 0xC000_0017 | 0xC000_0058) // RESOURCES, NO_MEMORY, WS_QUOTA
}

/// MiCleanSection retries a retryable status until `ReflushCount & MiIoRetryMask` (0x1f) is
/// zero: 32 attempts (NT5 sectsup.c, miglobal.c).
const SECTION_DELETE_WRITE_ATTEMPTS: u8 = 32;

impl GenericSectionTable {
    /// The control area and FILE_OBJECT reference of the exact section incarnation that may issue
    /// a page write: a section whose backing has not retired (including one released by its last
    /// handle and view), or a retired section's page writer.
    fn writer_source(&self, identity: SectionIdentity) -> Option<(u64, GenericSectionBacking)> {
        self.sections
            .get(identity.index)
            .filter(|section| section.backing.is_live() && section.generation == identity.generation)
            .map(|section| (section.control_area, section.backing))
            .or_else(|| {
                self.retired_writers
                    .iter()
                    .find(|writer| writer.identity == identity)
                    .map(|writer| (writer.control_area, writer.backing))
            })
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
        self.writer_source(via)
            .filter(|(area, backing)| {
                backing.kind == GENERIC_SECTION_BACKING_ROUTED
                    && backing.routed_lease.is_some()
                    && *area == ticket.control_area
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

    /// Settle a write exactly once. Success cleans only the version that was copied; an uncertain
    /// effect quarantines the page. A failure leaves the page dirty for a later writer, except
    /// once every section of the file data is released: MiCleanSection reissues only a retryable
    /// status, a bounded number of times, and otherwise ignores the error and drops the page
    /// (NT5 sectsup.c), so a failing page cannot hold its file data forever.
    pub fn finish_page_write(&mut self, write: SectionPageWrite, outcome: PageWriteOutcome) -> bool {
        let Some(index) = self.ticket_page(write.ticket) else {
            return false;
        };
        if self.pages[index].writer
            != (PageWriter::InFlight { generation: write.generation, via: write.via })
        {
            return false;
        }
        let released = !self.control_area_live(write.ticket.control_area);
        let page = &mut self.pages[index];
        match outcome {
            PageWriteOutcome::Written => {
                page.writer = PageWriter::Idle;
                page.write_failures = 0;
                if page.dirty && page.dirty_epoch == write.ticket.dirty_epoch {
                    page.dirty = false;
                }
            }
            PageWriteOutcome::Failed(status) => {
                page.writer = PageWriter::Idle;
                if released && page.dirty_epoch == write.ticket.dirty_epoch {
                    page.write_failures = page.write_failures.saturating_add(1);
                    if !retryable_write_status(status)
                        || page.write_failures >= SECTION_DELETE_WRITE_ATTEMPTS
                    {
                        page.dirty = false; // The lost write is not retried.
                    }
                }
            }
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
        let (area, _) = self.writer_source(section).ok_or(STATUS_NOT_MAPPED_VIEW)?;
        let area = self
            .control_areas
            .iter()
            .copied()
            .find(|candidate| candidate.id == area)
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
            // Prefer a section a handle still holds; a released one, or a retired section's page
            // writer, retains its FILE_OBJECT until this write settles.
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
                .map(|(index, section)| SectionIdentity { index, generation: section.generation })
                .or_else(|| {
                    self.retired_writers
                        .iter()
                        .find(|writer| writer.control_area == area.id)
                        .map(|writer| writer.identity)
                });
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
        let candidates = self
            .sections
            .iter()
            .enumerate()
            .map(|(index, section)| (SectionIdentity { index, generation: section.generation }, section.backing))
            .chain(self.retired_writers.iter().map(|writer| (writer.identity, writer.backing)));
        for (identity, backing) in candidates {
            if let (true, GENERIC_SECTION_BACKING_ROUTED, Some(lease)) =
                (backing.is_live(), backing.kind, backing.routed_lease)
            {
                if sections.try_reserve(1).is_err() {
                    break;
                }
                sections.push((identity, lease));
            }
        }
        sections
    }

    /// The FILE_OBJECT lease of the exact retained routed section incarnation, or of the page
    /// writer it retired into.
    pub fn routed_lease_exact(&self, section: SectionIdentity) -> Option<RoutedSectionLease> {
        self.writer_source(section)
            .filter(|(_, backing)| backing.kind == GENERIC_SECTION_BACKING_ROUTED)
            .and_then(|(_, backing)| backing.routed_lease)
    }

    /// Mark every resident page a writable provider view of this file data maps as modified, and
    /// return how many: MiFlushDirtyBitsToPfn (NT5 flushsec.c) for views that are still mapped.
    /// A provider view's stores raise no write fault, so each page it can write is treated as
    /// written.
    pub fn harvest_provider_view_writes(&mut self, section: SectionIdentity) -> usize {
        let Some((area, _)) = self.writer_source(section) else {
            return 0;
        };
        let mut harvested = 0;
        for index in 0..self.provider_views.len() {
            let view = self.provider_views[index];
            if self.sections.get(view.section.index).is_some_and(|section| section.control_area == area) {
                harvested += self.harvest_provider_view(view);
            }
        }
        harvested
    }

    /// Mark the resident pages of one writable provider view of a routed section modified: on a
    /// flush, and when the view is removed (MiRemoveMappedView, NT5 mapview.c).
    pub(super) fn harvest_provider_view(&mut self, view: ProviderSectionView) -> usize {
        let Some(section) = self.section(view.section.index) else {
            return 0;
        };
        if section.backing.kind != GENERIC_SECTION_BACKING_ROUTED
            || !matches!(section.protection & 0xff, crate::PAGE_READWRITE | 0x40)
        {
            return 0;
        }
        let first = view.section_offset / 0x1000;
        let pages = view.size / 0x1000;
        (first..first.saturating_add(pages))
            .filter(|&page_index| {
                self.page_frame(view.section.index, page_index).is_some()
                    && self.mark_page_dirty(view.section.index, page_index)
            })
            .count()
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

    /// A write issued through this incarnation's FILE_OBJECT is still in flight.
    pub(super) fn write_in_flight_via(&self, identity: SectionIdentity) -> bool {
        self.pages.iter().any(|page| {
            page.live && matches!(page.writer, PageWriter::InFlight { via, .. } if via == identity)
        })
    }

    /// Whether this incarnation's FILE_OBJECT must outlive its section: a write through it is
    /// uncertain, or it is the last reference of released file data that still owes a write.
    pub(super) fn needs_retained_writer(&self, identity: SectionIdentity, area: u64) -> bool {
        if self.pages.iter().any(|page| {
            page.live && matches!(page.writer, PageWriter::Uncertain { via, .. } if via == identity)
        }) {
            return true;
        }
        if self.control_area_live(area) {
            return false;
        }
        let other_holder = self.sections.iter().enumerate().any(|(index, section)| {
            section.backing.is_live()
                && section.control_area == area
                && SectionIdentity { index, generation: section.generation } != identity
        }) || self
            .retired_writers
            .iter()
            .any(|writer| writer.control_area == area && writer.identity != identity);
        let Some(control) = self.control_areas.iter().copied().find(|candidate| candidate.id == area)
        else {
            return false;
        };
        !other_holder
            && control.kind == GENERIC_SECTION_BACKING_ROUTED
            && self.pages.iter().any(|page| {
                page.live
                    && page.control_area == area
                    && page.writer == PageWriter::Idle
                    && Self::page_needs_write(control, page)
            })
    }

    /// A resident page of released file data that no write owns or still owes.
    pub(super) fn page_releasable(&self, page: &GenericSectionPage) -> bool {
        page.live
            && page.writer == PageWriter::Idle
            && !self.control_areas.iter().any(|area| {
                area.id == page.control_area
                    && area.kind == GENERIC_SECTION_BACKING_ROUTED
                    && Self::page_needs_write(*area, page)
            })
    }

    /// Settle every retired page writer whose pages no longer need its FILE_OBJECT, releasing
    /// the released file data's settled frames first.
    pub(super) fn drain_retired_writers(
        &mut self,
        io: &mut impl SectionRetirementIo,
    ) -> Result<(), u32> {
        let mut index = 0;
        while index < self.retired_writers.len() {
            let writer = self.retired_writers[index];
            if self.write_in_flight_via(writer.identity) {
                index += 1;
                continue;
            }
            if !self.control_area_live(writer.control_area) {
                self.release_settled_frames(writer.control_area, io)?;
            }
            if self.needs_retained_writer(writer.identity, writer.control_area) {
                index += 1;
                continue;
            }
            io.release_backing(writer.identity, writer.backing)?;
            self.retired_writers.remove(index);
            self.retire_control_area_if_unreferenced(writer.control_area);
        }
        Ok(())
    }

    /// Release, in order, the frames of released file data that no write owns or owes.
    pub(super) fn release_settled_frames(
        &mut self,
        area: u64,
        io: &mut impl SectionRetirementIo,
    ) -> Result<(), u32> {
        for page_index in 0..self.pages.len() {
            let page = self.pages[page_index];
            if page.control_area == area && self.page_releasable(&page) {
                io.release_frame(page.frame)?;
                self.pages[page_index] = GenericSectionPage::empty();
            }
        }
        Ok(())
    }

    pub(super) fn retired_writer_references(&self, area: u64) -> bool {
        self.retired_writers.iter().any(|writer| writer.control_area == area)
    }
}

#[cfg(test)]
#[path = "section_page_writes_tests.rs"]
mod tests;
