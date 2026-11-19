use super::*;
use crate::writeback::{PageWriteOutcome, PageWriteRefusal, PageWriteState};
use alloc::vec;

const IO_ERROR: u32 = 0xC000_0185;

fn file_identity(file_id: u64) -> SectionFileIdentity {
    SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id,
    }
}

#[derive(Default)]
struct Release {
    frames: Vec<u64>,
    leases: Vec<RoutedSectionLease>,
}

impl SectionRetirementIo for Release {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        self.frames.push(frame);
        Ok(())
    }
    fn release_backing(&mut self, _: SectionIdentity, backing: GenericSectionBacking) -> Result<(), u32> {
        self.leases.push(backing.routed_lease.unwrap());
        Ok(())
    }
}

/// A writable routed section with one view and dirty resident pages 0 and 1 of a 0x1800-byte file.
fn routed_table(lease: u64) -> (GenericSectionTable, usize, SectionIdentity) {
    let mut table = GenericSectionTable::new();
    let backing =
        GenericSectionBacking::routed(RoutedSectionLease::new(lease).unwrap(), file_identity(9), 0x1800);
    let section = table
        .create(2, 0x40, 0x1800, crate::PAGE_READWRITE, SECTION_ATTR_SEC_COMMIT, backing)
        .unwrap();
    assert!(table.map_view(3, section, 0x10000, 0x2000, 0));
    assert!(table.set_page_frame(section, 0, 100));
    assert!(table.set_page_frame(section, 1, 101));
    assert!(table.mark_page_dirty(section, 0));
    assert!(table.mark_page_dirty(section, 1));
    let identity = table.section_identity(section).unwrap();
    (table, section, identity)
}

#[test]
fn routed_views_plan_flushes_of_their_dirty_pages() {
    let (table, _, _) = routed_table(11);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let tickets = table.prepare_writeback(plan).unwrap();
    assert_eq!(tickets.iter().map(|ticket| ticket.page_index).collect::<Vec<_>>(), vec![0, 1]);
    assert_eq!(tickets.iter().map(|ticket| ticket.length).collect::<Vec<_>>(), vec![0x1000, 0x800]);
    assert_eq!(tickets[0].file_offset, 0);
}

#[test]
fn an_acknowledged_write_cleans_only_the_version_it_copied() {
    let (mut table, section, identity) = routed_table(11);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let tickets = table.prepare_writeback(plan).unwrap();
    let first = table.begin_page_write(identity, tickets[0]).unwrap();
    assert_eq!(table.page_write_state(tickets[0]), Some(PageWriteState::InFlight));
    assert_eq!(table.begin_page_write(identity, tickets[0]), Err(PageWriteRefusal::InFlight));
    let second = table.begin_page_write(identity, tickets[1]).unwrap();
    // A user write after the copy re-dirties page 1 under a new epoch.
    assert!(table.mark_page_dirty(section, 1));
    assert!(table.finish_page_write(first, PageWriteOutcome::Written));
    assert!(table.finish_page_write(second, PageWriteOutcome::Written));
    assert!(!table.finish_page_write(second, PageWriteOutcome::Written), "one settlement per write");
    let remaining = table.prepare_writeback(plan).unwrap();
    assert_eq!(remaining.iter().map(|ticket| ticket.page_index).collect::<Vec<_>>(), vec![1]);
    assert_eq!(table.begin_page_write(identity, tickets[1]), Err(PageWriteRefusal::Stale),
        "the old version's ticket cannot write the new one");
    assert!(table.begin_page_write(identity, remaining[0]).is_ok());
}

#[test]
fn a_failed_write_keeps_the_page_dirty_and_writable_again() {
    let (mut table, _, identity) = routed_table(11);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    let write = table.begin_page_write(identity, ticket).unwrap();
    assert!(table.finish_page_write(write, PageWriteOutcome::Failed(IO_ERROR)));
    assert_eq!(table.page_write_state(ticket), Some(PageWriteState::Idle));
    assert_eq!(table.prepare_writeback(plan).unwrap()[0], ticket);
    let retry = table.begin_page_write(identity, ticket).unwrap();
    assert_ne!(retry, write, "a new write is a new ownership generation");
}

#[test]
fn an_uncertain_write_is_never_replayed_and_never_releases_its_frame_or_file() {
    let (mut table, section, identity) = routed_table(11);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let tickets = table.prepare_writeback(plan).unwrap();
    let write = table.begin_page_write(identity, tickets[0]).unwrap();
    assert!(table.finish_page_write(write, PageWriteOutcome::Uncertain));
    assert_eq!(table.page_write_state(tickets[0]), Some(PageWriteState::Uncertain));
    assert_eq!(table.begin_page_write(identity, tickets[0]), Err(PageWriteRefusal::Uncertain));
    assert!(table.mark_page_dirty(section, 0));
    let redirtied = table.prepare_writeback(plan).unwrap()[0];
    assert_eq!(table.begin_page_write(identity, redirtied), Err(PageWriteRefusal::Uncertain));
    // Page 1 still writes back cleanly; retirement then keeps the quarantined frame and file.
    let clean = table.begin_page_write(identity, tickets[1]).unwrap();
    assert!(table.finish_page_write(clean, PageWriteOutcome::Written));
    assert!(table.unmap_view(3, 0x10000).is_some());
    assert!(table.release_handle(section));
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    // The section retires; only the quarantined page keeps its frame and its write's FILE_OBJECT.
    assert_eq!(io.frames, vec![101]);
    assert!(io.leases.is_empty(), "the uncertain write's FILE_OBJECT stays referenced");
    assert!(!table.section(section).is_some_and(|section| section.backing.is_live()));
    assert_eq!(table.routed_lease_exact(identity), RoutedSectionLease::new(11));
    assert_eq!(table.page_write_state(tickets[0]), Some(PageWriteState::Uncertain));
    assert_eq!(table.next_unmapped_page_write(), None, "the quarantined page is not rewritten");
    table.drain_retired(&mut io).unwrap();
    assert_eq!((io.frames.len(), io.leases.len()), (1, 0), "never settled, never reused");
}

const RESOURCES: u32 = 0xC000_009A;

/// Section deletion with a dirty page (MiCleanSection, NT5 sectsup.c): the section itself
/// retires at once and its FILE_OBJECT stays with the page until the page's write settles.
fn released_dirty_page() -> (GenericSectionTable, usize, SectionIdentity) {
    let (mut table, section, identity) = routed_table(11);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let ticket = table.prepare_writeback(plan).unwrap()[1];
    let write = table.begin_page_write(identity, ticket).unwrap();
    assert!(table.finish_page_write(write, PageWriteOutcome::Written));
    assert!(table.unmap_view(3, 0x10000).is_some());
    assert!(table.release_handle(section));
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, vec![101], "the clean page is released with the section");
    assert!(io.leases.is_empty());
    assert!(!table.section(section).is_some_and(|section| section.backing.is_live()),
        "a page that still owes a write does not keep its section");
    (table, section, identity)
}

#[test]
fn a_retryable_failure_is_retried_by_the_page_owner_then_dropped() {
    let (mut table, _, identity) = released_dirty_page();
    // MmIsRetryIoStatus statuses are reissued until ReflushCount & MiIoRetryMask(0x1f) is 0.
    for attempt in 0..32 {
        let next = table.next_unmapped_page_write().unwrap_or_else(|| panic!("attempt {attempt}"));
        assert_eq!((next.via, next.ticket.page_index, next.released), (identity, 0, true));
        let write = table.begin_page_write(next.via, next.ticket).unwrap();
        assert!(table.finish_page_write(write, PageWriteOutcome::Failed(RESOURCES)));
        let mut io = Release::default();
        table.drain_retired(&mut io).unwrap();
        if attempt < 31 {
            assert!(io.frames.is_empty() && io.leases.is_empty(), "attempt {attempt}");
        } else {
            // "NOTE that the error status is ignored": the page is dropped and released.
            assert_eq!(io.frames, vec![100]);
            assert_eq!(io.leases, vec![RoutedSectionLease::new(11).unwrap()]);
        }
    }
    assert_eq!(table.next_unmapped_page_write(), None);
    assert_eq!(table.routed_lease_exact(identity), None);
}

#[test]
fn a_definite_failure_at_section_deletion_is_not_retried() {
    let (mut table, _, identity) = released_dirty_page();
    let next = table.next_unmapped_page_write().unwrap();
    let write = table.begin_page_write(next.via, next.ticket).unwrap();
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert!(io.frames.is_empty() && io.leases.is_empty(), "the in-flight write owns both");
    assert!(table.finish_page_write(write, PageWriteOutcome::Failed(IO_ERROR)));
    assert_eq!(table.next_unmapped_page_write(), None);
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, vec![100]);
    assert_eq!(io.leases, vec![RoutedSectionLease::new(11).unwrap()]);
    assert_eq!(table.routed_lease_exact(identity), None);
}

#[test]
fn an_uncertain_write_at_section_deletion_keeps_only_its_own_page() {
    let (mut table, _, identity) = released_dirty_page();
    let next = table.next_unmapped_page_write().unwrap();
    let write = table.begin_page_write(next.via, next.ticket).unwrap();
    assert!(table.finish_page_write(write, PageWriteOutcome::Uncertain));
    let mut io = Release::default();
    for _ in 0..2 {
        table.drain_retired(&mut io).unwrap();
        assert!(io.frames.is_empty() && io.leases.is_empty());
        assert_eq!(table.next_unmapped_page_write(), None, "never replayed");
    }
    assert_eq!(table.routed_lease_exact(identity), RoutedSectionLease::new(11));
}

#[test]
fn the_mapped_page_writer_keeps_a_failing_page_of_a_live_section_dirty() {
    let (mut table, section, identity) = routed_table(11);
    assert!(table.map_view(4, section, 0x20000, 0x1000, 0));
    assert!(table.unmap_view(3, 0x10000).is_some());
    for _ in 0..40 {
        let next = table.next_unmapped_page_write().unwrap();
        assert_eq!((next.via, next.ticket.page_index, next.released), (identity, 1, false));
        let write = table.begin_page_write(next.via, next.ticket).unwrap();
        assert!(table.finish_page_write(write, PageWriteOutcome::Failed(IO_ERROR)));
    }
}

#[test]
fn retirement_waits_for_dirty_and_in_flight_routed_pages_then_releases_in_order() {
    let (mut table, section, identity) = routed_table(11);
    assert!(table.unmap_view(3, 0x10000).is_some());
    assert!(table.release_handle(section));
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert!(io.frames.is_empty() && io.leases.is_empty(), "dirty routed pages keep the section");
    assert_eq!(table.next_retirement(), None);
    // MiCleanSection: the retired section's own FILE_OBJECT writes the remaining pages.
    let first = table.next_unmapped_page_write().unwrap();
    assert_eq!((first.via, first.ticket.page_index, first.released), (identity, 0, true));
    let first = table.begin_page_write(first.via, first.ticket).unwrap();
    let second = table.next_unmapped_page_write().unwrap();
    assert_eq!(second.ticket.page_index, 1, "an in-flight page is not offered twice");
    let second = table.begin_page_write(second.via, second.ticket).unwrap();
    assert_eq!(table.next_unmapped_page_write(), None);
    assert!(table.finish_page_write(first, PageWriteOutcome::Written));
    table.drain_retired(&mut io).unwrap();
    assert!(io.frames.is_empty(), "an in-flight write still owns its frame and file");
    assert!(table.finish_page_write(second, PageWriteOutcome::Written));
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, vec![100, 101]);
    assert_eq!(io.leases, vec![RoutedSectionLease::new(11).unwrap()]);
}

#[test]
fn a_sibling_section_keeps_its_file_while_it_issues_a_write() {
    let (mut table, section, identity) = routed_table(11);
    let sibling = table
        .create(
            2,
            0x44,
            0x1800,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::routed(RoutedSectionLease::new(12).unwrap(), file_identity(9), 0x1800),
        )
        .unwrap();
    let sibling_identity = table.section_identity(sibling).unwrap();
    let ticket = table.prepare_section_writeback(sibling_identity).unwrap()[0];
    let write = table.begin_page_write(identity, ticket).unwrap();
    assert!(table.unmap_view(3, 0x10000).is_some());
    assert!(table.release_handle(section));
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert!(io.leases.is_empty(), "the writing section's FILE_OBJECT outlives its write");
    assert!(table.finish_page_write(write, PageWriteOutcome::Written));
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.leases, vec![RoutedSectionLease::new(11).unwrap()]);
    assert!(io.frames.is_empty(), "the sibling keeps the shared pages resident");
    assert_eq!(table.page_frame(sibling, 0), Some(100));
}

#[test]
fn only_a_routed_section_of_the_same_area_can_issue_a_write() {
    let (mut table, _, identity) = routed_table(11);
    let other = table
        .create(
            2,
            0x48,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::routed(RoutedSectionLease::new(13).unwrap(), file_identity(10), 0x1000),
        )
        .unwrap();
    let other_identity = table.section_identity(other).unwrap();
    let ticket = table.prepare_section_writeback(identity).unwrap()[0];
    assert_eq!(table.begin_page_write(other_identity, ticket), Err(PageWriteRefusal::Stale));
    let stale = SectionIdentity { index: identity.index, generation: identity.generation + 1 };
    assert_eq!(table.begin_page_write(stale, ticket), Err(PageWriteRefusal::Stale));
}

#[test]
fn overlay_retirement_is_unchanged_by_dirty_pages() {
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            2,
            0x40,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7, file_identity(7), 0x1000),
        )
        .unwrap();
    assert!(table.set_page_frame(section, 0, 100));
    assert!(table.mark_page_dirty(section, 0));
    assert!(table.release_handle(section));
    assert_eq!(table.next_unmapped_page_write(), None);
    #[derive(Default)]
    struct Overlay(Vec<u64>);
    impl SectionRetirementIo for Overlay {
        fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
            self.0.push(frame);
            Ok(())
        }
        fn release_backing(&mut self, _: SectionIdentity, _: GenericSectionBacking) -> Result<(), u32> {
            Ok(())
        }
    }
    let mut io = Overlay::default();
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.0, vec![100]);
}

#[test]
fn the_page_writer_takes_only_pages_no_view_still_maps() {
    let (mut table, section, identity) = routed_table(11);
    assert_eq!(table.next_unmapped_page_write(), None, "mapped dirty pages wait for a flush");
    assert!(table.map_view(4, section, 0x20000, 0x1000, 0));
    assert!(table.unmap_view(3, 0x10000).is_some());
    // Page 0 is still mapped by process 4; page 1 is on NT's modified list.
    let next = table.next_unmapped_page_write().unwrap();
    assert_eq!((next.via, next.ticket.page_index, next.released), (identity, 1, false));
    let write = table.begin_page_write(next.via, next.ticket).unwrap();
    assert_eq!(table.next_unmapped_page_write(), None);
    assert!(table.finish_page_write(write, PageWriteOutcome::Written));
    assert_eq!(table.next_unmapped_page_write(), None);
    assert!(table.unmap_view(4, 0x20000).is_some());
    assert_eq!(table.next_unmapped_page_write().unwrap().ticket.page_index, 0);
}

#[test]
fn a_flush_writes_only_versions_dirtied_before_it_began() {
    let (mut table, section, identity) = routed_table(11);
    let start = table.dirty_epoch();
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    assert!(table.prepare_writeback(plan).unwrap().iter().all(|ticket| ticket.dirty_epoch <= start));
    let first = table.prepare_writeback(plan).unwrap()[0];
    let write = table.begin_page_write(identity, first).unwrap();
    assert!(table.page_write_aliases(write).unwrap().iter().any(|alias| alias.pi == 3 && alias.page == 0x10000));
    assert!(table.finish_page_write(write, PageWriteOutcome::Written));
    assert_eq!(table.page_write_aliases(write), Err(STATUS_NOT_MAPPED_VIEW), "only an owned write rearms");
    assert!(table.mark_page_dirty(section, 0));
    assert!(table.prepare_writeback(plan).unwrap().iter().any(|ticket| ticket.dirty_epoch > start));
}

#[test]
fn the_page_writer_runs_until_no_routed_page_owes_a_write() {
    let (mut table, section, identity) = routed_table(11);
    assert!(table.has_async_dirty_pages(), "mapped dirty pages keep the writer scanning");
    assert_eq!(table.retained_routed_sections(), vec![(identity, RoutedSectionLease::new(11).unwrap())]);
    assert_eq!(table.routed_lease_exact(identity), RoutedSectionLease::new(11));
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    for ticket in table.prepare_writeback(plan).unwrap() {
        let write = table.begin_page_write(identity, ticket).unwrap();
        assert!(table.has_async_dirty_pages(), "an in-flight write is still owned");
        assert!(table.finish_page_write(write, PageWriteOutcome::Written));
    }
    assert!(!table.has_async_dirty_pages());
    assert!(table.unmap_view(3, 0x10000).is_some());
    assert!(table.release_handle(section));
    assert_eq!(table.routed_lease_exact(identity), RoutedSectionLease::new(11),
        "a released section retains its lease until it retires");
    table.drain_retired(&mut Release::default()).unwrap();
    assert_eq!(table.routed_lease_exact(identity), None);
    assert!(table.retained_routed_sections().is_empty());
}
