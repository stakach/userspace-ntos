use super::*;
use crate::writeback::{PageWriteOutcome, PageWriteState};
use alloc::vec;

fn routed() -> (GenericSectionTable, usize, SectionIdentity) {
    let mut table = GenericSectionTable::new();
    let file = SectionFileIdentity { mount: SectionMountIds::new().allocate().unwrap(), file_id: 9 };
    let backing = GenericSectionBacking::routed(RoutedSectionLease::new(11).unwrap(), file, 0x1800);
    let section = table
        .create(2, 0x40, 0x1800, crate::PAGE_READWRITE, SECTION_ATTR_SEC_COMMIT, backing)
        .unwrap();
    assert!(table.map_view(3, section, 0x10000, 0x2000, 0));
    assert!(table.set_page_frame(section, 0, 100));
    assert!(table.set_page_frame(section, 1, 101));
    let identity = table.section_identity(section).unwrap();
    (table, section, identity)
}

#[test]
fn a_completed_write_names_every_resident_page_it_overlaps() {
    let (table, _, identity) = routed();
    // 0x20 bytes straddling pages 0 and 1, and nothing for the absent page 2.
    let plan = table.plan_stream_write(identity, 0xff0, 0x1020).unwrap();
    assert_eq!(
        plan.pages().iter().map(|page| (page.frame, page.page_offset, page.data_offset, page.length))
            .collect::<Vec<_>>(),
        vec![(100, 0xff0, 0, 0x10), (101, 0, 0x10, 0x1000)],
    );
    assert!(table.plan_stream_write(identity, 0x2000, 0x10).unwrap().pages().is_empty());
}

#[test]
fn a_clean_page_takes_the_written_bytes_and_stays_clean() {
    let (mut table, _, identity) = routed();
    let plan = table.plan_stream_write(identity, 0x10, 4).unwrap();
    assert!(table.commit_stream_write(plan));
    let flush = table.plan_flush(3, 0x10000, 0).unwrap();
    assert!(table.prepare_writeback(flush).unwrap().is_empty(), "the disk already holds them");
}

#[test]
fn the_write_wins_over_a_dirty_or_in_flight_page() {
    let (mut table, section, identity) = routed();
    assert!(table.mark_page_dirty(section, 0));
    assert!(table.mark_page_dirty(section, 1));
    let flush = table.plan_flush(3, 0x10000, 0).unwrap();
    let tickets = table.prepare_writeback(flush).unwrap();
    // Page 1's older copy is already in flight when the file write completes.
    let in_flight = table.begin_page_write(identity, tickets[1]).unwrap();
    let plan = table.plan_stream_write(identity, 0x800, 0x1000).unwrap();
    assert!(table.commit_stream_write(plan));
    assert!(table.finish_page_write(in_flight, PageWriteOutcome::Written));
    let owed = table.prepare_writeback(flush).unwrap();
    assert_eq!(owed.iter().map(|ticket| ticket.page_index).collect::<Vec<_>>(), vec![0, 1],
        "the older copy cannot clean the page the write updated");
    assert!(owed.iter().all(|ticket| ticket.dirty_epoch() > tickets[1].dirty_epoch()));
    assert_eq!(table.page_write_state(owed[1]), Some(PageWriteState::Idle));
}

#[test]
fn a_write_past_the_cached_tail_grows_the_file_data() {
    let (mut table, section, identity) = routed();
    // Page 1 holds the 0x800-byte EOF tail as zero padding; the write makes it file data.
    let plan = table.plan_stream_write(identity, 0x1700, 0x400).unwrap();
    assert!(table.commit_stream_write(plan));
    assert_eq!(table.refresh_file_extent(section, 0x1b00), Ok(()));
    assert!(table.mark_page_dirty(section, 1));
    let flush = table.plan_flush(3, 0x10000, 0).unwrap();
    assert_eq!(table.prepare_writeback(flush).unwrap()[0].length, 0xb00);
}

#[test]
fn a_stale_plan_changes_nothing() {
    let (mut table, section, identity) = routed();
    assert!(table.mark_page_dirty(section, 0));
    let plan = table.plan_stream_write(identity, 0, 0x2000).unwrap();
    assert!(table.unmap_view(3, 0x10000).is_some());
    assert!(table.release_handle(section));
    table.drain_retired(&mut NoRelease).unwrap();
    let epoch = table.dirty_epoch();
    assert!(!table.commit_stream_write(plan));
    assert_eq!(table.dirty_epoch(), epoch);
}

struct NoRelease;
impl SectionRetirementIo for NoRelease {
    fn release_frame(&mut self, _: u64) -> Result<(), u32> { Ok(()) }
    fn release_backing(&mut self, _: SectionIdentity, _: GenericSectionBacking) -> Result<(), u32> {
        Ok(())
    }
}
