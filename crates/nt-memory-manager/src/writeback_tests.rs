use super::*;
use crate::*;
use alloc::{vec, vec::Vec};

const IO_ERROR: u32 = 0xC000_0185;

#[derive(Default)]
struct Io {
    fail_page: Option<(u64, u32, usize)>,
    barrier_status: u32,
    pages: Vec<u64>,
    barriers: usize,
}

impl SectionWritebackIo for Io {
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        self.pages.push(page.page_index);
        match self.fail_page {
            Some((index, status, bytes)) if index == page.page_index => (status, bytes),
            _ => (0, page.length),
        }
    }
    fn persist(&mut self) -> u32 {
        self.barriers += 1;
        self.barrier_status
    }
}

fn fixture() -> (GenericSectionTable, GenericSectionFlushPlan) {
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            2,
            0x40,
            0x2100,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7),
        )
        .unwrap();
    assert!(table.map_view(3, section, 0x10000, 0x3000, 0));
    // Deliberately register out of order; the batch is in file-offset order.
    for page in [2, 0, 1] {
        assert!(table.set_page_frame(section, page, page + 100));
        assert!(table.mark_page_dirty(section, page));
    }
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    (table, plan)
}

#[test]
fn success_persists_before_retiring_the_batch() {
    let (mut table, plan) = fixture();
    let mut io = Io::default();
    assert_eq!(
        table.writeback(plan, &mut io),
        WritebackResult {
            status: 0,
            bytes_written: 0x2100,
            pages_written: 3
        }
    );
    assert_eq!(io.pages, vec![0, 1, 2]);
    assert_eq!(io.barriers, 1);
    assert!(table.prepare_writeback(plan).unwrap().is_empty());
}

#[test]
fn failed_barrier_retains_every_page_for_retry() {
    let (mut table, plan) = fixture();
    let mut io = Io {
        barrier_status: IO_ERROR,
        ..Io::default()
    };
    assert_eq!(
        table.writeback(plan, &mut io),
        WritebackResult {
            status: IO_ERROR,
            bytes_written: 0x2100,
            pages_written: 3
        }
    );
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
    io.barrier_status = 0;
    assert_eq!(table.writeback(plan, &mut io).status, 0);
    assert_eq!(io.pages, vec![0, 1, 2, 0, 1, 2]);
    assert!(table.prepare_writeback(plan).unwrap().is_empty());
}

#[test]
fn partial_failure_retains_prefix_progress_and_dirty_ownership() {
    let (mut table, plan) = fixture();
    let mut io = Io {
        fail_page: Some((1, IO_ERROR, 37)),
        ..Io::default()
    };
    assert_eq!(
        table.writeback(plan, &mut io),
        WritebackResult {
            status: IO_ERROR,
            bytes_written: 0x1000 + 37,
            pages_written: 1
        }
    );
    assert_eq!(io.pages, vec![0, 1]);
    assert_eq!(io.barriers, 0);
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
}

#[test]
fn short_success_is_a_failure_without_losing_accepted_bytes() {
    let (mut table, plan) = fixture();
    let mut io = Io {
        fail_page: Some((0, 0, 27)),
        ..Io::default()
    };
    let result = table.writeback(plan, &mut io);
    assert_eq!(result.status, 0xC000_0001);
    assert_eq!(result.bytes_written, 27);
    assert_eq!(result.pages_written, 0);
    assert_eq!(io.pages, vec![0]);
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
}

#[test]
fn impossible_backend_progress_is_rejected() {
    let (mut table, plan) = fixture();
    let mut io = Io {
        fail_page: Some((1, 0, 0x1001)),
        ..Io::default()
    };
    let result = table.writeback(plan, &mut io);
    assert_eq!(result.status, IO_ERROR);
    assert_eq!(result.bytes_written, 0x1000);
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
}

#[test]
fn clean_range_still_runs_the_durability_barrier() {
    let (mut table, plan) = fixture();
    assert_eq!(table.writeback(plan, &mut Io::default()).status, 0);
    let mut io = Io {
        barrier_status: IO_ERROR,
        ..Io::default()
    };
    assert_eq!(
        table.writeback(plan, &mut io),
        WritebackResult::failure(IO_ERROR)
    );
    assert!(io.pages.is_empty());
    assert_eq!(io.barriers, 1);
}

#[test]
fn later_dirty_mark_invalidates_an_old_completion_ticket() {
    let (mut table, plan) = fixture();
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    assert!(table.mark_page_dirty(plan.view.section_index, ticket.page_index));
    assert!(!table.complete_writeback_page(ticket));
    let current = table.prepare_writeback(plan).unwrap()[0];
    assert!(table.complete_writeback_page(current));
    assert!(!table.complete_writeback_page(current));
}

#[test]
fn replacement_and_reset_cannot_revive_stale_tickets() {
    let (mut table, plan) = fixture();
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    assert!(table.set_page_frame(plan.view.section_index, ticket.page_index, 999));
    assert!(table.set_page_frame(plan.view.section_index, ticket.page_index, ticket.frame));
    assert!(!table.complete_writeback_page(ticket));
    assert!(table.reset());
    let section = table
        .create(
            2,
            0x40,
            0x2100,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7),
        )
        .unwrap();
    assert_eq!(section, plan.view.section_index);
    assert!(table.map_view(3, section, 0x10000, 0x3000, 0));
    assert!(table.set_page_frame(section, ticket.page_index, ticket.frame));
    assert!(table.mark_page_dirty(section, ticket.page_index));
    assert!(!table.complete_writeback_page(ticket));
}

#[test]
fn flushing_one_range_does_not_clean_another_page() {
    let (mut table, plan) = fixture();
    let partial = table.plan_flush(3, 0x11000, 1).unwrap();
    let mut io = Io::default();
    assert_eq!(table.writeback(partial, &mut io).status, 0);
    assert_eq!(io.pages, vec![1]);
    let remaining: Vec<_> = table
        .prepare_writeback(plan)
        .unwrap()
        .iter()
        .map(|page| page.page_index)
        .collect();
    assert_eq!(remaining, vec![0, 2]);
}

#[test]
fn forged_batch_ranges_cannot_write_outside_the_validated_view() {
    let (mut table, plan) = fixture();
    for invalid in [
        GenericSectionFlushPlan {
            base: plan.base - 1,
            ..plan
        },
        GenericSectionFlushPlan {
            size: plan.size + 1,
            ..plan
        },
        GenericSectionFlushPlan {
            section_offset: 0x1000,
            ..plan
        },
        GenericSectionFlushPlan { size: 0, ..plan },
    ] {
        let mut io = Io::default();
        assert_eq!(
            table.writeback(invalid, &mut io).status,
            STATUS_INVALID_PARAMETER_2
        );
        assert!(io.pages.is_empty());
        assert_eq!(io.barriers, 0);
    }
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
}
