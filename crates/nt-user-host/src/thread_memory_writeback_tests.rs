use super::*;
use alloc::vec::Vec;
use nt_memory_manager::writeback::{SectionPageAlias, SectionWritebackIo, SectionWritebackPage};
use nt_memory_manager::{
    GenericSectionBacking, GenericSectionTable, SectionFileIdentity, SectionMountIds,
    PAGE_READWRITE, SECTION_ATTR_SEC_COMMIT, STATUS_ACCESS_VIOLATION,
};

struct Writeback<'a> {
    slots: &'a [ThreadRuntimeSlot<Runtime>],
    rearmed: Vec<SectionPageAlias>,
    writes: usize,
    persists: usize,
}

impl<'a> Writeback<'a> {
    fn new(slots: &'a [ThreadRuntimeSlot<Runtime>]) -> Self {
        Self {
            slots,
            rearmed: Vec::new(),
            writes: 0,
            persists: 0,
        }
    }
}

impl SectionWritebackIo for Writeback<'_> {
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        check(self.slots, alias.pi, alias.page, 4096).map_err(|_| STATUS_ACCESS_VIOLATION)?;
        self.rearmed.push(alias);
        Ok(())
    }

    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        self.writes += 1;
        (0, page.length)
    }

    fn persist(&mut self) -> u32 {
        self.persists += 1;
        0
    }
}

fn dirty_shared_page() -> (GenericSectionTable, GenericSectionBacking) {
    let mut table = GenericSectionTable::new();
    let file = SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id: 100,
    };
    let backing = GenericSectionBacking::overlay(7, file, 4096);
    let section = table
        .create(4, 7, 4096, PAGE_READWRITE, SECTION_ATTR_SEC_COMMIT, backing)
        .unwrap();
    assert!(table.set_page_frame(section, 0, 1000));
    assert!(table.mark_page_dirty(section, 0));
    // The flush initiator is disjoint, but the same frame also has an excluded alias in PI 2.
    table.map_view(4, section, 0x50000, 4096, 0);
    table.map_view(2, section, 0x1000, 4096, 0);
    (table, backing)
}

fn excluded_alias_preserves_writeback(file_wide: bool) {
    let (mut table, backing) = dirty_shared_page();
    let plan = table.plan_flush(4, 0x50000, 0).unwrap();
    let tickets = table.prepare_writeback(plan).unwrap();
    assert_eq!(tickets.len(), 1);
    let mut slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    let id = slots[0].pending().unwrap().id();
    slots[0].prepare_cleanup(id, &[]).unwrap();
    slots[0].commit_memory_handoff(id).unwrap();

    // Both failed and completed-but-not-retired cleanup retain the writeback exclusion.
    let mut cleanup = Backend { id, fail: true };
    for completed in [false, true] {
        cleanup.fail = !completed;
        assert_eq!(
            slots[0].advance_cleanup(id, &mut cleanup).is_ok(),
            completed
        );
        let mut io = Writeback::new(&slots);
        let result = if file_wide {
            table.writeback_file(backing, &mut io)
        } else {
            table.writeback(plan, &mut io)
        };
        assert_eq!(result.status, STATUS_ACCESS_VIOLATION);
        assert_eq!(result.pages_written, 0);
        assert_eq!((io.writes, io.persists), (0, 0));
        assert_eq!(
            io.rearmed.as_slice(),
            &[SectionPageAlias {
                pi: 4,
                page: 0x50000
            }]
        );
        assert_eq!(table.prepare_writeback(plan).unwrap(), tickets);
    }

    assert!(slots[0].take_retired_payload(id).is_some());
    let mut io = Writeback::new(&slots);
    let result = if file_wide {
        table.writeback_file(backing, &mut io)
    } else {
        table.writeback(plan, &mut io)
    };
    assert_eq!(result.status, 0);
    assert_eq!(result.pages_written, 1);
    assert_eq!((io.writes, io.persists), (1, 1));
    assert_eq!(io.rearmed.len(), 2);
    assert!(table.prepare_writeback(plan).unwrap().is_empty());
}

#[test]
fn view_flush_checks_other_process_aliases_and_retains_dirty_ticket_until_retirement() {
    excluded_alias_preserves_writeback(false);
}

#[test]
fn file_flush_checks_all_aliases_and_retains_dirty_ticket_until_retirement() {
    excluded_alias_preserves_writeback(true);
}

#[test]
fn unrelated_pending_owner_does_not_block_writeback() {
    let (mut table, backing) = dirty_shared_page();
    let slots = [pending(runtime(3, ProcessGeneration::Temporary(9)))];
    let mut io = Writeback::new(&slots);
    assert_eq!(table.writeback_file(backing, &mut io).status, 0);
    assert_eq!((io.rearmed.len(), io.writes, io.persists), (2, 1, 1));
}
