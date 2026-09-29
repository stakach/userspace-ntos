use super::*;
use crate::*;
use alloc::{vec, vec::Vec};

fn file_identity(file_id: u64) -> SectionFileIdentity {
    SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id,
    }
}

const IO_ERROR: u32 = 0xC000_0185;

#[derive(Default)]
struct Io {
    fail_page: Option<(u64, u32, usize)>,
    barrier_status: u32,
    pages: Vec<u64>,
    barriers: usize,
    aliases: Vec<SectionPageAlias>,
    fail_alias: Option<usize>,
    events: Vec<char>,
    rearm_current: Option<ProcessIdentity>,
    rearm_view: Option<MemoryLifetime>,
    rearm_frame: Option<MemoryLifetime>,
}

impl SectionWritebackIo for Io {
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.events.push('r');
        if self.rearm_current.is_some() {
            crate::admit_section_alias_rearm(
                alias,
                self.rearm_current,
                self.rearm_view,
                self.rearm_frame,
            )?;
        }
        if self.fail_alias == Some(self.aliases.len()) {
            return Err(IO_ERROR);
        }
        self.aliases.push(alias);
        Ok(())
    }
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        self.events.push('w');
        self.pages.push(page.page_index);
        match self.fail_page {
            Some((index, status, bytes)) if index == page.page_index => (status, bytes),
            _ => (0, page.length),
        }
    }
    fn persist(&mut self) -> u32 {
        self.events.push('p');
        self.barriers += 1;
        self.barrier_status
    }
}

#[test]
fn stale_alias_rearm_has_no_write_effect_and_preserves_dirty_retry() {
    let old = ProcessIdentity {
        pid: 41,
        generation: ProcessGeneration::Hosted(7),
    };
    let new = ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(8),
    };
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            2,
            0x40,
            0x1000,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7, file_identity(7), 0x1000),
        )
        .unwrap();
    assert!(table.map_view_with_lifetime(
        8,
        MemoryLifetime::Process(old),
        section,
        0x20000,
        0x1000,
        0,
    ));
    assert!(table.set_page_frame(section, 0, 100));
    assert!(table.mark_page_dirty(section, 0));
    let plan = table.plan_flush(8, 0x20000, 0).unwrap();
    let mut stale = Io {
        rearm_current: Some(new),
        rearm_view: Some(MemoryLifetime::Process(old)),
        rearm_frame: Some(MemoryLifetime::Process(old)),
        ..Io::default()
    };
    assert_eq!(
        table.writeback(plan, &mut stale).status,
        STATUS_INVALID_HANDLE
    );
    assert_eq!(stale.events, vec!['r']);
    assert!(stale.aliases.is_empty());
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 1);

    let old_view = table
        .first_view_for_process_exact(8, MemoryLifetime::Process(old))
        .unwrap();
    assert!(table.unmap_view_identity(old_view).is_some());
    assert!(table.map_view_with_lifetime(
        8,
        MemoryLifetime::Process(new),
        section,
        0x20000,
        0x1000,
        0,
    ));
    let retry_plan = table.plan_flush(8, 0x20000, 0).unwrap();
    let mut retry = Io {
        rearm_current: Some(new),
        rearm_view: Some(MemoryLifetime::Process(new)),
        rearm_frame: None,
        ..Io::default()
    };
    assert_eq!(table.writeback(retry_plan, &mut retry).status, 0);
    assert_eq!(retry.events, vec!['r', 'w', 'p']);
    assert!(table.prepare_writeback(retry_plan).unwrap().is_empty());
}

#[test]
fn section_alias_rearm_rejects_foreign_view_or_resident_frame() {
    let owner = ProcessIdentity {
        pid: 41,
        generation: ProcessGeneration::Hosted(7),
    };
    let replacement = ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(8),
    };
    let alias = SectionPageAlias {
        pi: 8,
        page: 0x20000,
        lifetime: MemoryLifetime::Process(owner),
    };
    assert_eq!(
        crate::admit_section_alias_rearm(
            alias,
            Some(owner),
            Some(MemoryLifetime::Process(replacement)),
            None,
        ),
        Err(STATUS_NOT_MAPPED_VIEW),
    );
    assert_eq!(
        crate::admit_section_alias_rearm(
            alias,
            Some(owner),
            Some(alias.lifetime),
            Some(MemoryLifetime::Process(replacement)),
        ),
        Err(STATUS_INVALID_HANDLE),
    );
    assert_eq!(
        crate::admit_section_alias_rearm(alias, Some(owner), Some(alias.lifetime), None),
        Ok(()),
    );
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
            GenericSectionBacking::overlay(7, file_identity(7), 0x2100),
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
fn writeback_alias_retains_original_process_generation_after_slot_reuse() {
    let (mut table, plan) = fixture();
    let original = crate::MemoryLifetime::Process(crate::ProcessIdentity {
        pid: 41,
        generation: ProcessGeneration::Hosted(7),
    });
    let replacement = crate::MemoryLifetime::Process(crate::ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(8),
    });
    assert!(table.map_view_with_lifetime(
        8,
        original,
        plan.view.section_index,
        0x20000,
        0x1000,
        0,
    ));
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    assert!(table.writeback_aliases(ticket).unwrap().iter().any(|alias| {
        alias.pi == 8 && alias.page == 0x20000 && alias.lifetime == original
    }));
    assert!(table.first_view_for_process_exact(8, replacement).is_none());
    assert_eq!(
        table.first_view_for_process_exact(8, original).unwrap().lifetime,
        original
    );
    let original_view = table.first_view_for_process_exact(8, original).unwrap();
    assert!(table
        .unmap_view_identity(GenericSectionView { lifetime: replacement, ..original_view })
        .is_none());
    assert!(table.unmap_view_identity(original_view).is_some());
    assert!(!table
        .writeback_aliases(ticket)
        .unwrap()
        .iter()
        .any(|alias| alias.pi == 8));
}

#[test]
fn aliases_follow_section_offsets_across_processes_and_views() {
    let (mut table, plan) = fixture();
    let section = plan.view.section_index;
    assert!(table.map_view(8, section, 0x20000, 0x1000, 0x1000));
    assert!(table.map_view(3, section, 0x30000, 0x2000, 0x1000));
    assert!(table.map_view(9, section, 0x40000, 0x1000, 0x2000));
    let ticket = table.prepare_writeback(plan).unwrap()[1];
    assert_eq!(
        table.writeback_aliases(ticket).unwrap(),
        vec![
            SectionPageAlias::for_test(3, 0x11000),
            SectionPageAlias::for_test(8, 0x20000),
            SectionPageAlias::for_test(3, 0x30000),
        ]
    );
}

#[test]
fn aliases_exclude_dead_views_but_include_sibling_sections_of_the_same_file() {
    let (mut table, plan) = fixture();
    let other = table
        .create(
            2,
            0x44,
            0x2100,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            plan.section.backing,
        )
        .unwrap();
    assert!(table.map_view(8, other, 0x20000, 0x3000, 0));
    assert!(table.map_view(9, plan.view.section_index, 0x30000, 0x3000, 0));
    table.unmap_view(9, 0x30000).unwrap();
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    assert_eq!(
        table.writeback_aliases(ticket).unwrap(),
        vec![
            SectionPageAlias::for_test(3, 0x10000),
            SectionPageAlias::for_test(8, 0x20000)
        ]
    );
}

#[test]
fn alias_planning_rejects_stale_or_inconsistent_tickets() {
    let (mut table, plan) = fixture();
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    let mut invalid = ticket;
    invalid.file_offset = 0x1000;
    assert_eq!(
        table.writeback_aliases(invalid),
        Err(STATUS_NOT_MAPPED_VIEW)
    );
    table.mark_page_dirty(plan.view.section_index, 0);
    assert_eq!(table.writeback_aliases(ticket), Err(STATUS_NOT_MAPPED_VIEW));
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    assert!(!table.set_page_frame(plan.view.section_index, 0, 900));
    assert!(table.writeback_aliases(ticket).is_ok());
}

#[test]
fn malformed_alias_geometry_prevents_writeback() {
    for (base, size, offset) in [
        (0x20001, 0x1000, 0),
        (0x20000, 0x1000, 1),
        (u64::MAX & !0xfff, 0x2000, 0),
        (0x20000, 0x2000, u64::MAX & !0xfff),
    ] {
        let (mut table, plan) = fixture();
        assert!(table.map_view(8, plan.view.section_index, base, size, offset));
        let mut io = Io::default();
        assert_eq!(
            table.writeback(plan, &mut io).status,
            STATUS_INVALID_PARAMETER_2
        );
        assert!(io.pages.is_empty());
        assert_eq!(io.barriers, 0);
        assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
    }
}

#[test]
fn every_alias_is_rearmed_before_any_page_is_copied() {
    let (mut table, plan) = fixture();
    assert!(table.map_view(8, plan.view.section_index, 0x20000, 0x3000, 0));
    let mut io = Io::default();
    assert_eq!(table.writeback(plan, &mut io).status, 0);
    assert_eq!(
        io.events,
        vec!['r', 'r', 'r', 'r', 'r', 'r', 'w', 'w', 'w', 'p']
    );
}

#[test]
fn failed_alias_rearm_retains_whole_batch_without_io_then_retries() {
    for failed in 0..3 {
        let (mut table, plan) = fixture();
        let mut io = Io {
            fail_alias: Some(failed),
            ..Io::default()
        };
        assert_eq!(
            table.writeback(plan, &mut io),
            WritebackResult::failure(IO_ERROR)
        );
        assert!(io.pages.is_empty());
        assert_eq!(io.barriers, 0);
        assert_eq!(table.prepare_writeback(plan).unwrap().len(), 3);
        let mut retry = Io::default();
        assert_eq!(table.writeback(plan, &mut retry).status, 0);
        assert_eq!(retry.aliases.len(), 3);
        assert!(table.prepare_writeback(plan).unwrap().is_empty());
    }
}

#[test]
fn second_dirty_write_is_rearmed_and_checkpointed_again() {
    let (mut table, plan) = fixture();
    assert_eq!(table.writeback(plan, &mut Io::default()).status, 0);
    assert!(table.mark_page_dirty(plan.view.section_index, 1));
    let mut io = Io::default();
    assert_eq!(table.writeback(plan, &mut io).bytes_written, 0x1000);
    assert_eq!(
        io.aliases,
        vec![SectionPageAlias::for_test(3, 0x11000)]
    );
    assert_eq!(io.events, vec!['r', 'w', 'p']);
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
    assert!(!table.set_page_frame(plan.view.section_index, ticket.page_index, 999));
    assert!(table.set_page_frame(plan.view.section_index, ticket.page_index, ticket.frame));
    assert!(table.complete_writeback_page(ticket));
    table.clear_section(plan.view.section_index);
    while let Some(retirement) = table.next_retirement() {
        assert!(table.complete_retirement(retirement));
    }
    assert!(table.reset());
    let section = table
        .create(
            2,
            0x40,
            0x2100,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7, file_identity(7), 0x2100),
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
