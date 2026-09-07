use super::*;

fn prepare(table: &PrefetchFrames) -> PrefetchJournal<1> {
    PrefetchJournal::prepare(2, Some(7), [(0x1000, 0x2000)], table).unwrap()
}

fn live(table: &mut PrefetchFrames, page: u64, cap: u64) -> PrefetchReservation {
    let ticket = reserve(table, page);
    table
        .build(
            ticket,
            &mut Io {
                cap,
                ..Io::default()
            },
        )
        .unwrap();
    ticket
}

#[test]
fn claim_pins_every_selected_state_and_blocks_all_ordinary_release_paths() {
    let mut table = PrefetchFrames::new();
    let first = live(&mut table, 0x1000, 42);
    let reserved = reserve(&mut table, 0x2000);
    live(&mut table, 0x3000, 44);
    let journal = prepare(&table);
    assert!(table.lookup(PROCESS, 0x1000).unwrap().is_some());
    journal.claim(&mut table).unwrap();
    journal.claim(&mut table).unwrap();
    let mut io = Io::default();
    assert!(table.lookup(PROCESS, 0x1000).is_err());
    assert!(table.lookup(PROCESS, 0x3000).unwrap().is_some());
    assert!(table.build(reserved, &mut io).is_err());
    assert!(table.retire(first, &mut io).is_err());
    assert!(table.retire(reserved, &mut io).is_err());
    assert!(table.retry_retirement(PROCESS, 0x1000, &mut io).is_err());
    assert_eq!(table.retire_process(PROCESS, &mut io), (0, 1));
    assert!(table.lookup(PROCESS, 0x3000).unwrap().is_some());
    assert!(io.calls.is_empty());
    assert!(table.reserve(PROCESS, 0x4000, |_| Some(0x100000)).is_err());
}

#[test]
fn ordinary_process_preflight_refuses_excluded_pages_before_any_effects() {
    let mut table = PrefetchFrames::new();
    live(&mut table, 0x1000, 42);
    live(&mut table, 0x3000, 43);
    assert!(!table.can_retire_process(PROCESS, |page| page != 0x3000));
    assert!(table.lookup(PROCESS, 0x1000).unwrap().is_some());
    assert!(table.lookup(PROCESS, 0x3000).unwrap().is_some());
}

#[test]
fn separately_prepared_journal_cannot_steal_an_existing_claim() {
    let mut table = PrefetchFrames::new();
    live(&mut table, 0x1000, 42);
    let first = prepare(&table);
    let second = prepare(&table);
    first.claim(&mut table).unwrap();
    assert_eq!(second.claim(&mut table), Err(PrefetchJournalError::Claimed));
    assert_eq!(
        second.retire(&mut table, &mut Io::default()),
        Err(PrefetchJournalError::Claimed)
    );
    assert!(matches!(
        PrefetchJournal::prepare(2, Some(7), [(0x1000, 4096)], &table),
        Err(PrefetchJournalError::Claimed)
    ));
}

#[test]
fn complete_phase_snapshot_detects_delete_ack_with_same_cap_and_unavailable_lookup() {
    let mut table = PrefetchFrames::new();
    let ticket = live(&mut table, 0x1000, 42);
    let mut io = Io {
        fail_delete: true,
        ..Io::default()
    };
    assert!(table.retire(ticket, &mut io).is_err());
    let journal = prepare(&table);
    io.fail_delete = false;
    io.fail_recycle = true;
    assert!(table.retire(ticket, &mut io).is_err());
    assert_eq!(table.capabilities().collect::<Vec<_>>(), vec![42]);
    assert_eq!(
        journal.claim(&mut table),
        Err(PrefetchJournalError::StaleCoverage)
    );
    assert!(table.can_retire_process(PROCESS, |_| true));
}

#[test]
fn reservation_reuse_and_new_selected_rows_cannot_refresh_original_coverage() {
    let mut table = PrefetchFrames::new();
    let ticket = live(&mut table, 0x1000, 42);
    let journal = prepare(&table);
    table.retire(ticket, &mut Io::default()).unwrap();
    live(&mut table, 0x1000, 42);
    assert_eq!(
        journal.claim(&mut table),
        Err(PrefetchJournalError::StaleCoverage)
    );
    let journal = prepare(&table);
    live(&mut table, 0x2000, 43);
    assert_eq!(
        journal.claim(&mut table),
        Err(PrefetchJournalError::StaleCoverage)
    );
    assert!(table.can_retire_process(PROCESS, |_| true));
}

#[test]
fn cross_range_cap_collision_is_rejected_before_any_claim() {
    let mut table = PrefetchFrames::new();
    live(&mut table, 0x1000, 42);
    live(&mut table, 0x2000, 43);
    let journal = prepare(&table);
    live(&mut table, 0x4000, 43);
    assert_eq!(
        journal.claim(&mut table),
        Err(PrefetchJournalError::SharedCapability(43))
    );
    assert!(table.can_retire_process(PROCESS, |_| true));
}

#[test]
fn every_cleanup_failure_retains_acknowledgements_and_current_claim() {
    for failure in 0..3 {
        let mut table = PrefetchFrames::new();
        live(&mut table, 0x1000, 42);
        let journal = prepare(&table);
        journal.claim(&mut table).unwrap();
        let mut io = Io {
            fail_unmap: failure == 0,
            fail_delete: failure == 1,
            fail_recycle: failure == 2,
            ..Io::default()
        };
        for _ in 0..2 {
            assert!(matches!(
                journal.retire(&mut table, &mut io),
                Err(PrefetchJournalError::Backend { page: 0x1000, .. })
            ));
            assert!(!table.can_retire_process(PROCESS, |_| true));
            assert!(!journal.is_complete());
        }
        io.fail_unmap = false;
        io.fail_delete = false;
        io.fail_recycle = false;
        journal.retire(&mut table, &mut io).unwrap();
        assert!(journal.is_complete() && table.process_is_empty(2));
        for (index, operation) in ["unmap", "delete", "recycle"].iter().enumerate() {
            assert_eq!(
                io.calls.iter().filter(|(op, _)| op == operation).count(),
                if failure == index { 3 } else { 1 }
            );
        }
        let count = io.calls.len();
        journal.retire(&mut table, &mut io).unwrap();
        assert_eq!(io.calls.len(), count);
    }
}

#[test]
fn partial_cleanup_allows_reuse_of_released_row_and_slot_outside_selection() {
    let mut table = PrefetchFrames::new();
    live(&mut table, 0x1000, 42);
    live(&mut table, 0x2000, 43);
    let journal = prepare(&table);
    journal.claim(&mut table).unwrap();
    struct FailSecond(Io);
    impl AliasRetirementIo for FailSecond {
        fn unmap(&mut self, cap: u64) -> Result<(), u32> {
            self.0.unmap(cap)
        }
        fn delete(&mut self, cap: u64) -> Result<(), u32> {
            self.0.delete(cap)
        }
        fn recycle_slot(&mut self, cap: u64) -> Result<(), u32> {
            if cap == 43 {
                Err(6)
            } else {
                self.0.recycle_slot(cap)
            }
        }
        fn recycle_unretyped_slot(&mut self, _: u64) -> Result<(), u32> {
            panic!("mapped frames")
        }
    }
    assert!(journal
        .retire(&mut table, &mut FailSecond(Io::default()))
        .is_err());
    assert!(!table.contains(2, 0x1000));
    live(&mut table, 0x4000, 42);
    journal.revalidate(&table).unwrap();
    let mut io = Io::default();
    journal.retire(&mut table, &mut io).unwrap();
    assert_eq!(io.calls, vec![("recycle", 43)]);
    assert!(table.lookup(PROCESS, 0x4000).unwrap().is_some());
    assert_eq!(
        journal.original_capabilities().collect::<Vec<_>>(),
        vec![42, 43]
    );
}

#[test]
fn failed_allocation_slot_uses_strict_recycling_without_deletion() {
    let mut table = PrefetchFrames::new();
    let ticket = reserve(&mut table, 0x1000);
    let mut io = Io {
        alloc_status: 7,
        fail_recycle: true,
        ..Io::default()
    };
    assert!(table.build(ticket, &mut io).is_err());
    let journal = prepare(&table);
    journal.claim(&mut table).unwrap();
    io.calls.clear();
    io.fail_recycle = false;
    journal.retire(&mut table, &mut io).unwrap();
    assert_eq!(io.calls, vec![("recycle-empty", 42)]);
}

#[test]
fn delete_acknowledged_slot_remains_owned_until_recycling_succeeds() {
    let mut table = PrefetchFrames::new();
    live(&mut table, 0x1000, 42);
    let journal = prepare(&table);
    journal.claim(&mut table).unwrap();
    let mut io = Io {
        fail_recycle: true,
        ..Io::default()
    };
    assert!(journal.retire(&mut table, &mut io).is_err());
    live(&mut table, 0x4000, 42); // Contradictory allocator reuse before the slot was recycled.
    let calls = io.calls.len();
    assert_eq!(
        journal.retire(&mut table, &mut io),
        Err(PrefetchJournalError::SharedCapability(42))
    );
    assert_eq!(io.calls.len(), calls);
}

#[test]
fn generation_absence_and_range_validation_fail_closed() {
    let mut table = PrefetchFrames::new();
    live(&mut table, 0x4000, 42);
    for generation in [None, Some(0), Some(8)] {
        assert!(matches!(
            PrefetchJournal::prepare(2, generation, [(0x1000, 4096)], &table),
            Err(PrefetchJournalError::OwnerChanged)
        ));
    }
    for range in [(1, 4096), (0x1000, 0), (0x1000, 1), (u64::MAX - 4095, 4096)] {
        assert!(matches!(
            PrefetchJournal::prepare(2, Some(7), [range], &table),
            Err(PrefetchJournalError::InvalidRange)
        ));
    }
}

#[test]
fn empty_coverage_cannot_authorize_later_admission() {
    let mut table = PrefetchFrames::new();
    let journal = prepare(&table);
    journal.claim(&mut table).unwrap();
    live(&mut table, 0x1000, 42); // Deliberately violate the caller's admission exclusion.
    assert_eq!(
        journal.retire(&mut table, &mut Io::default()),
        Err(PrefetchJournalError::StaleCoverage)
    );
}

#[test]
fn reserved_empty_rows_complete_without_backend_effects_and_require_claim_first() {
    let mut table = PrefetchFrames::new();
    reserve(&mut table, 0x1000);
    let journal = prepare(&table);
    let mut io = Io::default();
    assert_eq!(
        journal.retire(&mut table, &mut io),
        Err(PrefetchJournalError::NotClaimed)
    );
    journal.claim(&mut table).unwrap();
    journal.retire(&mut table, &mut io).unwrap();
    assert!(table.process_is_empty(2));
    assert!(io.calls.is_empty());
}
