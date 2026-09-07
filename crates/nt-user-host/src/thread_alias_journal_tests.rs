use super::*;
use crate::process_identity::ProcessGeneration;
use crate::thread_rollback::{new_rollback_id, ThreadRollbackIdentity};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Unmap(u64),
    Delete(u64),
    Recycle(u64),
}

#[derive(Default)]
struct State {
    calls: Vec<Call>,
    fail: Option<Call>,
    populated: Vec<u64>,
    mapped: Vec<u64>,
}

#[derive(Clone, Default)]
struct Io(Rc<RefCell<State>>);
impl Io {
    fn effect(&self, call: Call) -> Result<(), u32> {
        let mut state = self.0.borrow_mut();
        state.calls.push(call);
        if state.fail == Some(call) {
            return Err(99);
        }
        match call {
            Call::Unmap(cap) => {
                let index = state
                    .mapped
                    .iter()
                    .position(|&n| n == cap)
                    .expect("mapped cap");
                state.mapped.swap_remove(index);
            }
            Call::Delete(cap) => {
                assert!(!state.mapped.contains(&cap));
                let index = state
                    .populated
                    .iter()
                    .position(|&n| n == cap)
                    .expect("populated cap");
                state.populated.swap_remove(index);
            }
            Call::Recycle(cap) => assert!(!state.populated.contains(&cap)),
        }
        Ok(())
    }
}
impl AliasRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Call::Unmap(cap))
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Call::Delete(cap))
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("strict recycling required")
    }
    fn recycle_unretyped_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Call::Recycle(cap))
    }
}
struct Setup {
    io: Io,
    cap: u64,
    copy_status: u32,
}
impl AliasRetirementIo for Setup {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.io.unmap(cap)
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.io.delete(cap)
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("strict recycling required")
    }
    fn recycle_unretyped_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.io.recycle_unretyped_slot(cap)
    }
}
impl AliasTransitionIo for Setup {
    fn copy(&mut self) -> (u64, u32) {
        if self.copy_status == 0 {
            self.io.0.borrow_mut().populated.push(self.cap);
        }
        (self.cap, self.copy_status)
    }
    fn map(&mut self, cap: u64, _: u64) -> Result<(), u32> {
        self.io.0.borrow_mut().mapped.push(cap);
        Ok(())
    }
}
fn id() -> ThreadRollbackId {
    new_rollback_id(ThreadRollbackIdentity {
        pi: 2,
        pid: 8,
        process_generation: ProcessGeneration::Hosted(1),
        tid: 12,
    })
    .unwrap()
}
fn layout() -> ThreadMemoryLayout {
    ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x6000, 0xa000).unwrap()
}
fn live(page: u64, cap: u64, io: &Io) -> ThreadAliasMapping {
    let mut row = ThreadAliasMapping::new(page).unwrap();
    row.replace(
        1,
        &mut Setup {
            io: io.clone(),
            cap,
            copy_status: 0,
        },
    )
    .unwrap();
    row
}

#[test]
fn claims_only_selected_pages_and_preserves_original_provenance() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io), live(0xb000, 12, &io)];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    assert!(rows.iter().all(|row| !row.is_claimed()));
    assert_eq!(
        journal.original_capabilities().collect::<Vec<_>>(),
        vec![11]
    );
    journal.claim(id, 2, &mut rows).unwrap();
    journal.claim(id, 2, &mut rows).unwrap();
    assert!(rows[0].is_claimed());
    assert!(!rows[1].is_claimed());
    assert!(io.0.borrow().calls.is_empty());
}

#[test]
fn claim_rejects_all_ordinary_operations_without_effects() {
    let io = Io::default();
    let mut rows = vec![
        live(0x1000, 11, &io),
        ThreadAliasMapping::new(0x2000).unwrap(),
    ];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    journal.claim(id, 2, &mut rows).unwrap();
    let mut backend = Setup {
        io: io.clone(),
        cap: 15,
        copy_status: 0,
    };
    for row in &mut rows {
        assert_eq!(row.live(), None);
        assert!(!row.is_empty());
        assert_eq!(row.replace(2, &mut backend), Err(INVALID));
        assert_eq!(row.remap(2, &mut backend), Err(INVALID));
        assert_eq!(row.recover(&mut backend), Err(INVALID));
        assert_eq!(row.retire(&mut backend), Err(INVALID));
    }
    assert!(io.0.borrow().calls.is_empty());
}

#[test]
fn stale_snapshot_refuses_every_claim() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io), live(0x2000, 12, &io)];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    rows[1]
        .remap(
            2,
            &mut Setup {
                io: io.clone(),
                cap: 20,
                copy_status: 0,
            },
        )
        .unwrap();
    assert_eq!(
        journal.claim(id, 2, &mut rows),
        Err(JournalError::StaleMappings)
    );
    assert!(rows.iter().all(|row| !row.is_claimed()));
}

#[test]
fn changed_coverage_and_duplicate_pages_are_rejected() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io)];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    rows.push(live(0x2000, 12, &io));
    assert_eq!(
        journal.claim(id, 2, &mut rows),
        Err(JournalError::StaleMappings)
    );
    rows[1] = live(0x1000, 13, &io);
    assert!(matches!(
        ThreadAliasJournal::prepare(id, layout(), 2, &rows),
        Err(JournalError::StaleMappings)
    ));
    rows.clear();
    assert_eq!(
        journal.claim(id, 2, &mut rows),
        Err(JournalError::StaleMappings)
    );
}

#[test]
fn cap_collision_outside_geometry_prevents_all_claims() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io), live(0x2000, 12, &io)];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    rows.push(live(0xb000, 12, &io));
    assert_eq!(
        journal.claim(id, 2, &mut rows),
        Err(JournalError::SharedCapability(12))
    );
    assert!(rows.iter().all(|row| !row.is_claimed()));
}

#[test]
fn different_attempt_and_attachment_cannot_claim_or_drive() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io)];
    let owner = id();
    let journal = ThreadAliasJournal::prepare(owner, layout(), 2, &rows).unwrap();
    assert_eq!(
        journal.claim(id(), 2, &mut rows),
        Err(JournalError::OwnerChanged)
    );
    assert_eq!(
        journal.claim(owner, 3, &mut rows),
        Err(JournalError::StaleMappings)
    );
    assert_eq!(
        journal.retire(owner, 2, &mut rows, |_| io.clone()),
        Err(JournalError::NotClaimed)
    );
    journal.claim(owner, 2, &mut rows).unwrap();
    assert_eq!(
        journal.retire(id(), 2, &mut rows, |_| io.clone()),
        Err(JournalError::OwnerChanged)
    );
    assert!(io.0.borrow().calls.is_empty());
}

#[test]
fn another_journal_cannot_steal_claim_even_with_same_attempt() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io)];
    let id = id();
    let first = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    let second = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    first.claim(id, 2, &mut rows).unwrap();
    assert_eq!(second.claim(id, 2, &mut rows), Err(JournalError::Claimed));
    assert!(matches!(
        ThreadAliasJournal::prepare(id, layout(), 2, &rows),
        Err(JournalError::Claimed)
    ));
}

#[test]
fn each_backend_failure_retains_phase_without_replaying_acknowledged_effects() {
    for failure in [Call::Unmap(11), Call::Delete(11), Call::Recycle(11)] {
        let io = Io::default();
        let mut rows = vec![live(0x1000, 11, &io)];
        let id = id();
        let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
        journal.claim(id, 2, &mut rows).unwrap();
        io.0.borrow_mut().fail = Some(failure);
        assert_eq!(
            journal.retire(id, 2, &mut rows, |_| io.clone()),
            Err(JournalError::Backend {
                page: 0x1000,
                status: 99
            })
        );
        assert!(rows[0].is_claimed());
        assert!(!journal.is_complete());
        io.0.borrow_mut().fail = None;
        journal.retire(id, 2, &mut rows, |_| io.clone()).unwrap();
        assert!(rows.is_empty());
        assert!(journal.is_complete());
        for call in [Call::Unmap(11), Call::Delete(11), Call::Recycle(11)] {
            assert_eq!(
                io.0.borrow()
                    .calls
                    .iter()
                    .filter(|&&item| item == call)
                    .count(),
                if call == failure { 2 } else { 1 }
            );
        }
        let calls = io.0.borrow().calls.len();
        journal.retire(id, 2, &mut rows, |_| io.clone()).unwrap();
        assert_eq!(io.0.borrow().calls.len(), calls);
    }
}

#[test]
fn partial_retirement_tracks_pages_after_swap_remove_and_allows_recycled_slot_reuse() {
    let io = Io::default();
    let mut rows = vec![
        live(0x1000, 11, &io),
        live(0xb000, 13, &io),
        live(0x2000, 12, &io),
    ];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    journal.claim(id, 2, &mut rows).unwrap();
    io.0.borrow_mut().fail = Some(Call::Delete(12));
    assert!(journal.retire(id, 2, &mut rows, |_| io.clone()).is_err());
    assert_eq!(rows[0].page(), 0x2000);
    rows.push(live(0xc000, 11, &io));
    journal.revalidate(id, 2, &rows).unwrap();
    assert_eq!(
        journal.original_capabilities().collect::<Vec<_>>(),
        vec![11, 12]
    );
    io.0.borrow_mut().fail = None;
    journal.retire(id, 2, &mut rows, |_| io.clone()).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|row| !row.is_claimed() && row.live().is_some()));
}

#[test]
fn pending_deleted_slot_still_participates_in_collision_checks() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io)];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    journal.claim(id, 2, &mut rows).unwrap();
    io.0.borrow_mut().fail = Some(Call::Recycle(11));
    assert!(journal.retire(id, 2, &mut rows, |_| io.clone()).is_err());
    rows.push(live(0xb000, 11, &io));
    assert_eq!(
        journal.revalidate(id, 2, &rows),
        Err(JournalError::SharedCapability(11))
    );
}

#[test]
fn failed_copy_slot_is_recycled_without_delete_or_unmap() {
    let io = Io::default();
    io.0.borrow_mut().fail = Some(Call::Recycle(11));
    let mut row = ThreadAliasMapping::new(0x1000).unwrap();
    assert_eq!(
        row.replace(
            1,
            &mut Setup {
                io: io.clone(),
                cap: 11,
                copy_status: 9
            }
        ),
        Err(9)
    );
    let mut rows = vec![row];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 2, &rows).unwrap();
    journal.claim(id, 2, &mut rows).unwrap();
    io.0.borrow_mut().fail = None;
    journal.retire(id, 2, &mut rows, |_| io.clone()).unwrap();
    assert_eq!(
        io.0.borrow().calls,
        vec![Call::Recycle(11), Call::Recycle(11)]
    );
}

#[test]
fn empty_coverage_completes_without_touching_other_process_attachment() {
    let io = Io::default();
    let mut rows = vec![live(0x1000, 11, &io)];
    let id = id();
    let journal = ThreadAliasJournal::prepare(id, layout(), 3, &rows).unwrap();
    journal.claim(id, 3, &mut rows).unwrap();
    journal.retire(id, 3, &mut rows, |_| io.clone()).unwrap();
    assert!(journal.is_complete());
    assert!(!rows[0].is_claimed());
    assert!(io.0.borrow().calls.is_empty());
}
