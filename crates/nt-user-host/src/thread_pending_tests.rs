use super::*;
use crate::thread_rollback::ThreadRollbackResourceKind;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;

fn identity() -> ThreadRollbackIdentity {
    ThreadRollbackIdentity {
        pi: 27,
        pid: 90,
        process_generation: crate::process_identity::ProcessGeneration::Hosted(7),
        tid: 301,
    }
}

fn reservations() -> ThreadRuntimeReservations {
    ThreadRuntimeReservations {
        badge: 526,
        pool_slot: 4,
        window_slot: Some(19),
    }
}

struct Runtime {
    drops: Rc<Cell<usize>>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn owner() -> (PendingThreadRuntime<Runtime>, Rc<Cell<usize>>) {
    let drops = Rc::new(Cell::new(0));
    let runtime = Runtime {
        drops: drops.clone(),
    };
    match PendingThreadRuntime::retain(identity(), 10, reservations(), runtime) {
        Ok(owner) => (owner, drops),
        Err(_) => panic!("valid admission failed"),
    }
}

fn resources() -> [ThreadRollbackResource; 3] {
    use ThreadRollbackResourceKind::*;
    [
        ThreadRollbackResource {
            cap: 200,
            kind: Frame,
        },
        ThreadRollbackResource {
            cap: 300,
            kind: Mechanism,
        },
        ThreadRollbackResource {
            cap: 100,
            kind: Alias,
        },
    ]
}

struct Backend {
    current: ThreadRollbackId,
    held: bool,
    calls: Vec<usize>,
    successes: Vec<usize>,
    fail: Option<usize>,
    drops: Rc<Cell<usize>>,
}

impl Backend {
    fn new(owner: &PendingThreadRuntime<Runtime>, drops: Rc<Cell<usize>>) -> Self {
        Self {
            current: owner.id(),
            held: true,
            calls: Vec::new(),
            successes: Vec::new(),
            fail: None,
            drops,
        }
    }

    fn effect(&mut self, step: usize) -> Result<(), u32> {
        assert_eq!(
            self.drops.get(),
            0,
            "runtime dropped before backend acknowledgement"
        );
        assert!(self.held);
        self.calls.push(step);
        if self.fail == Some(step) {
            return Err(0xc000_009a);
        }
        assert_eq!(
            self.successes.len(),
            step,
            "repeated or out-of-order effect"
        );
        self.successes.push(step);
        Ok(())
    }
}

impl ThreadRollbackIo for Backend {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.current == id && self.held
    }

    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert_eq!(tcb, 10);
        self.effect(0)
    }

    fn delete_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert_eq!(tcb, 10);
        self.effect(1)
    }

    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        assert_eq!(id, self.current);
        self.effect(2)
    }

    fn release_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        let (step, expected) = match resource.kind {
            ThreadRollbackResourceKind::Alias => (3, 100),
            ThreadRollbackResourceKind::Mechanism => (4, 300),
            ThreadRollbackResourceKind::Frame => (5, 200),
        };
        assert_eq!(resource.cap, expected);
        self.effect(step)
    }

    fn commit_rollback(&mut self, id: ThreadRollbackId) {
        assert_eq!(id, self.current);
        self.effect(6).unwrap();
        self.held = false;
    }
}

#[test]
fn admission_retains_nonclone_payload_and_exact_reservations_without_a_journal() {
    let (owner, drops) = owner();
    assert!(Rc::ptr_eq(&owner.runtime().drops, &drops));
    assert_eq!(owner.id().identity(), identity());
    assert_eq!(owner.reservations(), reservations());
    assert!(owner.cleanup().is_none());
    assert_eq!(drops.get(), 0);
}

#[test]
fn invalid_identity_returns_original_payload() {
    for invalid in [
        ThreadRollbackIdentity {
            pid: 0,
            ..identity()
        },
        ThreadRollbackIdentity {
            tid: 0,
            ..identity()
        },
        ThreadRollbackIdentity {
            process_generation: crate::process_identity::ProcessGeneration::Hosted(0),
            ..identity()
        },
    ] {
        let drops = Rc::new(Cell::new(0));
        let runtime = Runtime {
            drops: drops.clone(),
        };
        let (error, runtime) =
            match PendingThreadRuntime::retain(invalid, 10, reservations(), runtime) {
                Err(error) => error,
                Ok(_) => panic!("invalid identity admitted"),
            };
        assert_eq!(error, ThreadRollbackError::InvalidIdentity);
        assert!(Rc::ptr_eq(&runtime.drops, &drops));
        assert_eq!(drops.get(), 0);
        drop(runtime);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn invalid_tcb_returns_original_payload() {
    for tcb in [0, 1] {
        let runtime = alloc::boxed::Box::new(42);
        let ptr = &*runtime as *const i32;
        match PendingThreadRuntime::retain(identity(), tcb, reservations(), runtime) {
            Err((error, runtime)) => {
                assert_eq!(error, ThreadRollbackError::InvalidCapability);
                assert_eq!(&*runtime as *const i32, ptr);
            }
            Ok(_) => panic!("invalid TCB admitted"),
        }
    }
}

#[test]
fn reservations_are_captured_values_not_native_table_bounds() {
    let holds = ThreadRuntimeReservations {
        badge: 0,
        pool_slot: usize::MAX,
        window_slot: None,
    };
    let owner = match PendingThreadRuntime::retain(identity(), 10, holds, ()) {
        Ok(owner) => owner,
        Err(_) => panic!("host owner must not invent native slot limits"),
    };
    assert_eq!(owner.reservations(), holds);
}

#[test]
fn preparation_preserves_retained_attempt_identity() {
    let (mut owner, _) = owner();
    let id = owner.id();
    owner.prepare_journal(&resources()).unwrap();
    assert_eq!(owner.id(), id);
    assert_eq!(owner.cleanup().unwrap().id(), id);
    assert_eq!(owner.cleanup().unwrap().pending_tcb(), Some(10));
    assert_eq!(owner.cleanup().unwrap().pending_resources().count(), 3);
}

#[test]
fn journal_allocation_failure_preserves_owner_for_same_attempt_retry() {
    let (mut owner, drops) = owner();
    let id = owner.id();
    for _ in 0..3 {
        assert_eq!(
            owner.prepare_journal_with(&resources(), |actual, tcb, inventory| {
                assert_eq!(actual, id);
                assert_eq!(tcb, 10);
                assert_eq!(inventory, resources());
                Err(ThreadRollbackError::InsufficientResources)
            }),
            Err(ThreadRollbackError::InsufficientResources)
        );
        assert_eq!(owner.id(), id);
        assert_eq!(owner.reservations(), reservations());
        assert!(owner.cleanup().is_none());
        assert_eq!(drops.get(), 0);
    }
    owner.prepare_journal(&resources()).unwrap();
    assert_eq!(owner.cleanup().unwrap().id(), id);
}

#[test]
fn invalid_inventory_preserves_owner_for_retry() {
    let (mut owner, drops) = owner();
    let id = owner.id();
    assert_eq!(
        owner.prepare_journal(&[ThreadRollbackResource {
            cap: 10,
            kind: ThreadRollbackResourceKind::Frame,
        }]),
        Err(ThreadRollbackError::ConflictingOwnership)
    );
    assert!(owner.cleanup().is_none());
    assert_eq!(owner.reservations(), reservations());
    assert_eq!(drops.get(), 0);
    owner.prepare_journal(&resources()).unwrap();
    assert_eq!(owner.cleanup().unwrap().id(), id);
}

#[test]
fn unprepared_owner_cannot_advance_or_release_payload() {
    let (mut owner, drops) = owner();
    let mut io = Backend::new(&owner, drops.clone());
    assert_eq!(
        owner.advance(&mut io),
        Err(ThreadRollbackError::NotPrepared)
    );
    assert!(io.calls.is_empty());
    let retained = match owner.try_into_retired_payload() {
        Err(owner) => owner,
        Ok(_) => panic!("unprepared payload released"),
    };
    assert_eq!(retained.id(), io.current);
    assert_eq!(retained.reservations(), reservations());
    assert_eq!(drops.get(), 0);
}

#[test]
fn every_cleanup_failure_retains_payload_reservations_and_retry_progress() {
    for failure in 0..6 {
        let (mut owner, drops) = owner();
        owner.prepare_journal(&resources()).unwrap();
        let mut io = Backend::new(&owner, drops.clone());
        io.fail = Some(failure);
        for _ in 0..3 {
            assert!(matches!(
                owner.advance(&mut io),
                Err(ThreadRollbackError::Backend { .. })
            ));
            owner = match owner.try_into_retired_payload() {
                Err(owner) => owner,
                Ok(_) => panic!("partially cleaned payload released"),
            };
            assert_eq!(owner.id(), io.current);
            assert_eq!(owner.reservations(), reservations());
            assert!(io.held);
            assert_eq!(io.successes, (0..failure).collect::<Vec<_>>());
            assert_eq!(drops.get(), 0);
        }
        io.fail = None;
        owner.advance(&mut io).unwrap();
        assert_eq!(io.successes, (0..7).collect::<Vec<_>>());
        assert!(!io.held);
        let runtime = match owner.try_into_retired_payload() {
            Ok(runtime) => runtime,
            Err(_) => panic!("completed payload retained"),
        };
        assert_eq!(drops.get(), 0);
        drop(runtime);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn duplicate_preparation_cannot_reset_partial_progress() {
    let (mut owner, drops) = owner();
    owner.prepare_journal(&resources()).unwrap();
    let mut io = Backend::new(&owner, drops);
    io.fail = Some(4);
    assert!(owner.advance(&mut io).is_err());
    let stage = owner.cleanup().unwrap().stage();
    let pending = owner
        .cleanup()
        .unwrap()
        .pending_resources()
        .collect::<Vec<_>>();
    assert_eq!(
        owner.prepare_journal_with(&[], |_, _, _| panic!("builder called twice")),
        Err(ThreadRollbackError::AlreadyPrepared)
    );
    assert_eq!(owner.cleanup().unwrap().stage(), stage);
    assert_eq!(
        owner
            .cleanup()
            .unwrap()
            .pending_resources()
            .collect::<Vec<_>>(),
        pending
    );
    io.fail = None;
    owner.advance(&mut io).unwrap();
}

#[test]
fn reused_identity_cannot_drive_an_older_attempt() {
    let (mut old, drops) = owner();
    let (new, _) = owner();
    assert_eq!(old.id().identity(), new.id().identity());
    assert_ne!(old.id(), new.id());
    old.prepare_journal(&resources()).unwrap();
    let mut io = Backend::new(&new, drops);
    assert_eq!(old.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
    assert!(io.calls.is_empty());
    assert_eq!(old.cleanup().unwrap().pending_resources().count(), 3);
}

#[test]
fn missing_reservation_rejects_cleanup_without_effects() {
    let (mut owner, drops) = owner();
    owner.prepare_journal(&resources()).unwrap();
    let mut io = Backend::new(&owner, drops);
    io.held = false;
    assert_eq!(owner.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
    assert!(io.calls.is_empty());
}

#[test]
fn completion_is_idempotent_and_retains_payload_through_commit() {
    let (mut owner, drops) = owner();
    owner.prepare_journal(&resources()).unwrap();
    let mut io = Backend::new(&owner, drops.clone());
    owner.advance(&mut io).unwrap();
    let calls = io.calls.clone();
    owner.advance(&mut io).unwrap();
    assert_eq!(io.calls, calls);
    assert_eq!(
        owner.cleanup().unwrap().stage(),
        ThreadRollbackStage::Complete
    );
    assert_eq!(drops.get(), 0);
    assert_eq!(
        owner.prepare_journal(&resources()),
        Err(ThreadRollbackError::AlreadyPrepared)
    );
    let runtime = match owner.try_into_retired_payload() {
        Ok(runtime) => runtime,
        Err(_) => panic!("completed payload retained"),
    };
    drop(runtime);
    assert_eq!(drops.get(), 1);
}

#[test]
fn stale_owner_at_each_partial_stage_preserves_progress_for_exact_owner_retry() {
    for failure in 0..6 {
        let (mut owner, drops) = owner();
        owner.prepare_journal(&resources()).unwrap();
        let mut io = Backend::new(&owner, drops.clone());
        io.fail = Some(failure);
        assert!(owner.advance(&mut io).is_err());
        let stage = owner.cleanup().unwrap().stage();
        let pending = owner
            .cleanup()
            .unwrap()
            .pending_resources()
            .collect::<Vec<_>>();
        let calls = io.calls.clone();
        let exact = io.current;
        io.current = new_rollback_id(identity()).unwrap();
        io.fail = None;
        assert_eq!(owner.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
        assert_eq!(owner.id(), exact);
        assert_eq!(owner.cleanup().unwrap().stage(), stage);
        assert_eq!(
            owner
                .cleanup()
                .unwrap()
                .pending_resources()
                .collect::<Vec<_>>(),
            pending
        );
        assert_eq!(owner.reservations(), reservations());
        assert_eq!(io.calls, calls);
        assert_eq!(drops.get(), 0);
        io.current = exact;
        owner.advance(&mut io).unwrap();
        assert_eq!(io.successes, (0..7).collect::<Vec<_>>());
    }
}
