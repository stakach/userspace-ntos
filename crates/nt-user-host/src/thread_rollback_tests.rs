use super::*;
use alloc::vec;

fn identity() -> ThreadRollbackIdentity {
    ThreadRollbackIdentity {
        pi: 27,
        pid: 90,
        process_generation: 7,
        tid: 301,
    }
}

fn resource(cap: u64, kind: ThreadRollbackResourceKind) -> ThreadRollbackResource {
    ThreadRollbackResource { cap, kind }
}

fn resources() -> Vec<ThreadRollbackResource> {
    use ThreadRollbackResourceKind::*;
    // Deliberately not stage ordered, as runtime and registry fields are not stage ordered.
    vec![
        resource(200, Frame),
        resource(300, Mechanism),
        resource(100, Alias),
        resource(101, Alias),
        resource(201, Frame),
        resource(301, Mechanism),
        resource(102, Alias),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Suspend(u64),
    Delete(u64),
    Revoke,
    Release(ThreadRollbackResource),
    Commit,
}

struct Backend {
    current: ThreadRollbackId,
    calls: Vec<Event>,
    successes: Vec<Event>,
    fail: Option<Event>,
    suspended: bool,
    tcb_deleted: bool,
    excluded: bool,
    pool_held: bool,
    window_held: bool,
    charge: usize,
    commits: usize,
}

impl Backend {
    fn new(current: ThreadRollbackId) -> Self {
        Self {
            current,
            calls: Vec::new(),
            successes: Vec::new(),
            fail: None,
            suspended: false,
            tcb_deleted: false,
            excluded: false,
            pool_held: true,
            window_held: true,
            charge: 8192,
            commits: 0,
        }
    }

    fn attempt(&mut self, event: Event) -> Result<(), u32> {
        self.calls.push(event);
        if self.fail == Some(event) {
            return Err(0xc000_009a);
        }
        assert!(
            !self.successes.contains(&event),
            "repeated effect: {event:?}"
        );
        self.successes.push(event);
        Ok(())
    }
}

impl ThreadRollbackIo for Backend {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.current == id && self.pool_held && self.window_held
    }

    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert!(!self.tcb_deleted);
        self.attempt(Event::Suspend(tcb))?;
        self.suspended = true;
        Ok(())
    }

    fn delete_tcb(&mut self, tcb: u64) -> Result<(), u32> {
        assert!(self.suspended);
        self.attempt(Event::Delete(tcb))?;
        self.tcb_deleted = true;
        Ok(())
    }

    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        assert_eq!(id, self.current);
        assert!(self.tcb_deleted);
        self.attempt(Event::Revoke)?;
        self.excluded = true;
        Ok(())
    }

    fn release_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        assert!(self.tcb_deleted && self.excluded && self.pool_held && self.window_held);
        assert_eq!(self.charge, 8192);
        self.attempt(Event::Release(resource))
    }

    fn commit_rollback(&mut self, id: ThreadRollbackId) {
        assert_eq!(id, self.current);
        assert!(self.tcb_deleted && self.excluded);
        self.attempt(Event::Commit).unwrap();
        self.pool_held = false;
        self.window_held = false;
        self.charge = 0;
        self.commits += 1;
    }
}

fn expected_events() -> Vec<Event> {
    use ThreadRollbackResourceKind::*;
    vec![
        Event::Suspend(10),
        Event::Delete(10),
        Event::Revoke,
        Event::Release(resource(100, Alias)),
        Event::Release(resource(101, Alias)),
        Event::Release(resource(102, Alias)),
        Event::Release(resource(300, Mechanism)),
        Event::Release(resource(301, Mechanism)),
        Event::Release(resource(200, Frame)),
        Event::Release(resource(201, Frame)),
        Event::Commit,
    ]
}

fn stage_for(event: Event) -> ThreadRollbackStage {
    use ThreadRollbackResourceKind::*;
    match event {
        Event::Suspend(_) => ThreadRollbackStage::Suspend,
        Event::Delete(_) => ThreadRollbackStage::DeleteTcb,
        Event::Revoke => ThreadRollbackStage::RevokeMemoryAccess,
        Event::Release(ThreadRollbackResource { kind: Alias, .. }) => ThreadRollbackStage::Aliases,
        Event::Release(ThreadRollbackResource { kind: Frame, .. }) => ThreadRollbackStage::Frames,
        Event::Release(ThreadRollbackResource {
            kind: Mechanism, ..
        }) => ThreadRollbackStage::Mechanism,
        Event::Commit => ThreadRollbackStage::Commit,
    }
}

#[test]
fn cleanup_is_stage_ordered_and_commits_target_ownership_once() {
    let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    assert!(io.calls.is_empty());
    assert_eq!(owner.pending_tcb(), Some(10));
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
    assert_eq!(owner.stage(), ThreadRollbackStage::Complete);
    assert_eq!(owner.pending_tcb(), None);
    assert_eq!(owner.pending_resources().count(), 0);
    assert!(!io.pool_held && !io.window_held);
    assert_eq!((io.charge, io.commits), (0, 1));
    let calls = io.calls.clone();
    io.current.identity.process_generation += 1;
    owner.advance(&mut io).unwrap();
    assert_eq!(io.calls, calls);
    assert_eq!(io.commits, 1);
}

#[test]
fn every_backend_failure_retains_exact_pending_caps_and_reservations() {
    let expected = expected_events();
    for (index, &failure) in expected[..expected.len() - 1].iter().enumerate() {
        let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
        let mut io = Backend::new(owner.id());
        io.fail = Some(failure);
        for _ in 0..3 {
            assert_eq!(
                owner.advance(&mut io),
                Err(ThreadRollbackError::Backend {
                    stage: stage_for(failure),
                    status: 0xc000_009a,
                })
            );
            assert_eq!(owner.stage(), stage_for(failure));
            assert_eq!(io.successes, expected[..index]);
            assert!(io.pool_held && io.window_held);
            assert_eq!((io.charge, io.commits), (8192, 0));
            assert_eq!(
                owner.pending_tcb(),
                if index <= 1 { Some(10) } else { None }
            );
            let pending: Vec<_> = resources()
                .into_iter()
                .filter(|&entry| !io.successes.contains(&Event::Release(entry)))
                .collect();
            assert_eq!(owner.pending_resources().collect::<Vec<_>>(), pending);
        }
        io.fail = None;
        owner.advance(&mut io).unwrap();
        assert_eq!(io.successes, expected);
        assert_eq!(io.commits, 1);
    }
}

#[test]
fn stale_identity_refuses_all_effects_at_every_retry_stage() {
    for failure in expected_events()
        .into_iter()
        .filter(|event| *event != Event::Commit)
    {
        let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
        let mut io = Backend::new(owner.id());
        io.fail = Some(failure);
        assert!(owner.advance(&mut io).is_err());
        let calls = io.calls.clone();
        let pending = owner.pending_resources().collect::<Vec<_>>();
        for replacement in [
            ThreadRollbackIdentity {
                pi: 28,
                ..identity()
            },
            ThreadRollbackIdentity {
                pid: 91,
                ..identity()
            },
            ThreadRollbackIdentity {
                process_generation: 8,
                ..identity()
            },
            ThreadRollbackIdentity {
                tid: 302,
                ..identity()
            },
        ] {
            io.current.identity = replacement;
            assert_eq!(owner.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
            assert_eq!(io.calls, calls);
            assert_eq!(owner.pending_resources().collect::<Vec<_>>(), pending);
        }
        io.current = owner.id();
        io.fail = None;
        owner.advance(&mut io).unwrap();
    }
}

#[test]
fn missing_target_reservation_refuses_cleanup() {
    for pool_missing in [true, false] {
        let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
        let mut io = Backend::new(owner.id());
        if pool_missing {
            io.pool_held = false;
        } else {
            io.window_held = false;
        }
        assert_eq!(owner.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
        assert!(io.calls.is_empty());
    }
}

#[test]
fn repeated_registry_runtime_caps_are_retired_once() {
    let mut entries = resources();
    entries.extend(resources());
    entries.push(resource(0, ThreadRollbackResourceKind::Frame));
    let mut owner = ThreadRollback::prepare(identity(), 10, &entries).unwrap();
    assert_eq!(owner.pending_resources().count(), resources().len());
    let mut io = Backend::new(owner.id());
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
}

#[test]
fn conflicting_cap_classes_and_tcb_overlap_are_rejected_before_adoption() {
    use ThreadRollbackResourceKind::*;
    for (a, b) in [
        (Frame, Alias),
        (Alias, Frame),
        (Mechanism, Frame),
        (Alias, Mechanism),
    ] {
        let entries = [resource(100, a), resource(100, b)];
        assert!(matches!(
            ThreadRollback::prepare(identity(), 10, &entries),
            Err(ThreadRollbackError::ConflictingOwnership)
        ));
    }
    for kind in [Frame, Alias, Mechanism] {
        assert!(matches!(
            ThreadRollback::prepare(identity(), 10, &[resource(10, kind)]),
            Err(ThreadRollbackError::ConflictingOwnership)
        ));
    }
}

#[test]
fn invalid_identities_and_tcb_sentinels_cannot_own_rollback() {
    for id in [
        ThreadRollbackIdentity {
            pid: 0,
            ..identity()
        },
        ThreadRollbackIdentity {
            tid: 0,
            ..identity()
        },
        ThreadRollbackIdentity {
            process_generation: 0,
            ..identity()
        },
    ] {
        assert!(matches!(
            ThreadRollback::prepare(id, 10, &[]),
            Err(ThreadRollbackError::InvalidIdentity)
        ));
    }
    for tcb in [0, 1] {
        assert!(matches!(
            ThreadRollback::prepare(identity(), tcb, &[]),
            Err(ThreadRollbackError::InvalidCapability)
        ));
    }
}

#[test]
fn empty_resource_set_still_requires_tcb_deletion_and_memory_exclusion() {
    let mut owner = ThreadRollback::prepare(identity(), 10, &[]).unwrap();
    let mut io = Backend::new(owner.id());
    owner.advance(&mut io).unwrap();
    assert_eq!(
        io.successes,
        [
            Event::Suspend(10),
            Event::Delete(10),
            Event::Revoke,
            Event::Commit
        ]
    );
}

#[test]
fn deleted_tcb_slot_can_be_reused_without_being_touched_by_retry() {
    let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::Revoke);
    assert!(owner.advance(&mut io).is_err());
    assert_eq!(owner.pending_tcb(), None);
    let boundary = io.calls.len();
    io.fail = None;
    owner.advance(&mut io).unwrap();
    assert!(!io.calls[boundary..]
        .iter()
        .any(|event| matches!(event, Event::Suspend(_) | Event::Delete(_))));
}

#[test]
fn released_alias_slots_are_not_deleted_again_after_later_failure() {
    use ThreadRollbackResourceKind::*;
    let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::Release(resource(201, Frame)));
    assert!(owner.advance(&mut io).is_err());
    let boundary = io.calls.len();
    io.fail = None;
    owner.advance(&mut io).unwrap();
    assert_eq!(
        io.calls[boundary..],
        [Event::Release(resource(201, Frame)), Event::Commit]
    );
}

#[test]
fn pooled_tid_reuse_requires_a_new_attempt_owner_at_every_retry_stage() {
    for failure in expected_events()
        .into_iter()
        .filter(|event| *event != Event::Commit)
    {
        let mut old = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
        let mut io = Backend::new(old.id());
        io.fail = Some(failure);
        assert!(old.advance(&mut io).is_err());
        let replacement = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
        assert_eq!(old.identity(), replacement.identity());
        assert_ne!(old.id(), replacement.id());
        io.current = replacement.id();
        let calls = io.calls.clone();
        let pending = old.pending_resources().collect::<Vec<_>>();
        assert_eq!(old.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
        assert_eq!(io.calls, calls);
        assert_eq!(old.pending_resources().collect::<Vec<_>>(), pending);
        io.current = old.id();
        io.fail = None;
        old.advance(&mut io).unwrap();
        let mut next_io = Backend::new(replacement.id());
        old.advance(&mut next_io).unwrap();
        assert!(next_io.calls.is_empty());
    }
}

#[test]
fn attempt_exhaustion_never_wraps_or_reuses_an_identity() {
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_attempt(&counter), Ok(u64::MAX - 1));
    for _ in 0..3 {
        assert_eq!(
            allocate_attempt(&counter),
            Err(ThreadRollbackError::InsufficientResources)
        );
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}

#[test]
fn mechanism_failure_preserves_all_physical_frame_owners() {
    use ThreadRollbackResourceKind::*;
    let mut owner = ThreadRollback::prepare(identity(), 10, &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::Release(resource(301, Mechanism)));
    assert!(owner.advance(&mut io).is_err());
    assert!(!io.calls.iter().any(|event| matches!(
        event,
        Event::Release(ThreadRollbackResource { kind: Frame, .. })
    )));
    assert_eq!(
        owner
            .pending_resources()
            .filter(|entry| entry.kind == Frame)
            .count(),
        2
    );
    io.fail = None;
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
}

#[test]
fn backend_failure_status_is_preserved() {
    struct Failing;
    impl ThreadRollbackIo for Failing {
        fn is_current(&self, _: ThreadRollbackId) -> bool {
            true
        }
        fn suspend_tcb(&mut self, _: u64) -> Result<(), u32> {
            Err(0xc000_0001)
        }
        fn delete_tcb(&mut self, _: u64) -> Result<(), u32> {
            panic!()
        }
        fn revoke_memory_access(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
            panic!()
        }
        fn release_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
            panic!()
        }
        fn commit_rollback(&mut self, _: ThreadRollbackId) {
            panic!()
        }
    }
    let mut owner = ThreadRollback::prepare(identity(), 10, &[]).unwrap();
    assert_eq!(
        owner.advance(&mut Failing),
        Err(ThreadRollbackError::Backend {
            stage: ThreadRollbackStage::Suspend,
            status: 0xc000_0001,
        })
    );
}
