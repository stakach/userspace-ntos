use super::*;
use alloc::vec;

#[test]
fn temporary_generation_zero_is_not_a_cleanup_identity() {
    assert!(matches!(
        ThreadRollback::prepare(
            ThreadRollbackIdentity {
                process_generation: ProcessGeneration::Temporary(0),
                ..identity()
            },
            &[]
        ),
        Err(ThreadRollbackError::InvalidIdentity)
    ));
}

#[test]
fn cleanup_identity_retains_process_generation_domain() {
    let mut rollback = ThreadRollback::prepare(
        ThreadRollbackIdentity {
            process_generation: ProcessGeneration::Temporary(7),
            ..identity()
        },
        &resources(),
    )
    .unwrap();
    let mut io = Backend::new(rollback.id());
    io.current.identity.process_generation = ProcessGeneration::Hosted(7);
    assert_eq!(
        rollback.advance(&mut io),
        Err(ThreadRollbackError::StaleOwner)
    );
    assert!(io.calls.is_empty());
    io.current = rollback.id();
    rollback.advance(&mut io).unwrap();
}

fn identity() -> ThreadRollbackIdentity {
    ThreadRollbackIdentity {
        pi: 27,
        pid: 90,
        process_generation: ProcessGeneration::Hosted(7),
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
    Revoke,
    Unmap(ThreadRollbackResource),
    DeleteResource(ThreadRollbackResource),
    // Final allocator transfer, separate from capability deletion.
    Release(ThreadRollbackResource),
    FinishTransfers,
    Commit,
}

struct Backend {
    current: ThreadRollbackId,
    calls: Vec<Event>,
    successes: Vec<Event>,
    fail: Option<Event>,
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

    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        assert_eq!(id, self.current);
        self.attempt(Event::Revoke)?;
        self.excluded = true;
        Ok(())
    }

    fn unmap_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        assert!(self.excluded && self.pool_held && self.window_held);
        assert_ne!(resource.kind, ThreadRollbackResourceKind::Mechanism);
        self.attempt(Event::Unmap(resource))
    }

    fn delete_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        assert!(self.excluded && self.pool_held && self.window_held);
        assert_ne!(resource.kind, ThreadRollbackResourceKind::Frame);
        assert!(
            resource.kind == ThreadRollbackResourceKind::Mechanism
                || self.successes.contains(&Event::Unmap(resource))
        );
        self.attempt(Event::DeleteResource(resource))
    }

    fn recycle_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
        assert!(self.excluded && self.pool_held && self.window_held);
        assert_eq!(self.charge, 8192);
        assert!(
            resource.kind == ThreadRollbackResourceKind::Frame
                || self.successes.contains(&Event::DeleteResource(resource))
        );
        assert!(
            resource.kind == ThreadRollbackResourceKind::Mechanism
                || self.successes.contains(&Event::Unmap(resource))
        );
        self.attempt(Event::Release(resource))
    }

    fn finish_memory_transfers(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
        assert_eq!(id, self.current);
        assert!(self.pool_held && self.window_held && self.commits == 0);
        self.attempt(Event::FinishTransfers)
    }

    fn commit_rollback(&mut self, id: ThreadRollbackId) {
        assert_eq!(id, self.current);
        assert!(self.excluded);
        assert!(self.successes.contains(&Event::FinishTransfers));
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
        Event::Revoke,
        Event::Unmap(resource(100, Alias)),
        Event::DeleteResource(resource(100, Alias)),
        Event::Release(resource(100, Alias)),
        Event::Unmap(resource(101, Alias)),
        Event::DeleteResource(resource(101, Alias)),
        Event::Release(resource(101, Alias)),
        Event::Unmap(resource(102, Alias)),
        Event::DeleteResource(resource(102, Alias)),
        Event::Release(resource(102, Alias)),
        Event::DeleteResource(resource(300, Mechanism)),
        Event::Release(resource(300, Mechanism)),
        Event::DeleteResource(resource(301, Mechanism)),
        Event::Release(resource(301, Mechanism)),
        Event::Unmap(resource(200, Frame)),
        Event::Release(resource(200, Frame)),
        Event::Unmap(resource(201, Frame)),
        Event::Release(resource(201, Frame)),
        Event::FinishTransfers,
        Event::Commit,
    ]
}

#[test]
fn alias_unmap_failure_blocks_all_backing_and_preserves_completed_cap_progress() {
    use ThreadRollbackResourceKind::*;
    let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::Unmap(resource(101, Alias)));
    assert!(owner.advance(&mut io).is_err());
    assert!(!io.calls.iter().any(|event| matches!(
        event,
        Event::Unmap(ThreadRollbackResource { kind: Frame, .. })
            | Event::Release(ThreadRollbackResource { kind: Frame, .. })
    )));
    assert!(owner
        .pending_resources()
        .any(|entry| entry == resource(101, Alias)));
    assert!(!owner
        .pending_resources()
        .any(|entry| entry == resource(100, Alias)));
    io.fail = None;
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
}

#[test]
fn failed_alias_and_frame_recycle_never_replay_acknowledged_unmap() {
    use ThreadRollbackResourceKind::*;
    for failed in [resource(101, Alias), resource(201, Frame)] {
        let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
        let mut io = Backend::new(owner.id());
        io.fail = Some(Event::Release(failed));
        for _ in 0..3 {
            assert!(owner.advance(&mut io).is_err());
        }
        assert_eq!(
            io.calls
                .iter()
                .filter(|&&event| event == Event::Unmap(failed))
                .count(),
            1
        );
        assert!(owner.pending_resources().any(|entry| entry == failed));
        assert!(io.pool_held && io.window_held);
        io.fail = None;
        owner.advance(&mut io).unwrap();
        assert_eq!(io.successes, expected_events());
    }
}

#[test]
fn delete_failure_retains_resource_and_blocks_recycle_until_acknowledged() {
    use ThreadRollbackResourceKind::*;
    for failed in [resource(101, Alias), resource(300, Mechanism)] {
        let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
        let mut io = Backend::new(owner.id());
        io.fail = Some(Event::DeleteResource(failed));
        for _ in 0..3 {
            assert!(owner.advance(&mut io).is_err());
        }
        assert!(!io.calls.contains(&Event::Release(failed)));
        assert!(owner.pending_resources().any(|entry| entry == failed));
        assert_eq!(
            io.calls
                .iter()
                .filter(|&&e| e == Event::Unmap(failed))
                .count(),
            usize::from(failed.kind == Alias)
        );
        io.fail = None;
        owner.advance(&mut io).unwrap();
        assert_eq!(io.successes, expected_events());
        assert_eq!(io.commits, 1);
    }
}

#[test]
fn recycle_failure_does_not_repeat_delete_or_unmap_for_any_resource_kind() {
    use ThreadRollbackResourceKind::*;
    for failed in [
        resource(101, Alias),
        resource(300, Mechanism),
        resource(200, Frame),
    ] {
        let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
        let mut io = Backend::new(owner.id());
        io.fail = Some(Event::Release(failed));
        for _ in 0..3 {
            assert!(owner.advance(&mut io).is_err());
        }
        assert_eq!(
            io.calls
                .iter()
                .filter(|&&e| e == Event::DeleteResource(failed))
                .count(),
            usize::from(failed.kind != Frame)
        );
        assert_eq!(
            io.calls
                .iter()
                .filter(|&&e| e == Event::Unmap(failed))
                .count(),
            usize::from(failed.kind != Mechanism)
        );
        assert!(owner.pending_resources().any(|entry| entry == failed));
        assert!(io.pool_held && io.window_held && io.commits == 0);
        io.fail = None;
        owner.advance(&mut io).unwrap();
        assert_eq!(io.successes, expected_events());
        assert!(!io.calls.iter().any(|event| matches!(
            event,
            Event::DeleteResource(ThreadRollbackResource { kind: Frame, .. })
        )));
    }
}

#[test]
fn partial_registry_transfer_survives_failed_cap_cleanup_until_final_acknowledgement() {
    use crate::thread_registry::ThreadRegistrySnapshot;
    use crate::thread_resources::{ThreadMemoryLayout, ThreadMemoryResources};
    use nt_memory_manager::{ClientFrameRegistry, ClientFrameTransfer};
    use ThreadRollbackResourceKind::*;
    struct RegistryBackend<'a> {
        base: Backend,
        registry: &'a mut ClientFrameRegistry,
        transfer: Option<ClientFrameTransfer>,
    }
    impl ThreadRollbackIo for RegistryBackend<'_> {
        fn is_current(&self, id: ThreadRollbackId) -> bool {
            self.base.is_current(id)
        }

        fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
            self.base.revoke_memory_access(id)
        }
        fn unmap_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
            self.base.unmap_resource(resource)
        }
        fn delete_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
            assert!(self.transfer.is_some());
            self.base.delete_resource(resource)
        }
        fn recycle_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32> {
            assert!(self.transfer.is_some());
            self.base.recycle_resource(resource)
        }
        fn finish_memory_transfers(&mut self, id: ThreadRollbackId) -> Result<(), u32> {
            assert!(self.base.pool_held && self.base.window_held);
            self.base.finish_memory_transfers(id)?;
            self.registry
                .finish_transfer(self.transfer.take().unwrap())
                .unwrap();
            assert!(self.registry.is_process_empty(id.identity().pi as u64));
            Ok(())
        }
        fn commit_rollback(&mut self, id: ThreadRollbackId) {
            assert!(self.transfer.is_none());
            self.base.commit_rollback(id);
        }
    }
    let mut memory = ThreadMemoryResources::<2>::new(
        identity().pi,
        ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x6000, 0xa000).unwrap(),
    )
    .unwrap();
    memory.stack_owner[0] = 200;
    memory.stack_target[0] = 100;
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert(identity().pi as u64, 0x1000, 100, 0, 0, 200, true)
        .unwrap();
    let snapshot = ThreadRegistrySnapshot::capture_partial(&memory, &registry, &[0x1000]).unwrap();
    let mut owner = ThreadRollback::prepare(identity(), snapshot.rollback_resources()).unwrap();
    let transfer = snapshot
        .prepare_transfer(&memory, &mut registry)
        .unwrap()
        .unwrap();
    let retained = transfer.records().to_vec();
    let mut io = RegistryBackend {
        base: Backend::new(owner.id()),
        registry: &mut registry,
        transfer: Some(transfer),
    };
    io.base.fail = Some(Event::Release(resource(100, Alias)));
    for _ in 0..3 {
        assert!(owner.advance(&mut io).is_err());
        assert_eq!(io.transfer.as_ref().unwrap().records(), retained.as_slice());
        assert!(!io
            .registry
            .get(identity().pi as u64, 0x1000)
            .unwrap()
            .is_resident());
        assert!(io.registry.take(identity().pi as u64, 0x1000).is_none());
        assert!(!io.base.calls.contains(&Event::Unmap(resource(200, Frame))));
        assert!(!io.registry.is_process_empty(identity().pi as u64));
    }
    io.base.fail = None;
    owner.advance(&mut io).unwrap();
    assert!(io.transfer.is_none());
    assert!(io.registry.is_process_empty(identity().pi as u64));
    assert!(!io.base.pool_held && !io.base.window_held);
    assert_eq!(
        io.base
            .calls
            .iter()
            .filter(|&&event| event == Event::Unmap(resource(100, Alias)))
            .count(),
        1
    );
}

fn stage_for(event: Event) -> ThreadRollbackStage {
    use ThreadRollbackResourceKind::*;
    match event {
        Event::Revoke => ThreadRollbackStage::RevokeMemoryAccess,
        Event::Release(ThreadRollbackResource { kind: Alias, .. })
        | Event::DeleteResource(ThreadRollbackResource { kind: Alias, .. })
        | Event::Unmap(ThreadRollbackResource { kind: Alias, .. }) => ThreadRollbackStage::Aliases,
        Event::Release(ThreadRollbackResource { kind: Frame, .. })
        | Event::Unmap(ThreadRollbackResource { kind: Frame, .. }) => ThreadRollbackStage::Frames,
        Event::Unmap(ThreadRollbackResource {
            kind: Mechanism, ..
        }) => panic!("mechanism unmap"),
        Event::DeleteResource(ThreadRollbackResource { kind: Frame, .. }) => {
            panic!("frame deletion")
        }
        Event::Release(ThreadRollbackResource {
            kind: Mechanism, ..
        })
        | Event::DeleteResource(ThreadRollbackResource {
            kind: Mechanism, ..
        }) => ThreadRollbackStage::Mechanism,
        Event::FinishTransfers => ThreadRollbackStage::FinishMemoryTransfers,
        Event::Commit => ThreadRollbackStage::Commit,
    }
}

#[test]
fn cleanup_is_stage_ordered_and_commits_target_ownership_once() {
    let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    assert!(io.calls.is_empty());
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
    assert_eq!(owner.stage(), ThreadRollbackStage::Complete);
    assert_eq!(owner.pending_resources().count(), 0);
    assert!(!io.pool_held && !io.window_held);
    assert_eq!((io.charge, io.commits), (0, 1));
    let calls = io.calls.clone();
    io.current.identity.process_generation = ProcessGeneration::Hosted(8);
    owner.advance(&mut io).unwrap();
    assert_eq!(io.calls, calls);
    assert_eq!(io.commits, 1);
}

#[test]
fn every_backend_failure_retains_exact_pending_caps_and_reservations() {
    let expected = expected_events();
    for (index, &failure) in expected[..expected.len() - 1].iter().enumerate() {
        let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
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
        let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
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
                process_generation: ProcessGeneration::Hosted(8),
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
        let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
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
    let mut owner = ThreadRollback::prepare(identity(), &entries).unwrap();
    assert_eq!(owner.pending_resources().count(), resources().len());
    let mut io = Backend::new(owner.id());
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
}

#[test]
fn conflicting_cap_classes_are_rejected_before_adoption() {
    use ThreadRollbackResourceKind::*;
    for (a, b) in [
        (Frame, Alias),
        (Alias, Frame),
        (Mechanism, Frame),
        (Alias, Mechanism),
    ] {
        let entries = [resource(100, a), resource(100, b)];
        assert!(matches!(
            ThreadRollback::prepare(identity(), &entries),
            Err(ThreadRollbackError::ConflictingOwnership)
        ));
    }
}

#[test]
fn invalid_identities_cannot_own_rollback() {
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
            process_generation: ProcessGeneration::Hosted(0),
            ..identity()
        },
    ] {
        assert!(matches!(
            ThreadRollback::prepare(id, &[]),
            Err(ThreadRollbackError::InvalidIdentity)
        ));
    }
}

#[test]
fn empty_resource_set_still_requires_memory_exclusion_and_transfer_finish() {
    let mut owner = ThreadRollback::prepare(identity(), &[]).unwrap();
    let mut io = Backend::new(owner.id());
    owner.advance(&mut io).unwrap();
    assert_eq!(
        io.successes,
        [Event::Revoke, Event::FinishTransfers, Event::Commit]
    );
}

#[test]
fn released_alias_slots_are_not_deleted_again_after_later_failure() {
    use ThreadRollbackResourceKind::*;
    let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::Release(resource(201, Frame)));
    assert!(owner.advance(&mut io).is_err());
    let boundary = io.calls.len();
    io.fail = None;
    owner.advance(&mut io).unwrap();
    assert_eq!(
        io.calls[boundary..],
        [
            Event::Release(resource(201, Frame)),
            Event::FinishTransfers,
            Event::Commit
        ]
    );
}

#[test]
fn pooled_tid_reuse_requires_a_new_attempt_owner_at_every_retry_stage() {
    for failure in expected_events()
        .into_iter()
        .filter(|event| *event != Event::Commit)
    {
        let mut old = ThreadRollback::prepare(identity(), &resources()).unwrap();
        let mut io = Backend::new(old.id());
        io.fail = Some(failure);
        assert!(old.advance(&mut io).is_err());
        let replacement = ThreadRollback::prepare(identity(), &resources()).unwrap();
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
    let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
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
fn terminal_transfer_failure_retains_owner_without_replaying_released_resources() {
    let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::FinishTransfers);
    for attempt in 1..=3 {
        assert_eq!(
            owner.advance(&mut io),
            Err(ThreadRollbackError::Backend {
                stage: ThreadRollbackStage::FinishMemoryTransfers,
                status: 0xc000_009a,
            })
        );
        assert_eq!(owner.stage(), ThreadRollbackStage::FinishMemoryTransfers);
        assert_eq!(owner.pending_resources().count(), 0);
        assert!(io.pool_held && io.window_held && io.charge == 8192);
        assert_eq!(io.commits, 0);
        assert_eq!(
            io.calls
                .iter()
                .filter(|&&event| event == Event::FinishTransfers)
                .count(),
            attempt
        );
        for event in expected_events()
            .into_iter()
            .filter(|event| !matches!(event, Event::FinishTransfers | Event::Commit))
        {
            assert_eq!(
                io.calls.iter().filter(|&&actual| actual == event).count(),
                1
            );
        }
    }
    io.fail = None;
    owner.advance(&mut io).unwrap();
    assert_eq!(io.successes, expected_events());
    let calls = io.calls.len();
    owner.advance(&mut io).unwrap();
    assert_eq!(io.calls.len(), calls);
    assert_eq!(io.commits, 1);
}

#[test]
fn stale_terminal_retry_cannot_finish_transfers_or_commit_replacement() {
    let mut owner = ThreadRollback::prepare(identity(), &resources()).unwrap();
    let mut io = Backend::new(owner.id());
    io.fail = Some(Event::FinishTransfers);
    owner.advance(&mut io).unwrap_err();
    let calls = io.calls.len();
    io.current = ThreadRollback::prepare(identity(), &[]).unwrap().id();
    io.fail = None;
    assert_eq!(owner.advance(&mut io), Err(ThreadRollbackError::StaleOwner));
    assert_eq!(io.calls.len(), calls);
    assert_eq!(owner.stage(), ThreadRollbackStage::FinishMemoryTransfers);
    assert!(io.pool_held && io.window_held && io.commits == 0);
    io.current = owner.id();
    owner.advance(&mut io).unwrap();
    assert_eq!(&io.calls[calls..], &[Event::FinishTransfers, Event::Commit]);
}

#[test]
fn backend_failure_status_is_preserved() {
    struct Failing;
    impl ThreadRollbackIo for Failing {
        fn is_current(&self, _: ThreadRollbackId) -> bool {
            true
        }

        fn revoke_memory_access(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
            Err(0xc000_0001)
        }
        fn unmap_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
            panic!()
        }
        fn delete_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
            panic!()
        }
        fn recycle_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
            panic!()
        }
        fn finish_memory_transfers(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
            panic!()
        }
        fn commit_rollback(&mut self, _: ThreadRollbackId) {
            panic!()
        }
    }
    let mut owner = ThreadRollback::prepare(identity(), &[]).unwrap();
    assert_eq!(
        owner.advance(&mut Failing),
        Err(ThreadRollbackError::Backend {
            stage: ThreadRollbackStage::RevokeMemoryAccess,
            status: 0xc000_0001,
        })
    );
}
#[test]
fn construction_and_registered_attempt_numbers_have_distinct_authority() {
    let mut publication = crate::thread_publication::ThreadPublicationSlot::empty();
    let ticket = publication.prepare(24u64).unwrap();
    let id = construction_rollback_id(identity(), &ticket).unwrap();
    let registered = ThreadRollbackId {
        identity: identity(),
        attempt: RollbackAttempt::Registered(ticket.attempt()),
    };
    assert_eq!(id.identity(), registered.identity());
    assert_ne!(id, registered);
    let again = construction_rollback_id(identity(), &ticket).unwrap();
    assert_eq!(id, again);
}
