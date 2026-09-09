use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::thread_binding::ThreadBinding;
use crate::thread_publication::ThreadPublicationSlot;
use crate::thread_retirement::Operation;
use crate::thread_slot::{RuntimeIdentity, ThreadRuntimeSlot};
use alloc::vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Suspend(u64),
    Delete(Role, u64),
    Recycle(Role, u64),
}

struct Io {
    current: ThreadRollbackId,
    calls: Vec<Event>,
    successes: Vec<Event>,
    fail: Option<Event>,
}
impl Io {
    fn new(current: ThreadRollbackId) -> Self {
        Self {
            current,
            calls: Vec::new(),
            successes: Vec::new(),
            fail: None,
        }
    }
    fn effect(&mut self, event: Event) -> Result<(), u32> {
        self.calls.push(event);
        if self.fail == Some(event) {
            return Err(123);
        }
        assert!(!self.successes.contains(&event));
        self.successes.push(event);
        Ok(())
    }
}
impl ThreadRetirementIo for Io {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.current == id
    }
    fn suspend_tcb(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Event::Suspend(cap))
    }
    fn delete_cap(&mut self, role: Role, cap: u64) -> Result<(), u32> {
        self.effect(Event::Delete(role, cap))
    }
    fn recycle_slot(&mut self, role: Role, cap: u64) -> Result<(), u32> {
        self.effect(Event::Recycle(role, cap))
    }
    fn recycle_failed_memory_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("registered owner has no failed constructor slot")
    }
}

pub(crate) fn finish_pending<R: RuntimeMechanismHandoff>(owner: &mut PendingThreadRuntime<R>) {
    owner.handoff_registered_mechanisms(owner.id()).unwrap();
    owner
        .advance_registered_mechanism_retirement(&mut Io::new(owner.id()))
        .unwrap();
}

pub(crate) fn finish_slot<R: RuntimeMechanismHandoff>(
    slot: &mut ThreadRuntimeSlot<R>,
    id: ThreadRollbackId,
) {
    slot.handoff_registered_mechanisms(id).unwrap();
    slot.advance_registered_mechanism_retirement(id, &mut Io::new(id))
        .unwrap();
}

pub(crate) struct PublishedMechanisms {
    pub binding: ThreadBinding<u32>,
    pub publication: ThreadPublicationSlot,
    pub caps: [u64; 4],
}
impl PublishedMechanisms {
    pub fn new(
        identity: ThreadRollbackIdentity,
        reservations: ThreadRuntimeReservations,
        tcb: u64,
    ) -> Self {
        Self {
            binding: ThreadBinding {
                pi: identity.pi,
                tid: identity.tid,
                tcb,
                badge: reservations.badge,
                role: 0,
                process: ProcessIdentity {
                    pid: identity.pid,
                    generation: identity.process_generation,
                },
                reservations: Some(reservations),
            },
            publication: ThreadPublicationSlot::empty(),
            caps: [9001, 9002, tcb, 9003],
        }
    }
}

macro_rules! delegate {
    ($runtime:ty, $field:ident) => {
        impl crate::thread_slot::RuntimeIdentity for $runtime {
            type Role = u32;
            fn binding(&self) -> crate::thread_binding::ThreadBinding<u32> {
                self.$field.binding
            }
            fn publication(&self) -> &crate::thread_publication::ThreadPublicationSlot {
                &self.$field.publication
            }
        }
        impl crate::thread_slot::RuntimeTcbProjection for $runtime {
            fn clear_retired_tcb_projection(&mut self, cap: u64) -> Result<(), u32> {
                if self.$field.binding.tcb != cap && self.$field.binding.tcb != 1 {
                    return Err(125);
                }
                self.$field.binding.tcb = 1;
                Ok(())
            }
        }
        impl crate::thread_slot::RuntimeMechanismHandoff for $runtime {
            fn registered_mechanism_slots(&self) -> Result<[u64; 4], u32> {
                Ok(self.$field.caps)
            }
            fn clear_registered_mechanism_projections(
                &mut self,
                id: crate::thread_rollback::ThreadRollbackId,
                caps: [u64; 4],
            ) -> Result<(), u32> {
                if id.identity().tid != self.$field.binding.tid || caps != self.$field.caps {
                    return Err(126);
                }
                self.$field.caps = [0; 4];
                Ok(())
            }
        }
    };
}
pub(crate) use delegate;

struct Runtime {
    binding: ThreadBinding<u32>,
    publication: ThreadPublicationSlot,
    caps: [u64; 4],
    fail_clear: bool,
    fail_tcb_clear: bool,
    handoffs: usize,
    suspension: Option<crate::thread_suspend::ThreadSuspendOwner<u32>>,
    suspension_retirements: usize,
}
impl RuntimeIdentity for Runtime {
    type Role = u32;
    fn binding(&self) -> ThreadBinding<u32> {
        self.binding
    }
    fn publication(&self) -> &ThreadPublicationSlot {
        &self.publication
    }
}
impl RuntimeTcbProjection for Runtime {
    fn clear_retired_tcb_projection(&mut self, expected: u64) -> Result<(), u32> {
        if self.fail_tcb_clear {
            return Err(124);
        }
        if self.binding.tcb != expected && self.binding.tcb != 1 {
            return Err(125);
        }
        if let Some(suspension) = self.suspension.take() {
            // The sealed actor calls this hook only after its Delete ACK, before recycling.
            if let Err((_, suspension)) = unsafe { suspension.retire_deleted_tcb(self.binding) } {
                self.suspension = Some(suspension);
                return Err(127);
            }
            self.suspension_retirements += 1;
        }
        self.binding.tcb = 1;
        Ok(())
    }
}
impl RuntimeMechanismHandoff for Runtime {
    fn registered_mechanism_slots(&self) -> Result<[u64; 4], u32> {
        Ok(self.caps)
    }
    fn clear_registered_mechanism_projections(
        &mut self,
        id: ThreadRollbackId,
        expected: [u64; 4],
    ) -> Result<(), u32> {
        if self.fail_clear || self.caps != expected || id.identity().tid != self.binding.tid {
            return Err(126);
        }
        self.caps = [0; 4];
        self.handoffs += 1;
        Ok(())
    }
}
fn owner() -> PendingThreadRuntime<Runtime> {
    let reservations = ThreadRuntimeReservations {
        badge: 8,
        pool_slot: 2,
        window_slot: Some(3),
    };
    let binding = ThreadBinding {
        pi: 4,
        tid: 7,
        tcb: 12,
        badge: 8,
        role: 1,
        process: ProcessIdentity {
            pid: 9,
            generation: ProcessGeneration::Hosted(6),
        },
        reservations: Some(reservations),
    };
    let runtime = Runtime {
        binding,
        publication: ThreadPublicationSlot::empty(),
        caps: [10, 11, 12, 13],
        fail_clear: false,
        fail_tcb_clear: false,
        handoffs: 0,
        suspension: None,
        suspension_retirements: 0,
    };
    match PendingThreadRuntime::retain(
        ThreadRollbackIdentity {
            pi: binding.pi,
            pid: binding.process.pid,
            process_generation: binding.process.generation,
            tid: binding.tid,
        },
        binding.tcb,
        Some(reservations),
        runtime,
    ) {
        Ok(owner) => owner,
        Err(_) => panic!(),
    }
}
fn expected() -> Vec<Event> {
    vec![
        Event::Suspend(12),
        Event::Delete(Role::Tcb, 12),
        Event::Recycle(Role::Tcb, 12),
        Event::Delete(Role::GuardedCnode, 11),
        Event::Recycle(Role::GuardedCnode, 11),
        Event::Delete(Role::RawCnode, 10),
        Event::Recycle(Role::RawCnode, 10),
        Event::Delete(Role::SchedContext, 13),
        Event::Recycle(Role::SchedContext, 13),
    ]
}

#[test]
fn registered_handoff_has_distinct_provenance_and_is_allocation_free_in_shape() {
    let mut owner = owner();
    let id = owner.id();
    let binding = owner.runtime.binding;
    let mut io = Io::new(id);
    assert_eq!(
        owner.advance_registered_mechanism_retirement(&mut io),
        Err(RetirementError::NotTransferred)
    );
    assert_eq!(
        owner.prepare_journal(&[]),
        Err(ThreadRollbackError::MechanismsPending)
    );
    assert!(io.calls.is_empty());
    owner.handoff_registered_mechanisms(id).unwrap();
    assert!(owner.construction_retirement().is_none());
    assert_eq!(owner.runtime.binding, binding);
    assert_eq!(owner.runtime.caps, [0; 4]);
    assert_eq!(
        owner
            .registered_mechanism_retirement()
            .unwrap()
            .inventory()
            .live_slots(),
        Ok([10, 11, 12, 13])
    );
    owner.handoff_registered_mechanisms(id).unwrap();
    assert_eq!(owner.runtime.handoffs, 1);
    assert_eq!(
        owner.prepare_journal(&[]),
        Err(ThreadRollbackError::MechanismsPending)
    );
    owner
        .advance_registered_mechanism_retirement(&mut io)
        .unwrap();
    assert_eq!(io.successes, expected());
    assert_eq!(owner.runtime.binding.tcb, 1);
    assert_eq!(owner.runtime.binding.reservations, owner.reservations);
    owner.prepare_journal(&[]).unwrap();
}

#[test]
fn invalid_or_changed_registered_bundle_leaves_original_owner_untouched() {
    for caps in [
        [0, 11, 12, 13],
        [10, 1, 12, 13],
        [10, 11, 99, 13],
        [10, 11, 12, 10],
    ] {
        let mut owner = owner();
        owner.runtime.caps = caps;
        let id = owner.id();
        assert_eq!(
            owner.handoff_registered_mechanisms(id),
            Err(RetirementError::InvalidMechanisms)
        );
        assert_eq!(owner.runtime.caps, caps);
        assert_eq!(owner.runtime.handoffs, 0);
        assert!(owner.registered_mechanism_retirement().is_none());
    }
    let mut owner = owner();
    let id = owner.id();
    owner
        .runtime
        .binding
        .reservations
        .as_mut()
        .unwrap()
        .pool_slot += 1;
    assert_eq!(
        owner.handoff_registered_mechanisms(id),
        Err(RetirementError::StaleOwner)
    );
    assert_eq!(owner.runtime.caps, [10, 11, 12, 13]);
}

#[test]
fn projection_failure_and_foreign_attempt_preserve_untransferred_owner() {
    let foreign = owner().id();
    let mut owner = owner();
    let id = owner.id();
    assert_eq!(
        owner.handoff_registered_mechanisms(foreign),
        Err(RetirementError::StaleOwner)
    );
    owner.runtime.fail_clear = true;
    for _ in 0..3 {
        assert_eq!(
            owner.handoff_registered_mechanisms(id),
            Err(RetirementError::Projection(126))
        );
        assert_eq!(owner.runtime.caps, [10, 11, 12, 13]);
        assert!(owner.registered_mechanism_retirement().is_none());
    }
    owner.runtime.fail_clear = false;
    finish_pending(&mut owner);
    assert_eq!(
        owner.handoff_registered_mechanisms(foreign),
        Err(RetirementError::StaleOwner)
    );
}

#[test]
fn every_mechanism_failure_retains_progress_and_cannot_replay_on_foreign_owner() {
    for (index, failure) in expected().into_iter().enumerate() {
        let foreign = owner().id();
        let mut owner = owner();
        owner.handoff_registered_mechanisms(owner.id()).unwrap();
        let mut io = Io::new(owner.id());
        io.fail = Some(failure);
        for _ in 0..3 {
            assert!(owner
                .advance_registered_mechanism_retirement(&mut io)
                .is_err());
            assert_eq!(io.successes, expected()[..index]);
            assert_eq!(
                owner.prepare_journal(&[]),
                Err(ThreadRollbackError::MechanismsPending)
            );
        }
        let calls = io.calls.clone();
        io.current = foreign;
        assert_eq!(
            owner.advance_registered_mechanism_retirement(&mut io),
            Err(RetirementError::StaleOwner)
        );
        assert_eq!(io.calls, calls);
        io.current = owner.id();
        io.fail = None;
        owner
            .advance_registered_mechanism_retirement(&mut io)
            .unwrap();
        assert_eq!(io.successes, expected());
        owner
            .advance_registered_mechanism_retirement(&mut io)
            .unwrap();
        assert_eq!(io.successes, expected());
    }
}

#[test]
fn tcb_projection_clears_after_delete_and_before_recycle_including_retry() {
    let mut owner = owner();
    owner.runtime.fail_tcb_clear = true;
    owner.handoff_registered_mechanisms(owner.id()).unwrap();
    let mut io = Io::new(owner.id());
    assert_eq!(
        owner.advance_registered_mechanism_retirement(&mut io),
        Err(RetirementError::Backend {
            role: Role::Tcb,
            operation: Operation::Recycle,
            status: 124,
        })
    );
    assert_eq!(io.successes, expected()[..2]);
    assert_eq!(owner.runtime.binding.tcb, 12);
    owner.runtime.fail_tcb_clear = false;
    io.fail = Some(Event::Recycle(Role::Tcb, 12));
    assert!(owner
        .advance_registered_mechanism_retirement(&mut io)
        .is_err());
    assert_eq!(owner.runtime.binding.tcb, 1);
    assert_eq!(io.successes, expected()[..2]);
    io.fail = None;
    owner
        .advance_registered_mechanism_retirement(&mut io)
        .unwrap();
    assert_eq!(io.successes, expected());
}

#[test]
fn settled_hold_retires_once_between_sealed_tcb_delete_and_recycle() {
    use crate::thread_suspend::{
        ThreadExecutionState, ThreadSuspendAction, ThreadSuspendOutcome, ThreadSuspendOwner,
    };
    use nt_process::thread_suspend::ThreadSuspendOperation;

    let mut pm = nt_process::ProcessManager::new();
    let pid = pm.create_process("held-retirement", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let binding = ThreadBinding {
        pi: 4,
        tid: u64::from(tid),
        tcb: 12,
        badge: 8,
        role: 1,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(6),
        },
        reservations: None,
    };
    let mut suspension = ThreadSuspendOwner::running(binding, lifetime).unwrap();
    suspension
        .prepare(&mut pm, binding, lifetime, ThreadSuspendOperation::Suspend)
        .unwrap();
    let invocation = suspension.begin().unwrap();
    assert_eq!(
        invocation.action(),
        ThreadSuspendAction::Acquire { tcb: 12 }
    );
    suspension
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged {
                generation: Some(73),
            },
        )
        .unwrap();
    suspension.finish(&mut pm, binding, lifetime).unwrap();
    let runtime = Runtime {
        binding,
        publication: ThreadPublicationSlot::empty(),
        caps: [10, 11, 12, 13],
        fail_clear: false,
        fail_tcb_clear: true,
        handoffs: 0,
        suspension: Some(suspension),
        suspension_retirements: 0,
    };
    let mut owner = match PendingThreadRuntime::retain(
        ThreadRollbackIdentity {
            pi: binding.pi,
            pid,
            process_generation: binding.process.generation,
            tid: binding.tid,
        },
        binding.tcb,
        None,
        runtime,
    ) {
        Ok(owner) => owner,
        Err(_) => panic!("exact registered owner admission"),
    };
    owner.handoff_registered_mechanisms(owner.id()).unwrap();
    let mut io = Io::new(owner.id());
    io.fail = Some(Event::Delete(Role::Tcb, 12));
    assert!(owner
        .advance_registered_mechanism_retirement(&mut io)
        .is_err());
    assert_eq!(io.successes, vec![Event::Suspend(12)]);
    assert_eq!(owner.runtime.binding.tcb, 12);
    assert_eq!(
        owner.runtime.suspension.as_ref().unwrap().execution_state(),
        ThreadExecutionState::Held { generation: 73 }
    );
    assert_eq!(owner.runtime.suspension_retirements, 0);

    io.fail = None;
    assert_eq!(
        owner.advance_registered_mechanism_retirement(&mut io),
        Err(RetirementError::Backend {
            role: Role::Tcb,
            operation: Operation::Recycle,
            status: 124
        })
    );
    assert_eq!(io.successes, expected()[..2]);
    assert_eq!(owner.runtime.binding.tcb, 12);
    assert_eq!(
        owner.runtime.suspension.as_ref().unwrap().execution_state(),
        ThreadExecutionState::Held { generation: 73 }
    );
    assert_eq!(owner.runtime.suspension_retirements, 0);

    owner.runtime.fail_tcb_clear = false;
    io.fail = Some(Event::Recycle(Role::Tcb, 12));
    assert!(owner
        .advance_registered_mechanism_retirement(&mut io)
        .is_err());
    assert_eq!(owner.runtime.binding.tcb, 1);
    assert!(owner.runtime.suspension.is_none());
    assert_eq!(owner.runtime.suspension_retirements, 1);
    assert_eq!(io.successes, expected()[..2]);
    let delete_attempts = io
        .calls
        .iter()
        .filter(|event| **event == Event::Delete(Role::Tcb, 12))
        .count();
    assert_eq!(
        delete_attempts, 2,
        "one rejected delete and one acknowledged delete"
    );

    io.fail = None;
    owner
        .advance_registered_mechanism_retirement(&mut io)
        .unwrap();
    owner
        .advance_registered_mechanism_retirement(&mut io)
        .unwrap();
    assert_eq!(io.successes, expected());
    assert_eq!(
        io.calls
            .iter()
            .filter(|event| **event == Event::Delete(Role::Tcb, 12))
            .count(),
        delete_attempts
    );
    assert_eq!(owner.runtime.suspension_retirements, 1);
    assert!(
        owner.runtime.suspension.is_none(),
        "no owner remains to issue Release after deletion"
    );
    assert_eq!(
        pm.thread(tid).unwrap().suspend_count,
        1,
        "mechanism deletion consumes physical ownership, not an NT count-resume transaction"
    );
    assert!(!pm.has_thread_suspend_control(tid));
}

#[test]
fn retired_mechanism_numbers_cannot_reenter_memory_journal() {
    for cap in [10, 11, 12, 13] {
        let mut owner = owner();
        finish_pending(&mut owner);
        for kind in [
            crate::thread_rollback::ThreadRollbackResourceKind::Alias,
            crate::thread_rollback::ThreadRollbackResourceKind::Frame,
        ] {
            assert_eq!(
                owner.prepare_journal(&[ThreadRollbackResource { cap, kind }]),
                Err(ThreadRollbackError::ConflictingOwnership)
            );
        }
    }
}
