//! Readiness remains owned until the exact continuation accepts its completion.

use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use nt_provider_wait::*;
use nt_time::TimeSnapshot;

#[derive(Default)]
struct Effects {
    consumed: Cell<usize>,
    released: Cell<usize>,
}

#[derive(Default)]
struct Backend {
    effects: Rc<Effects>,
    leases: BTreeMap<u64, ProviderWaitObject>,
    signals: BTreeMap<u64, bool>,
    next_lease: u64,
}

impl ProviderDispatcherWaitBackend for Backend {
    type Lease = u64;
    type Error = ();

    fn acquire_dispatcher_wait(
        &mut self,
        _: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<u64, ()> {
        self.next_lease += 1;
        self.leases.insert(self.next_lease, object);
        Ok(self.next_lease)
    }

    fn dispatcher_is_ready(&self, lease: u64) -> bool {
        self.signals.get(&self.leases[&lease].object_id).copied() == Some(true)
    }

    fn consume_ready_dispatcher(&mut self, lease: u64) {
        assert!(self.dispatcher_is_ready(lease));
        self.signals.insert(self.leases[&lease].object_id, false);
        self.effects.consumed.set(self.effects.consumed.get() + 1);
    }

    fn release_dispatcher_wait(&mut self, lease: u64) {
        assert!(self.leases.remove(&lease).is_some());
        self.effects.released.set(self.effects.released.get() + 1);
    }
}

fn owner(kernel: bool, dispatch_id: u64) -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: 3,
        provider_generation: 2,
        dispatch_id,
        caller: if kernel {
            SuspensionCaller::Kernel {
                lane: LaneHandle {
                    index: 1,
                    generation: 2,
                },
            }
        } else {
            SuspensionCaller::Hosted(SuspensionHostedClient {
                client_pi: 4,
                client_generation: 5,
                client_tid: 6,
                client_badge: 7,
            })
        },
    }
}

fn event(id: u64) -> ProviderWaitObject {
    ProviderWaitObject::new(ProviderWaitObjectType::Event, id, 1)
}

fn now(monotonic: u64, system: u64) -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns: monotonic,
        system_time_100ns: system,
        clock_generation: 0,
    }
}

fn request(
    owner: ProviderWaitOwner,
    id: u64,
    wait_type: ProviderWaitType,
    timeout_kind: ProviderWaitTimeoutKind,
    timeout: i64,
) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: id,
                owner,
                wait_type,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind,
                timeout_100ns: timeout,
            },
            &[event(1), event(2)],
        )
        .unwrap();
    request
}

fn park(
    arbiter: &mut ProviderDispatcherWaitArbiter<u64>,
    backend: &mut Backend,
    request: &ProviderWaitRequest,
    owner: ProviderWaitOwner,
    sequence: u64,
) {
    assert!(matches!(
        arbiter.admit(backend, request, owner, sequence, now(10, 100)),
        Ok(ProviderDispatcherWaitAdmission::Parked { .. })
    ));
}

#[test]
fn refusal_preserves_oldest_mixed_caller_and_retry_publishes_before_consumption() {
    for targeted in [false, true] {
        for kernel_first in [false, true] {
            for wait_type in [ProviderWaitType::Any, ProviderWaitType::All] {
                let mut backend = Backend::default();
                let mut arbiter = ProviderDispatcherWaitArbiter::new();
                // Reverse vector order; equal dispatch IDs are distinct caller namespaces.
                let older = owner(kernel_first, 1);
                let younger = owner(!kernel_first, 1);
                park(
                    &mut arbiter,
                    &mut backend,
                    &request(younger, 22, wait_type, ProviderWaitTimeoutKind::Infinite, 0),
                    younger,
                    20,
                );
                park(
                    &mut arbiter,
                    &mut backend,
                    &request(older, 11, wait_type, ProviderWaitTimeoutKind::Infinite, 0),
                    older,
                    10,
                );
                backend.signals.insert(1, true);
                backend.signals.insert(2, true);
                let effects = backend.effects.clone();
                let reject = |completion: ProviderDispatcherWaitCompletion| {
                    assert_eq!(completion.wait_id, 11);
                    assert_eq!(completion.owner, older);
                    assert_eq!(completion.admission_sequence, 10);
                    assert_eq!(completion.status, STATUS_WAIT_0);
                    assert!(!completion.cancelled);
                    assert_eq!(effects.consumed.get(), 0);
                    assert_eq!(effects.released.get(), 0);
                    Err::<Box<u64>, _>("wrong route")
                };
                let rejected = if targeted {
                    arbiter.pop_event_ready_with(&mut backend, event(1), 10, reject)
                } else {
                    arbiter.pop_ready_with(&mut backend, reject)
                };
                assert_eq!(rejected, Err("wrong route"));
                assert_eq!(arbiter.len(), 2);
                assert_eq!(arbiter.lease_count(), 4);
                assert_eq!(backend.leases.len(), 4);
                assert!(backend.signals[&1] && backend.signals[&2]);
                assert_eq!(effects.consumed.get(), 0);
                assert_eq!(effects.released.get(), 0);
                let accept = |completion: ProviderDispatcherWaitCompletion| {
                    assert_eq!(completion.owner, older);
                    assert_eq!(effects.consumed.get(), 0);
                    assert_eq!(effects.released.get(), 0);
                    Ok::<_, ()>(Box::new(completion.wait_id))
                };
                let (completion, output) = if targeted {
                    arbiter.pop_event_ready_with(&mut backend, event(1), 10, accept)
                } else {
                    arbiter.pop_ready_with(&mut backend, accept)
                }
                .unwrap()
                .unwrap();
                assert_eq!(*output, completion.wait_id);
                assert_eq!(completion.owner, older);
                assert_eq!(
                    effects.consumed.get(),
                    if wait_type == ProviderWaitType::Any {
                        1
                    } else {
                        2
                    }
                );
                assert_eq!(effects.released.get(), 2);
                assert_eq!(arbiter.len(), 1);
                backend.signals.insert(1, true);
                backend.signals.insert(2, true);
                let next = arbiter.pop_ready(&mut backend).unwrap();
                assert_eq!(next.owner, younger);
                assert_eq!(next.admission_sequence, 20);
                assert!(arbiter.is_empty());
                assert!(backend.leases.is_empty());
            }
        }
    }
}

#[test]
fn absence_and_stale_event_sequence_never_invoke_publication() {
    let mut backend = Backend::default();
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let no_call =
        |_: ProviderDispatcherWaitCompletion| -> Result<(), ()> { panic!("no candidate") };
    assert_eq!(arbiter.pop_ready_with(&mut backend, no_call), Ok(None));
    assert_eq!(
        arbiter.pop_event_ready_with(&mut backend, event(1), 1, no_call),
        Ok(None)
    );
    assert_eq!(
        arbiter.pop_due_with(&mut backend, now(10, 100), no_call),
        Ok(None)
    );
    let owner = owner(true, 1);
    park(
        &mut arbiter,
        &mut backend,
        &request(
            owner,
            1,
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
            0,
        ),
        owner,
        10,
    );
    assert_eq!(arbiter.pop_ready_with(&mut backend, no_call), Ok(None));
    backend.signals.insert(1, true);
    for stale in [0, 9, 11] {
        assert_eq!(
            arbiter.pop_event_ready_with(&mut backend, event(1), stale, no_call),
            Ok(None)
        );
    }
    assert_eq!(
        arbiter.pop_event_ready_with(&mut backend, event(2), 10, no_call),
        Ok(None)
    );
    assert_eq!(
        arbiter.pop_due_with(&mut backend, now(u64::MAX, u64::MAX), no_call),
        Ok(None)
    );
    assert_eq!(arbiter.len(), 1);
    assert_eq!(backend.leases.len(), 2);
    assert!(backend.signals[&1]);
    assert_eq!(backend.effects.consumed.get(), 0);
    assert_eq!(backend.effects.released.get(), 0);
}

#[test]
fn refused_timeout_retains_deadline_and_leases_without_consuming_ready_events() {
    for timeout_kind in [
        ProviderWaitTimeoutKind::Relative,
        ProviderWaitTimeoutKind::Absolute,
    ] {
        let mut backend = Backend::default();
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let older = owner(true, 1);
        let younger = owner(false, 1);
        let timeout = if timeout_kind == ProviderWaitTimeoutKind::Relative {
            -20
        } else {
            120
        };
        park(
            &mut arbiter,
            &mut backend,
            &request(younger, 2, ProviderWaitType::Any, timeout_kind, timeout),
            younger,
            20,
        );
        park(
            &mut arbiter,
            &mut backend,
            &request(older, 1, ProviderWaitType::Any, timeout_kind, timeout),
            older,
            10,
        );
        assert_eq!(arbiter.next_deadline(now(10, 100)), Some(30));
        assert_eq!(
            arbiter.pop_due_with(&mut backend, now(29, 119), |_| -> Result<(), ()> {
                panic!("not due")
            }),
            Ok(None)
        );
        backend.signals.insert(1, true);
        let effects = backend.effects.clone();
        let rejected = arbiter.pop_due_with(&mut backend, now(30, 120), |completion| {
            assert_eq!(completion.owner, older);
            assert_eq!(completion.status, STATUS_TIMEOUT);
            assert!(!completion.cancelled);
            assert_eq!(effects.released.get(), 0);
            Err::<(), _>("recipient unavailable")
        });
        assert_eq!(rejected, Err("recipient unavailable"));
        assert_eq!(arbiter.next_deadline(now(10, 100)), Some(30));
        assert_eq!(arbiter.len(), 2);
        assert_eq!(backend.leases.len(), 4);
        assert_eq!(effects.released.get(), 0);
        assert_eq!(effects.consumed.get(), 0);
        let (completion, output) = arbiter
            .pop_due_with(&mut backend, now(30, 120), |completion| {
                assert_eq!(effects.released.get(), 0);
                Ok::<_, ()>(Box::new(completion.admission_sequence))
            })
            .unwrap()
            .unwrap();
        assert_eq!(completion.owner, older);
        assert_eq!(*output, 10);
        assert_eq!(effects.released.get(), 2);
        assert_eq!(effects.consumed.get(), 0);
        assert!(backend.signals[&1]);
        assert_eq!(
            arbiter.pop_due(&mut backend, now(30, 120)).unwrap().owner,
            younger
        );
        assert!(arbiter.is_empty());
        assert!(backend.leases.is_empty());
        assert_eq!(effects.consumed.get(), 0);
    }
}
