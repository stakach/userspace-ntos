//! Publication owns the continuation before the arbiter may consume dispatcher readiness.

use std::{cell::Cell, collections::BTreeMap, rc::Rc};

use nt_component_suspension::{ComponentSuspensionLanes, LaneBinding, LaneError, SuspensionKey};
use nt_provider_wait::*;
use nt_time::TimeSnapshot;

#[derive(Debug)]
struct Continuation {
    bank: Box<u64>,
    drops: Rc<Cell<usize>>,
}

impl Continuation {
    fn new(drops: &Rc<Cell<usize>>) -> Self {
        Self {
            bank: Box::new(42),
            drops: drops.clone(),
        }
    }

    fn address(&self) -> usize {
        &*self.bank as *const u64 as usize
    }
}

impl Drop for Continuation {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

#[derive(Default)]
struct Observations {
    acquired: Cell<usize>,
    released: Cell<usize>,
    readiness_checks: Cell<usize>,
    consumed: Cell<usize>,
}

#[derive(Default)]
struct Backend {
    observations: Rc<Observations>,
    leases: BTreeMap<u64, ProviderWaitObject>,
    next_lease: u64,
    fail_at: Option<usize>,
    signaled: bool,
}

impl ProviderDispatcherWaitBackend for Backend {
    type Lease = u64;
    type Error = &'static str;

    fn acquire_dispatcher_wait(
        &mut self,
        _: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<u64, Self::Error> {
        let acquired = self.observations.acquired.get();
        if self.fail_at == Some(acquired) {
            return Err("lease rejected");
        }
        self.next_lease += 1;
        self.leases.insert(self.next_lease, object);
        self.observations.acquired.set(acquired + 1);
        Ok(self.next_lease)
    }

    fn dispatcher_is_ready(&self, lease: u64) -> bool {
        assert!(self.leases.contains_key(&lease));
        self.observations
            .readiness_checks
            .set(self.observations.readiness_checks.get() + 1);
        self.signaled
    }

    fn consume_ready_dispatcher(&mut self, lease: u64) {
        assert!(self.leases.contains_key(&lease));
        assert!(self.signaled);
        self.signaled = false;
        self.observations
            .consumed
            .set(self.observations.consumed.get() + 1);
    }

    fn release_dispatcher_wait(&mut self, lease: u64) {
        assert!(self.leases.remove(&lease).is_some());
        self.observations
            .released
            .set(self.observations.released.get() + 1);
    }
}

fn owner() -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: 7,
        provider_generation: 3,
        dispatch_id: 1,
        caller: SuspensionCaller::Kernel {
            lane: LaneHandle {
                index: 0,
                generation: 1,
            },
        },
    }
}

fn request(
    owner: ProviderWaitOwner,
    id: u64,
    timeout: ProviderWaitTimeoutKind,
) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: id,
                owner,
                wait_type: ProviderWaitType::Any,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: timeout,
                timeout_100ns: if timeout == ProviderWaitTimeoutKind::Absolute {
                    99
                } else {
                    0
                },
            },
            &[
                ProviderWaitObject::new(ProviderWaitObjectType::Event, 31, 2),
                ProviderWaitObject::new(ProviderWaitObjectType::Event, 32, 2),
            ],
        )
        .unwrap();
    request
}

fn now() -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns: 10,
        system_time_100ns: 100,
        clock_generation: 0,
    }
}

fn no_publication(_: Continuation) -> Result<(), (&'static str, Continuation)> {
    panic!("publication must not run")
}

#[test]
fn validation_rejections_return_the_original_nonclone_continuation() {
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut backend = Backend::default();
    let drops = Rc::new(Cell::new(0));
    let mut continuation = Continuation::new(&drops);
    let address = continuation.address();
    let good = request(owner(), 1, ProviderWaitTimeoutKind::Infinite);
    let mut invalid = good;
    invalid.header.magic = 0;
    let mut foreign = owner();
    foreign.dispatch_id += 1;
    for (request, expected, sequence, error) in [
        (
            invalid,
            owner(),
            1,
            ProviderDispatcherWaitError::InvalidRequest(ProviderWaitAbiError::InvalidHeader),
        ),
        (good, foreign, 1, ProviderDispatcherWaitError::OwnerMismatch),
        (
            good,
            owner(),
            0,
            ProviderDispatcherWaitError::InvalidAdmissionSequence,
        ),
    ] {
        let (actual, returned) = arbiter
            .admit_owned(
                &mut backend,
                &request,
                expected,
                sequence,
                now(),
                continuation,
                no_publication,
            )
            .unwrap_err();
        assert_eq!(actual, ProviderDispatcherWaitPublicationError::Wait(error));
        assert_eq!(returned.address(), address);
        assert_eq!(drops.get(), 0);
        continuation = returned;
    }
    assert_eq!(backend.observations.acquired.get(), 0);
    assert!(arbiter.is_empty());
    drop(continuation);
    assert_eq!(drops.get(), 1);
}

#[test]
fn duplicate_rejection_preserves_the_existing_wait_and_offered_continuation() {
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut backend = Backend::default();
    let original = request(owner(), 1, ProviderWaitTimeoutKind::Infinite);
    arbiter
        .admit(&mut backend, &original, owner(), 1, now())
        .unwrap();
    let drops = Rc::new(Cell::new(0));
    let continuation = Continuation::new(&drops);
    let address = continuation.address();
    let (error, returned) = arbiter
        .admit_owned(
            &mut backend,
            &request(owner(), 2, ProviderWaitTimeoutKind::Infinite),
            owner(),
            2,
            now(),
            continuation,
            no_publication,
        )
        .unwrap_err();
    assert_eq!(
        error,
        ProviderDispatcherWaitPublicationError::Wait(ProviderDispatcherWaitError::DuplicateWait)
    );
    assert_eq!(returned.address(), address);
    assert_eq!(drops.get(), 0);
    assert!(arbiter.contains(1));
    assert!(!arbiter.contains(2));
    assert_eq!(backend.leases.len(), 2);
    assert_eq!(backend.observations.acquired.get(), 2);
    backend.signaled = true;
    arbiter.pop_ready(&mut backend).unwrap();
    assert!(backend.leases.is_empty());
}

#[test]
fn acquisition_failure_rolls_back_every_acquired_lease_without_publication() {
    for fail_at in [0, 1] {
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut backend = Backend {
            fail_at: Some(fail_at),
            signaled: true,
            ..Default::default()
        };
        let drops = Rc::new(Cell::new(0));
        let continuation = Continuation::new(&drops);
        let address = continuation.address();
        let (error, returned) = arbiter
            .admit_owned(
                &mut backend,
                &request(owner(), 1, ProviderWaitTimeoutKind::Infinite),
                owner(),
                1,
                now(),
                continuation,
                no_publication,
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProviderDispatcherWaitPublicationError::Wait(ProviderDispatcherWaitError::Backend(
                "lease rejected"
            ))
        );
        assert_eq!(returned.address(), address);
        assert_eq!(drops.get(), 0);
        assert_eq!(backend.observations.acquired.get(), fail_at);
        assert_eq!(backend.observations.released.get(), fail_at);
        assert_eq!(backend.observations.readiness_checks.get(), 0);
        assert!(backend.signaled);
        assert!(backend.leases.is_empty());
        assert!(arbiter.is_empty());
    }
}

#[test]
fn publication_rejection_has_all_leases_but_cannot_consume_ready_events() {
    for timeout in [
        ProviderWaitTimeoutKind::Infinite,
        ProviderWaitTimeoutKind::Poll,
        ProviderWaitTimeoutKind::Absolute,
    ] {
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut backend = Backend {
            signaled: true,
            ..Default::default()
        };
        let observations = backend.observations.clone();
        let drops = Rc::new(Cell::new(0));
        let continuation = Continuation::new(&drops);
        let address = continuation.address();
        let (error, returned) = arbiter
            .admit_owned(
                &mut backend,
                &request(owner(), 1, timeout),
                owner(),
                1,
                now(),
                continuation,
                |continuation| {
                    assert_eq!(observations.acquired.get(), 2);
                    assert_eq!(observations.released.get(), 0);
                    assert_eq!(observations.readiness_checks.get(), 0);
                    assert_eq!(observations.consumed.get(), 0);
                    Err::<(), _>(("lane rejected", continuation))
                },
            )
            .unwrap_err();
        assert_eq!(
            error,
            ProviderDispatcherWaitPublicationError::Publication("lane rejected")
        );
        assert_eq!(returned.address(), address);
        assert_eq!(drops.get(), 0);
        assert_eq!(observations.released.get(), 2);
        assert_eq!(observations.readiness_checks.get(), 0);
        assert!(backend.signaled);
        assert!(backend.leases.is_empty());
        assert!(arbiter.is_empty());
    }
}

#[test]
fn successful_publication_returns_its_owned_output_for_immediate_and_parked_waits() {
    for (signaled, timeout, expected) in [
        (
            true,
            ProviderWaitTimeoutKind::Infinite,
            ProviderDispatcherWaitAdmission::Satisfied {
                wait_id: 1,
                status: STATUS_WAIT_0,
            },
        ),
        (
            true,
            ProviderWaitTimeoutKind::Absolute,
            ProviderDispatcherWaitAdmission::Satisfied {
                wait_id: 1,
                status: STATUS_WAIT_0,
            },
        ),
        (
            false,
            ProviderWaitTimeoutKind::Poll,
            ProviderDispatcherWaitAdmission::TimedOut { wait_id: 1 },
        ),
        (
            false,
            ProviderWaitTimeoutKind::Absolute,
            ProviderDispatcherWaitAdmission::TimedOut { wait_id: 1 },
        ),
        (
            false,
            ProviderWaitTimeoutKind::Infinite,
            ProviderDispatcherWaitAdmission::Parked { wait_id: 1 },
        ),
    ] {
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut backend = Backend {
            signaled,
            ..Default::default()
        };
        let observations = backend.observations.clone();
        let drops = Rc::new(Cell::new(0));
        let continuation = Continuation::new(&drops);
        let address = continuation.address();
        let (admission, output) = arbiter
            .admit_owned(
                &mut backend,
                &request(owner(), 1, timeout),
                owner(),
                9,
                now(),
                continuation,
                |continuation| {
                    assert_eq!(observations.acquired.get(), 2);
                    assert_eq!(observations.readiness_checks.get(), 0);
                    Ok::<_, (&'static str, Continuation)>((continuation, 77))
                },
            )
            .unwrap();
        assert_eq!(admission, expected);
        assert_eq!(output.0.address(), address);
        assert_eq!(output.1, 77);
        assert_eq!(drops.get(), 0);
        if matches!(admission, ProviderDispatcherWaitAdmission::Parked { .. }) {
            assert_eq!(arbiter.lease_count(), 2);
            backend.signaled = true;
            let completion = arbiter.pop_ready(&mut backend).unwrap();
            assert_eq!(completion.wait_id, 1);
            assert_eq!(completion.admission_sequence, 9);
            assert_eq!(completion.owner, owner());
            assert_eq!(completion.status, STATUS_WAIT_0);
            assert!(!completion.cancelled);
        }
        assert!(backend.leases.is_empty());
        assert!(arbiter.is_empty());
        assert_eq!(observations.released.get(), 2);
        drop(output);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn real_lane_rearm_failure_preserves_both_continuations_and_ready_state() {
    let mut lanes = ComponentSuspensionLanes::<Continuation, i32>::new(1, 4);
    let reply = 303;
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 101,
            receive_endpoint: 202,
            reply_object: reply,
        })
        .unwrap();
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = ProviderWaitOwner {
        dispatch_id: dispatch.epoch(),
        caller: SuspensionCaller::Kernel { lane },
        ..owner()
    };
    let old_key = SuspensionKey::provider_wait(1);
    let new_key = SuspensionKey::provider_wait(2);
    let drops = Rc::new(Cell::new(0));
    let old = Continuation::new(&drops);
    let old_address = old.address();
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut backend = Backend::default();
    let (admission, ()) = arbiter
        .admit_owned(
            &mut backend,
            &request(owner, 1, ProviderWaitTimeoutKind::Infinite),
            owner,
            1,
            now(),
            old,
            |continuation| lanes.admit_running_owned(lane, reply, old_key, 1, owner, continuation),
        )
        .unwrap();
    assert_eq!(
        admission,
        ProviderDispatcherWaitAdmission::Parked { wait_id: 1 }
    );
    backend.signaled = true;
    let completion = arbiter.pop_ready(&mut backend).unwrap();
    lanes.select(old_key, completion.status).unwrap();
    lanes.begin_resume(lane, reply, old_key).unwrap();
    backend.signaled = true;
    let next = Continuation::new(&drops);
    let next_address = next.address();
    let (error, next) = arbiter
        .admit_owned(
            &mut backend,
            &request(owner, 2, ProviderWaitTimeoutKind::Infinite),
            owner,
            2,
            now(),
            next,
            |continuation| {
                lanes.rearm_running_owned(lane, reply + 1, old_key, new_key, 2, owner, continuation)
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ProviderDispatcherWaitPublicationError::Publication(LaneError::WrongBinding)
    ));
    assert_eq!(next.address(), next_address);
    assert_eq!(
        lanes
            .frame(lane, old_key)
            .unwrap()
            .unwrap()
            .continuation
            .address(),
        old_address
    );
    assert_eq!(drops.get(), 0);
    assert!(arbiter.is_empty());
    assert!(backend.leases.is_empty());
    assert!(backend.signaled);
    assert_eq!(backend.observations.consumed.get(), 1);

    let (admission, previous) = arbiter
        .admit_owned(
            &mut backend,
            &request(owner, 2, ProviderWaitTimeoutKind::Infinite),
            owner,
            2,
            now(),
            next,
            |continuation| {
                lanes.rearm_running_owned(lane, reply, old_key, new_key, 2, owner, continuation)
            },
        )
        .unwrap();
    assert_eq!(
        admission,
        ProviderDispatcherWaitAdmission::Satisfied {
            wait_id: 2,
            status: STATUS_WAIT_0
        }
    );
    assert_eq!(previous.address(), old_address);
    assert_eq!(
        lanes
            .frame(lane, new_key)
            .unwrap()
            .unwrap()
            .continuation
            .address(),
        next_address
    );
    assert_eq!(backend.observations.consumed.get(), 2);
    assert!(arbiter.is_empty());
    assert!(backend.leases.is_empty());
    assert_eq!(drops.get(), 0);
    drop(previous);
    drop(lanes);
    assert_eq!(drops.get(), 2);
}
