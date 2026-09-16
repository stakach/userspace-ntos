use super::*;

#[path = "provider_dispatcher_expiry_tests.rs"]
mod expiry;

#[path = "provider_dispatcher_scan_tests.rs"]
mod scan;
use crate::dispatcher_state::DispatcherState;
use nt_component_suspension::{LaneHandle, SuspensionHostedClient};
use nt_kernel_exec::{EventKind, EventObjectError, TimeSnapshot};
use nt_provider_wait::{
    ProviderDispatcherWaitAdmission, ProviderDispatcherWaitArbiter, ProviderDispatcherWaitError,
    ProviderDomainIdentity, ProviderTimerKind, ProviderWaitMode, ProviderWaitRequest,
    ProviderWaitRequestMetadata, ProviderWaitTimeoutKind, ProviderWaitType,
};

const PROVIDER: ProviderDomainIdentity = ProviderDomainIdentity {
    domain: 7,
    generation: 3,
};

#[derive(Default)]
struct Backing {
    live: bool,
    acquired: usize,
    released: usize,
    retired: usize,
}

impl ProviderEventBacking for Backing {
    fn is_live_event(&self, native: u64) -> bool {
        self.live && matches!(native, 101 | 102)
    }

    fn retire_event(&mut self, events: &mut EventStore, retired: RetiredEventObject) {
        assert!(self.is_live_event(retired.native_identity));
        assert!(events.remove_existing(retired.native_identity));
        self.live = false;
        self.retired += 1;
    }

    fn lease_acquired(&mut self) {
        self.acquired += 1;
    }
    fn lease_released(&mut self) {
        self.released += 1;
    }
}

fn owner() -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: PROVIDER.domain,
        provider_generation: PROVIDER.generation,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 2,
            client_generation: 4,
            client_tid: 11,
            client_badge: 13,
        }),
        dispatch_id: 19,
    }
}

fn kernel_owner() -> ProviderWaitOwner {
    ProviderWaitOwner {
        caller: SuspensionCaller::Kernel {
            lane: LaneHandle {
                index: 2,
                generation: 4,
            },
        },
        ..owner()
    }
}

fn event(state: &mut DispatcherState) -> (EventObjectId, ProviderWaitObject) {
    assert!(state
        .events
        .try_initialize(101, EventKind::Synchronization, true));
    let id = state
        .event_objects
        .create_provider_local(
            EventObjectOwner::provider(PROVIDER.domain, PROVIDER.generation),
            201,
            101,
        )
        .unwrap();
    (id, event_object(id))
}

fn event_object(id: EventObjectId) -> ProviderWaitObject {
    ProviderWaitObject::new(
        ProviderWaitObjectType::Event,
        id.0.slot() + 1,
        u64::from(id.0.generation().0),
    )
}

fn backend(
    state: &mut DispatcherState,
    access: Option<ProviderDispatcherAccess>,
) -> ProviderDispatcherObjects<'_, Backing> {
    ProviderDispatcherObjects {
        events: &mut state.events,
        event_objects: &mut state.event_objects,
        timers: state.provider_timers.as_mut(),
        backing: Backing {
            live: true,
            ..Backing::default()
        },
        access,
    }
}

fn now() -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns: 10,
        system_time_100ns: 100,
        clock_generation: 0,
    }
}

fn wait(objects: &[ProviderWaitObject]) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: 23,
                owner: owner(),
                wait_type: ProviderWaitType::All,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Infinite,
                timeout_100ns: 0,
            },
            objects,
        )
        .unwrap();
    request
}

#[test]
fn access_checks_exact_hosted_and_kernel_owner_before_acquiring() {
    for expected in [owner(), kernel_owner()] {
        let mut state = DispatcherState::new(2, 2);
        let (_, object) = event(&mut state);
        let access = if expected.hosted_client().is_some() {
            ProviderDispatcherAccess::hosted(expected, 42).unwrap()
        } else {
            ProviderDispatcherAccess::kernel_events(expected).unwrap()
        };
        let mut objects = backend(&mut state, Some(access));
        for field in 0..7 {
            let mut wrong = expected;
            match field {
                0 => wrong.provider_domain += 1,
                1 => wrong.provider_generation += 1,
                2 => wrong.dispatch_id += 1,
                _ => match &mut wrong.caller {
                    SuspensionCaller::Hosted(client) => match field {
                        3 => client.client_pi += 1,
                        4 => client.client_generation += 1,
                        5 => client.client_tid += 1,
                        _ => client.client_badge += 1,
                    },
                    SuspensionCaller::Kernel { lane } => {
                        if field % 2 == 0 {
                            lane.generation += 1;
                        } else {
                            lane.index += 1;
                        }
                    }
                },
            }
            assert_eq!(
                objects.acquire_dispatcher_wait(wrong, object),
                Err(INVALID_PARAMETER)
            );
            assert_eq!(objects.event_objects.live_lease_count(), 0);
            assert!(objects.events.read_state(101));
            assert_eq!(objects.backing.acquired, 0);
        }
        let lease = objects.acquire_dispatcher_wait(expected, object).unwrap();
        objects.release_dispatcher_wait(lease);
        assert_eq!((objects.backing.acquired, objects.backing.released), (1, 1));
    }
    assert!(ProviderDispatcherAccess::kernel_events(owner()).is_err());
    assert!(ProviderDispatcherAccess::hosted(kernel_owner(), 42).is_err());
    assert!(ProviderDispatcherAccess::hosted(owner(), 0).is_err());
}

#[test]
fn kernel_scope_rejects_projected_events_and_timers_without_consuming() {
    let mut state = DispatcherState::new(2, 2);
    let (_, local) = event(&mut state);
    let projected = state
        .event_objects
        .create(EventObjectOwner::new(42, 4), 102)
        .unwrap();
    state
        .event_objects
        .retain_pointer_or_install(projected, 0xD000)
        .unwrap();
    assert!(state
        .events
        .try_initialize(102, EventKind::Synchronization, true));
    let mut timers = ProviderTimerTable::new(PROVIDER).unwrap();
    let timer = timers
        .publish(301, ProviderTimerKind::Synchronization)
        .unwrap();
    timers.set_local(301, 0, 0, now()).unwrap();
    assert!(timers.expire_next_due(now()).is_some());
    state.provider_timers = Some(timers);
    let expected = kernel_owner();
    let mut objects = backend(
        &mut state,
        Some(ProviderDispatcherAccess::kernel_events(expected).unwrap()),
    );
    for object in [event_object(projected), timer.wait_object()] {
        assert_eq!(
            objects.acquire_dispatcher_wait(expected, object),
            Err(INVALID_PARAMETER)
        );
        assert_eq!(objects.event_objects.live_lease_count(), 0);
        assert!(objects.events.read_state(102));
        assert_eq!(objects.timers.as_ref().unwrap().read_state(timer), Ok(true));
        assert_eq!(objects.backing.acquired, 0);
    }
    let lease = objects.acquire_dispatcher_wait(expected, local).unwrap();
    objects.release_dispatcher_wait(lease);
}

#[test]
fn hosted_projection_requires_exact_process_generation_and_pointer() {
    for (pid, generation, pointer, accepted) in [
        (42, 4, true, true),
        (43, 4, true, false),
        (42, 5, true, false),
        (42, 4, false, false),
    ] {
        let mut state = DispatcherState::new(1, 1);
        let id = state
            .event_objects
            .create(EventObjectOwner::new(pid, generation), 101)
            .unwrap();
        assert!(state
            .events
            .try_initialize(101, EventKind::Synchronization, true));
        if pointer {
            state
                .event_objects
                .retain_pointer_or_install(id, 0xD000)
                .unwrap();
        }
        let mut objects = backend(
            &mut state,
            Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
        );
        let result = objects.acquire_dispatcher_wait(owner(), event_object(id));
        if accepted {
            let lease = result.unwrap();
            assert!(objects.dispatcher_is_ready(lease));
            objects.release_dispatcher_wait(lease);
        } else {
            assert_eq!(result, Err(INVALID_PARAMETER));
            assert_eq!(objects.backing.acquired, 0);
        }
        assert_eq!(objects.event_objects.live_lease_count(), 0);
        assert!(objects.events.read_state(101));
    }
}

#[test]
fn missing_namespace_or_backing_refuses_lease_before_instrumentation() {
    for missing_namespace in [false, true] {
        let mut state = DispatcherState::new(1, 1);
        let (_, object) = event(&mut state);
        let mut objects = backend(
            &mut state,
            Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
        );
        if missing_namespace {
            objects.backing.live = false;
        } else {
            assert!(objects.events.remove_existing(101));
        }
        assert_eq!(
            objects.acquire_dispatcher_wait(owner(), object),
            Err(INVALID_PARAMETER)
        );
        assert_eq!(objects.event_objects.live_lease_count(), 0);
        assert_eq!(
            (
                objects.backing.acquired,
                objects.backing.released,
                objects.backing.retired
            ),
            (0, 0, 0)
        );
    }
}

#[test]
fn selector_scope_reuses_lease_and_retires_backing_only_after_last_release() {
    let mut state = DispatcherState::new(1, 2);
    let (id, object) = event(&mut state);
    let leases = {
        let mut objects = backend(
            &mut state,
            Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
        );
        [
            objects.acquire_dispatcher_wait(owner(), object).unwrap(),
            objects.acquire_dispatcher_wait(owner(), object).unwrap(),
        ]
    };
    assert_eq!(state.event_objects.request_delete(id), Ok(None));
    let mut objects = backend(&mut state, None);
    assert_eq!(
        objects.acquire_dispatcher_wait(owner(), object),
        Err(INVALID_PARAMETER)
    );
    assert!(objects.dispatcher_is_ready(leases[0]));
    objects.consume_ready_dispatcher(leases[0]);
    objects.release_dispatcher_wait(leases[0]);
    assert_eq!(objects.backing.retired, 0);
    assert!(objects.events.query_existing(101).is_some());
    assert!(!objects.dispatcher_is_ready(leases[1]));
    objects.release_dispatcher_wait(leases[1]);
    assert_eq!(objects.backing.retired, 1);
    assert!(!objects.backing.live);
    assert_eq!(objects.events.query_existing(101), None);
    assert_eq!(
        objects.event_objects.snapshot(id),
        Err(EventObjectError::StaleObject)
    );
    assert_eq!(objects.backing.released, 2);
}

#[test]
fn mixed_timer_wait_all_preserves_event_until_timer_is_ready() {
    let mut state = DispatcherState::new(1, 2);
    let (_, event) = event(&mut state);
    let mut timers = ProviderTimerTable::new(PROVIDER).unwrap();
    let timer = timers
        .publish(301, ProviderTimerKind::Synchronization)
        .unwrap();
    state.provider_timers = Some(timers);
    let mut objects = backend(
        &mut state,
        Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
    );
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    assert_eq!(
        arbiter.admit(
            &mut objects,
            &wait(&[event, timer.wait_object()]),
            owner(),
            1,
            now()
        ),
        Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 23 })
    );
    assert!(arbiter.pop_ready(&mut objects).is_none());
    assert!(objects.events.read_state(101));
    objects
        .timers
        .as_mut()
        .unwrap()
        .set_local(301, 0, 0, now())
        .unwrap();
    objects.access = None;
    assert_eq!(objects.expire_timers(now()), 1);
    assert_eq!(objects.expire_timers(now()), 0);
    assert_eq!(arbiter.pop_ready(&mut objects).unwrap().status, 0);
    assert!(!objects.events.read_state(101));
    assert_eq!(
        objects.timers.as_ref().unwrap().read_state(timer),
        Ok(false)
    );
    assert_eq!(objects.event_objects.live_lease_count(), 0);
    assert_eq!((objects.backing.acquired, objects.backing.released), (2, 2));
    assert!(objects
        .timers
        .as_mut()
        .unwrap()
        .request_retire_local(301)
        .unwrap()
        .is_some());
    assert!(arbiter.is_empty());
}

#[test]
fn timer_owner_mismatch_and_second_object_failure_preserve_event_signal() {
    let mut state = DispatcherState::new(1, 2);
    let (_, event) = event(&mut state);
    let mut timers = ProviderTimerTable::new(PROVIDER).unwrap();
    let timer = timers
        .publish(301, ProviderTimerKind::Synchronization)
        .unwrap();
    state.provider_timers = Some(timers);
    let mut objects = backend(
        &mut state,
        Some(ProviderDispatcherAccess::hosted(owner(), 42).unwrap()),
    );
    let mut wrong = owner();
    wrong.dispatch_id += 1;
    assert_eq!(
        objects.acquire_dispatcher_wait(wrong, timer.wait_object()),
        Err(INVALID_PARAMETER)
    );
    assert_eq!(objects.backing.acquired, 0);
    let mut stale = timer.wait_object();
    stale.object_generation += 1;
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    assert_eq!(
        arbiter.admit(&mut objects, &wait(&[event, stale]), owner(), 1, now()),
        Err(ProviderDispatcherWaitError::Backend(INVALID_PARAMETER))
    );
    assert!(objects.events.read_state(101));
    assert_eq!(objects.event_objects.live_lease_count(), 0);
    assert_eq!((objects.backing.acquired, objects.backing.released), (1, 1));
    assert!(objects
        .timers
        .as_mut()
        .unwrap()
        .request_retire_local(301)
        .unwrap()
        .is_some());
    assert!(arbiter.is_empty());
}
