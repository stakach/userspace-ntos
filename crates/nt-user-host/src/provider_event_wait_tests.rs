use super::DispatcherState;
use nt_component_suspension::{SuspensionCaller, SuspensionHostedClient};
use nt_kernel_exec::{
    provider_event_wait_is_ready, EventKind, EventLeaseId, EventLeaseKind, EventObjectError,
    EventObjectId, EventObjectOwner, TimeSnapshot,
};
use nt_provider_wait::{
    ProviderDispatcherWaitAdmission, ProviderDispatcherWaitArbiter, ProviderDispatcherWaitBackend,
    ProviderDispatcherWaitError, ProviderWaitMode, ProviderWaitObject, ProviderWaitObjectType,
    ProviderWaitOwner, ProviderWaitRequest, ProviderWaitRequestMetadata, ProviderWaitTimeoutKind,
    ProviderWaitType, STATUS_TIMEOUT,
};

const PROVIDER: EventObjectOwner = EventObjectOwner::provider(7, 3);

struct Backend<'a> {
    state: &'a mut DispatcherState,
    last_acquired: Option<EventLeaseId>,
}

impl<'a> Backend<'a> {
    fn new(state: &'a mut DispatcherState) -> Self {
        Self {
            state,
            last_acquired: None,
        }
    }
}

struct Backing;

impl crate::provider_dispatcher_backend::ProviderEventBacking for Backing {
    fn is_live_event(&self, _: u64) -> bool {
        true
    }

    fn retire_event(
        &mut self,
        events: &mut nt_kernel_exec::EventStore,
        retired: nt_kernel_exec::RetiredEventObject,
    ) {
        assert!(events.remove_existing(retired.native_identity));
    }
}

impl Backend<'_> {
    fn objects(
        &mut self,
    ) -> crate::provider_dispatcher_backend::ProviderDispatcherObjects<'_, Backing> {
        crate::provider_dispatcher_backend::ProviderDispatcherObjects {
            events: &mut self.state.events,
            event_objects: &mut self.state.event_objects,
            timers: self.state.provider_timers.as_mut(),
            backing: Backing,
            access: Some(
                crate::provider_dispatcher_backend::ProviderDispatcherAccess::hosted(owner(), 2)
                    .unwrap(),
            ),
        }
    }
}

impl ProviderDispatcherWaitBackend for Backend<'_> {
    type Lease = crate::provider_dispatcher_backend::ProviderDispatcherLease;
    type Error = u32;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<Self::Lease, u32> {
        let lease = self.objects().acquire_dispatcher_wait(owner, object)?;
        let Self::Lease::Event(event) = lease else {
            panic!("Event test acquired a Timer")
        };
        self.last_acquired = Some(event);
        Ok(lease)
    }

    fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool {
        crate::provider_dispatcher_backend::dispatcher_lease_is_ready(
            &self.state.event_objects,
            &self.state.events,
            self.state.provider_timers.as_ref(),
            lease,
        )
    }

    fn consume_ready_dispatcher(&mut self, lease: Self::Lease) {
        self.objects().consume_ready_dispatcher(lease);
    }

    fn release_dispatcher_wait(&mut self, lease: Self::Lease) {
        self.objects().release_dispatcher_wait(lease);
    }
}

fn owner() -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: 7,
        provider_generation: 3,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 2,
            client_generation: 4,
            client_tid: 11,
            client_badge: 13,
        }),
        dispatch_id: 19,
    }
}

fn event(
    state: &mut DispatcherState,
    native: u64,
    kind: EventKind,
    signaled: bool,
) -> (EventObjectId, ProviderWaitObject) {
    assert!(state.events.try_initialize(native, kind, signaled));
    let id = state
        .event_objects
        .create_provider_local(PROVIDER, native + 100, native)
        .unwrap();
    (
        id,
        ProviderWaitObject::new(
            ProviderWaitObjectType::Event,
            id.0.slot() + 1,
            u64::from(id.0.generation().0),
        ),
    )
}

fn request(
    objects: &[ProviderWaitObject],
    wait_type: ProviderWaitType,
    timeout_kind: ProviderWaitTimeoutKind,
) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: 23,
                owner: owner(),
                wait_type,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind,
                timeout_100ns: 0,
            },
            objects,
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

#[test]
fn ready_admission_consumes_synchronization_but_preserves_notification_event() {
    for kind in [EventKind::Synchronization, EventKind::Notification] {
        let mut state = DispatcherState::new(1, 1);
        let (id, object) = event(&mut state, 101, kind, true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut backend = Backend::new(&mut state);
        assert_eq!(
            arbiter.admit(
                &mut backend,
                &request(
                    &[object],
                    ProviderWaitType::Any,
                    ProviderWaitTimeoutKind::Infinite
                ),
                owner(),
                1,
                now(),
            ),
            Ok(ProviderDispatcherWaitAdmission::Satisfied {
                wait_id: 23,
                status: 0
            })
        );
        assert_eq!(
            backend.state.events.read_state(101),
            kind == EventKind::Notification
        );
        assert_eq!(
            backend
                .state
                .event_objects
                .snapshot(id)
                .unwrap()
                .provider_wait_leases,
            0
        );
        assert_eq!(backend.state.event_objects.live_lease_count(), 0);
        assert!(arbiter.is_empty());
    }
}

#[test]
fn poll_wait_any_selects_ready_index_without_retaining_leases() {
    let mut state = DispatcherState::new(2, 2);
    let (_, first) = event(&mut state, 101, EventKind::Synchronization, false);
    let (_, second) = event(&mut state, 102, EventKind::Synchronization, true);
    let arbiter = ProviderDispatcherWaitArbiter::new();
    let mut backend = Backend::new(&mut state);
    let poll = request(
        &[first, second],
        ProviderWaitType::Any,
        ProviderWaitTimeoutKind::Poll,
    );
    assert_eq!(arbiter.poll(&mut backend, &poll, owner()), Ok(1));
    assert!(!backend.state.events.read_state(102));
    assert_eq!(
        arbiter.poll(&mut backend, &poll, owner()),
        Ok(STATUS_TIMEOUT)
    );
    assert_eq!(backend.state.event_objects.live_lease_count(), 0);
    assert_eq!(arbiter.lease_count(), 0);
}

#[test]
fn wait_all_does_not_consume_any_event_until_every_backing_is_ready() {
    let mut state = DispatcherState::new(2, 2);
    let (first_id, first) = event(&mut state, 101, EventKind::Synchronization, true);
    let (second_id, second) = event(&mut state, 102, EventKind::Synchronization, false);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut backend = Backend::new(&mut state);
    let wait = request(
        &[first, second],
        ProviderWaitType::All,
        ProviderWaitTimeoutKind::Infinite,
    );
    assert_eq!(
        arbiter.admit(&mut backend, &wait, owner(), 1, now()),
        Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 23 })
    );
    assert_eq!(arbiter.lease_count(), 2);
    assert!(arbiter.pop_ready(&mut backend).is_none());
    assert!(backend.state.events.read_state(101));
    for id in [first_id, second_id] {
        assert_eq!(
            backend
                .state
                .event_objects
                .snapshot(id)
                .unwrap()
                .provider_wait_leases,
            1
        );
    }
    assert_eq!(backend.state.events.set_existing(102), Some(false));
    let completion = arbiter.pop_ready(&mut backend).unwrap();
    assert_eq!(completion.wait_id, 23);
    assert_eq!(completion.owner, owner());
    assert_eq!(completion.status, 0);
    assert!(!completion.cancelled);
    assert!(!backend.state.events.read_state(101));
    assert!(!backend.state.events.read_state(102));
    assert_eq!(backend.state.event_objects.live_lease_count(), 0);
    assert!(arbiter.is_empty());
}

#[test]
fn missing_second_backing_rolls_back_admission_and_poll_without_consuming_first() {
    for poll in [false, true] {
        let mut state = DispatcherState::new(2, 2);
        let (first_id, first) = event(&mut state, 101, EventKind::Synchronization, true);
        let (second_id, second) = event(&mut state, 102, EventKind::Synchronization, true);
        assert!(state.events.remove_existing(102));
        let snapshots = [
            state.event_objects.snapshot(first_id).unwrap(),
            state.event_objects.snapshot(second_id).unwrap(),
        ];
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let mut backend = Backend::new(&mut state);
        let wait = request(
            &[first, second],
            ProviderWaitType::All,
            if poll {
                ProviderWaitTimeoutKind::Poll
            } else {
                ProviderWaitTimeoutKind::Infinite
            },
        );
        let error = ProviderDispatcherWaitError::Backend(0xC000_000D);
        if poll {
            assert_eq!(arbiter.poll(&mut backend, &wait, owner()), Err(error));
        } else {
            assert_eq!(
                arbiter.admit(&mut backend, &wait, owner(), 1, now()),
                Err(error)
            );
        }
        assert!(backend.state.events.read_state(101));
        for (id, before) in [first_id, second_id].into_iter().zip(snapshots) {
            assert_eq!(backend.state.event_objects.snapshot(id).unwrap(), before);
        }
        assert_eq!(backend.state.event_objects.live_lease_count(), 0);
        assert_eq!(arbiter.lease_count(), 0);
        assert!(arbiter.is_empty());
    }
}

#[test]
fn deletion_retains_parked_backing_until_exact_wait_completion() {
    let mut state = DispatcherState::new(1, 1);
    let (id, object) = event(&mut state, 101, EventKind::Synchronization, false);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let mut backend = Backend::new(&mut state);
    let wait = request(
        &[object],
        ProviderWaitType::Any,
        ProviderWaitTimeoutKind::Infinite,
    );
    assert_eq!(
        arbiter.admit(&mut backend, &wait, owner(), 1, now()),
        Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 23 })
    );
    assert_eq!(backend.state.event_objects.request_delete(id), Ok(None));
    assert_eq!(
        backend
            .state
            .event_objects
            .snapshot(id)
            .unwrap()
            .provider_wait_leases,
        1
    );
    assert!(arbiter.pop_ready(&mut backend).is_none());
    assert_eq!(backend.state.events.set_existing(101), Some(false));
    assert_eq!(arbiter.pop_ready(&mut backend).unwrap().status, 0);
    assert_eq!(
        backend.state.event_objects.snapshot(id),
        Err(EventObjectError::StaleObject)
    );
    assert_eq!(backend.state.events.set_existing(101), None);
    assert_eq!(backend.state.event_objects.live_lease_count(), 0);
    assert!(arbiter.is_empty());
}

#[test]
fn moving_dispatcher_state_preserves_exact_parked_lease_and_backing() {
    let mut state = DispatcherState::new(1, 1);
    let (id, object) = event(&mut state, 101, EventKind::Synchronization, false);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let lease = {
        let mut backend = Backend::new(&mut state);
        let wait = request(
            &[object],
            ProviderWaitType::Any,
            ProviderWaitTimeoutKind::Infinite,
        );
        assert_eq!(
            arbiter.admit(&mut backend, &wait, owner(), 71, now()),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 23 })
        );
        backend.last_acquired.unwrap()
    };
    let before = state.event_objects.snapshot(id).unwrap();
    let mut live = state;
    assert_eq!(live.event_objects.snapshot(id).unwrap(), before);
    assert_eq!(
        live.event_objects
            .event_for_lease(lease, EventLeaseKind::ProviderWait),
        Ok(id)
    );
    assert_eq!(
        provider_event_wait_is_ready(&live.event_objects, &live.events, lease),
        Ok(false)
    );
    assert_eq!(live.events.set_existing(101), Some(false));
    let mut backend = Backend::new(&mut live);
    let completion = arbiter.pop_ready(&mut backend).unwrap();
    assert_eq!(completion.admission_sequence, 71);
    assert_eq!(completion.owner, owner());
    assert_eq!(completion.status, 0);
    assert!(!backend.state.events.read_state(101));
    assert!(backend
        .state
        .event_objects
        .event_for_lease(lease, EventLeaseKind::ProviderWait)
        .is_err());
    assert_eq!(backend.state.event_objects.live_lease_count(), 0);
    assert_eq!(arbiter.lease_count(), 0);
}
