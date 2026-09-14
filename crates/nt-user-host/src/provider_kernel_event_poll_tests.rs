use super::*;
use crate::dispatcher_state::DispatcherState;
use nt_kernel_exec::{
    acquire_provider_local_event_wait, consume_provider_event_wait, provider_event_wait_is_ready,
    EventKind, EventLeaseId, EventLeaseKind, EventObjectError, EventObjectId, EventObjectOwner,
    ProviderEventWaitError,
};
use nt_provider_wait::{
    ProviderDispatcherWaitArbiter, ProviderDispatcherWaitBackend, ProviderDispatcherWaitError,
    ProviderWaitMode, ProviderWaitObject, ProviderWaitObjectType, ProviderWaitOwner,
    ProviderWaitRequestMetadata, ProviderWaitTimeoutKind, ProviderWaitType,
    PROVIDER_WAIT_MAX_OBJECTS, STATUS_TIMEOUT,
};

const WAIT_MESSAGE_INFO: u64 = 0x779 << 12;

impl Fixture {
    fn wait_envelope(&self) -> KernelProviderServiceEnvelope {
        KernelProviderServiceEnvelope {
            message_info: WAIT_MESSAGE_INFO,
            ..self.envelope()
        }
    }
}

fn request(f: &Fixture) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: 71,
                owner: f.caller.owner(),
                wait_type: ProviderWaitType::Any,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Poll,
                timeout_100ns: 0,
            },
            &[nt_provider_wait::ProviderWaitObject::new(
                ProviderWaitObjectType::Event,
                81,
                1,
            )],
        )
        .unwrap();
    request
}

fn validate(
    f: &Fixture,
    caller: KernelProviderCaller,
    envelope: KernelProviderServiceEnvelope,
    request: &ProviderWaitRequest,
) -> Result<(), u32> {
    let lane = f.caller.dispatch.lane();
    let before = (
        f.lanes.phase(lane),
        f.lanes.active_dispatch_identity(lane),
        f.lanes.external_depth(lane),
        f.lanes.suspension_count(lane),
        references(&f.pm, f.caller.thread()),
        f.activations.completion(f.caller),
    );
    let result = f.activations.validate_event_poll(
        caller,
        &f.pm,
        &f.catalog,
        &f.lanes,
        envelope,
        WAIT_MESSAGE_INFO,
        request,
    );
    assert_eq!(
        before,
        (
            f.lanes.phase(lane),
            f.lanes.active_dispatch_identity(lane),
            f.lanes.external_depth(lane),
            f.lanes.suspension_count(lane),
            references(&f.pm, f.caller.thread()),
            f.activations.completion(f.caller),
        )
    );
    result
}

#[test]
fn event_poll_accepts_any_and_all_without_parking_or_completing_activation() {
    let f = Fixture::new();
    for count in [1, 2, PROVIDER_WAIT_MAX_OBJECTS] {
        for wait_type in [ProviderWaitType::Any, ProviderWaitType::All] {
            let mut request = request(&f);
            let metadata = ProviderWaitRequestMetadata {
                wait_id: request.header.wait_id,
                owner: f.caller.owner(),
                wait_type,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Poll,
                timeout_100ns: 0,
            };
            let objects: alloc::vec::Vec<_> = (0..count)
                .map(|index| {
                    nt_provider_wait::ProviderWaitObject::new(
                        ProviderWaitObjectType::Event,
                        index as u64 + 1,
                        1,
                    )
                })
                .collect();
            request.begin(metadata, &objects).unwrap();
            assert_eq!(validate(&f, f.caller, f.wait_envelope(), &request), Ok(()));
        }
    }
    assert_eq!(
        f.lanes.phase(f.caller.dispatch.lane()),
        Ok(LanePhase::Running)
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}

#[test]
fn event_poll_requires_exact_envelope() {
    let f = Fixture::new();
    let request = request(&f);
    let envelope = f.wait_envelope();
    assert_eq!(
        validate(&f, f.caller, f.envelope(), &request),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        validate(
            &f,
            f.caller,
            KernelProviderServiceEnvelope {
                message_info: WAIT_MESSAGE_INFO | 4,
                ..envelope
            },
            &request,
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    for bit in 0..64 {
        assert_eq!(
            validate(
                &f,
                f.caller,
                KernelProviderServiceEnvelope {
                    message_info: envelope.message_info ^ (1 << bit),
                    ..envelope
                },
                &request,
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    for wrong in [
        KernelProviderServiceEnvelope {
            badge: 4,
            ..envelope
        },
        KernelProviderServiceEnvelope {
            reply_cap: 0,
            ..envelope
        },
        KernelProviderServiceEnvelope {
            reply_cap: envelope.reply_cap + 1,
            ..envelope
        },
    ] {
        assert_eq!(
            validate(&f, f.caller, wrong, &request),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
}

#[test]
fn event_poll_requires_exact_request_owner_and_valid_abi() {
    let f = Fixture::new();
    for field in 0..9 {
        let mut request = request(&f);
        match field {
            0 => request.header.provider_domain += 1,
            1 => request.header.provider_generation += 1,
            2 => request.header.dispatch_id += 1,
            3 => request.header.kernel_lane_index += 1,
            4 => request.header.kernel_lane_generation += 1,
            5 => request.header.wait_id = 0,
            6 => request.header.reserved = 1,
            7 => request.header.object_count = 0,
            8 => request.objects[1] = request.objects[0],
            _ => unreachable!(),
        }
        assert_eq!(
            validate(&f, f.caller, f.wait_envelope(), &request),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    let mut forged = f.caller;
    forged.binding.executor_id += 1;
    assert_eq!(
        validate(&f, forged, f.wait_envelope(), &request(&f)),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn event_poll_refuses_blocking_user_mode_and_alertable_waits() {
    let f = Fixture::new();
    for (kind, timeout) in [
        (ProviderWaitTimeoutKind::Infinite, 0),
        (ProviderWaitTimeoutKind::Relative, -1),
        (ProviderWaitTimeoutKind::Absolute, 1),
    ] {
        let mut request = request(&f);
        request.header.timeout_kind = kind as u32;
        request.header.timeout_100ns = timeout;
        assert_eq!(
            validate(&f, f.caller, f.wait_envelope(), &request),
            Err(0xc000_00bb)
        );
    }
    for alertable in [false, true] {
        let mut request = request(&f);
        if alertable {
            request.header.alertable = 1;
        } else {
            request.header.wait_mode = ProviderWaitMode::User as u32;
        }
        assert_eq!(
            validate(&f, f.caller, f.wait_envelope(), &request),
            Err(0xc000_00bb)
        );
    }
}

#[test]
fn event_poll_rejects_every_non_event_type_and_mixed_array() {
    let f = Fixture::new();
    for object_type in [
        ProviderWaitObjectType::Semaphore,
        ProviderWaitObjectType::Timer,
        ProviderWaitObjectType::Process,
        ProviderWaitObjectType::Thread,
        ProviderWaitObjectType::File,
    ] {
        for mixed in [false, true] {
            let mut request = request(&f);
            let index = usize::from(mixed);
            request.objects[index] = nt_provider_wait::ProviderWaitObject::new(object_type, 82, 1);
            request.header.object_count = index as u32 + 1;
            request.header.request_size +=
                (index * core::mem::size_of::<nt_provider_wait::ProviderWaitObject>()) as u32;
            assert_eq!(
                validate(&f, f.caller, f.wait_envelope(), &request),
                Err(0xc000_00bb)
            );
        }
    }
}

#[test]
fn event_poll_refuses_suspended_replaced_and_completed_activation() {
    let mut f = Fixture::new();
    let request = request(&f);
    let lane = f.caller.dispatch.lane();
    let reply = f.caller.binding.reply_object;
    f.lanes.suspend_running(lane, reply, 91).unwrap();
    assert_eq!(
        validate(&f, f.caller, f.wait_envelope(), &request),
        Err(STATUS_INVALID_HANDLE)
    );
    f.lanes.resume_external(lane, reply, 91).unwrap();
    assert_eq!(validate(&f, f.caller, f.wait_envelope(), &request), Ok(()));
    f.lanes.complete_external(lane, reply, 91).unwrap();
    f.lanes.begin_dispatch(lane, reply).unwrap();
    assert_eq!(
        validate(&f, f.caller, f.wait_envelope(), &request),
        Err(STATUS_INVALID_HANDLE)
    );

    let mut f = Fixture::new();
    let request = self::request(&f);
    let receipt = f
        .activations
        .record_completion(f.caller, &f.pm, &f.catalog, &mut f.lanes, 0)
        .unwrap();
    assert_eq!(
        validate(&f, f.caller, f.wait_envelope(), &request),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(f.activations.completion(f.caller), Ok(receipt));
}

#[test]
fn event_poll_refuses_retired_provider_and_exited_caller_without_releasing_references() {
    let mut f = Fixture::new();
    let request = request(&f);
    f.catalog.retire(f.provider, 0).unwrap();
    assert_eq!(
        validate(&f, f.caller, f.wait_envelope(), &request),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));

    let mut f = Fixture::new();
    let request = self::request(&f);
    f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
        .unwrap();
    assert!(validate(&f, f.caller, f.wait_envelope(), &request).is_err());
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}

struct EventBackend<'a>(&'a mut DispatcherState);

impl ProviderDispatcherWaitBackend for EventBackend<'_> {
    type Lease = EventLeaseId;
    type Error = ProviderEventWaitError;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<EventLeaseId, Self::Error> {
        let id = EventObjectId::from_wire_parts(object.object_id, object.object_generation).ok_or(
            ProviderEventWaitError::Registry(EventObjectError::StaleObject),
        )?;
        acquire_provider_local_event_wait(
            &mut self.0.event_objects,
            &self.0.events,
            id,
            EventObjectOwner::provider(owner.provider_domain, owner.provider_generation),
        )
    }

    fn dispatcher_is_ready(&self, lease: EventLeaseId) -> bool {
        provider_event_wait_is_ready(&self.0.event_objects, &self.0.events, lease).unwrap()
    }

    fn consume_ready_dispatcher(&mut self, lease: EventLeaseId) {
        assert!(
            consume_provider_event_wait(&self.0.event_objects, &mut self.0.events, lease).unwrap()
        );
    }

    fn release_dispatcher_wait(&mut self, lease: EventLeaseId) {
        if let Some(retired) = self
            .0
            .event_objects
            .release_wait(lease, EventLeaseKind::ProviderWait)
            .unwrap()
        {
            assert!(self.0.events.remove_existing(retired.native_identity));
        }
    }
}

fn event(
    f: &Fixture,
    state: &mut DispatcherState,
    native: u64,
    kind: EventKind,
    signaled: bool,
) -> (EventObjectId, ProviderWaitObject) {
    assert!(state.events.try_initialize(native, kind, signaled));
    let owner = f.caller.owner();
    let id = state
        .event_objects
        .create_provider_local(
            EventObjectOwner::provider(owner.provider_domain, owner.provider_generation),
            native + 100,
            native,
        )
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

fn poll(
    f: &Fixture,
    state: &mut DispatcherState,
    arbiter: &ProviderDispatcherWaitArbiter<EventLeaseId>,
    objects: &[ProviderWaitObject],
    wait_type: ProviderWaitType,
) -> Result<i32, ProviderDispatcherWaitError<ProviderEventWaitError>> {
    let mut request = request(f);
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id: request.header.wait_id,
                owner: f.caller.owner(),
                wait_type,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind: ProviderWaitTimeoutKind::Poll,
                timeout_100ns: 0,
            },
            objects,
        )
        .unwrap();
    assert_eq!(validate(f, f.caller, f.wait_envelope(), &request), Ok(()));
    let result = arbiter.poll(&mut EventBackend(state), &request, f.caller.owner());
    assert_eq!(validate(f, f.caller, f.wait_envelope(), &request), Ok(()));
    assert_eq!(
        f.lanes.phase(f.caller.dispatch.lane()),
        Ok(LanePhase::Running)
    );
    assert_eq!(
        f.lanes.active_dispatch_identity(f.caller.dispatch.lane()),
        Ok(Some(f.caller.dispatch))
    );
    assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
    assert_eq!(f.lanes.external_depth(f.caller.dispatch.lane()), Ok(0));
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    assert!(f.activations.completion(f.caller).is_err());
    assert_eq!(state.event_objects.live_lease_count(), 0);
    assert!(arbiter.is_empty());
    result
}

#[test]
fn authenticated_kernel_poll_consumes_actual_event_state_without_wait_registration() {
    for kind in [EventKind::Notification, EventKind::Synchronization] {
        let f = Fixture::new();
        let mut state = DispatcherState::new(1, 1);
        let (_, object) = event(&f, &mut state, 101, kind, false);
        let arbiter = ProviderDispatcherWaitArbiter::new();
        assert_eq!(
            poll(&f, &mut state, &arbiter, &[object], ProviderWaitType::Any),
            Ok(STATUS_TIMEOUT)
        );
        assert_eq!(state.events.set_existing(101), Some(false));
        assert_eq!(
            poll(&f, &mut state, &arbiter, &[object], ProviderWaitType::Any),
            Ok(0)
        );
        assert_eq!(
            state.events.read_state(101),
            kind == EventKind::Notification
        );
        assert_eq!(
            poll(&f, &mut state, &arbiter, &[object], ProviderWaitType::Any),
            Ok(if kind == EventKind::Notification {
                0
            } else {
                STATUS_TIMEOUT
            })
        );
    }
}

#[test]
fn authenticated_kernel_poll_wait_all_never_partially_consumes() {
    let f = Fixture::new();
    let mut state = DispatcherState::new(2, 2);
    let (_, first) = event(&f, &mut state, 101, EventKind::Synchronization, true);
    let (_, second) = event(&f, &mut state, 102, EventKind::Synchronization, false);
    let arbiter = ProviderDispatcherWaitArbiter::new();
    assert_eq!(
        poll(
            &f,
            &mut state,
            &arbiter,
            &[first, second],
            ProviderWaitType::All
        ),
        Ok(STATUS_TIMEOUT)
    );
    assert!(state.events.read_state(101));
    assert_eq!(state.events.set_existing(102), Some(false));
    assert_eq!(
        poll(
            &f,
            &mut state,
            &arbiter,
            &[first, second],
            ProviderWaitType::All
        ),
        Ok(0)
    );
    assert!(!state.events.read_state(101));
    assert!(!state.events.read_state(102));
}

#[test]
fn authenticated_kernel_poll_missing_backing_rolls_back_exact_leases() {
    let f = Fixture::new();
    let mut state = DispatcherState::new(2, 2);
    let (first_id, first) = event(&f, &mut state, 101, EventKind::Synchronization, true);
    let (second_id, second) = event(&f, &mut state, 102, EventKind::Synchronization, true);
    assert!(state.events.remove_existing(102));
    let snapshots = [
        state.event_objects.snapshot(first_id),
        state.event_objects.snapshot(second_id),
    ];
    let arbiter = ProviderDispatcherWaitArbiter::new();
    for wait_type in [ProviderWaitType::Any, ProviderWaitType::All] {
        assert_eq!(
            poll(&f, &mut state, &arbiter, &[first, second], wait_type),
            Err(ProviderDispatcherWaitError::Backend(
                ProviderEventWaitError::MissingBacking
            ))
        );
        assert!(state.events.read_state(101));
        assert_eq!(
            snapshots,
            [
                state.event_objects.snapshot(first_id),
                state.event_objects.snapshot(second_id)
            ]
        );
    }
}
