use super::*;
use crate::dispatcher_state::DispatcherState;
use nt_kernel_exec::{
    acquire_provider_local_event_wait, consume_provider_event_wait, provider_event_wait_is_ready,
    EventKind, EventLeaseId, EventLeaseKind, EventObjectError, EventObjectId, EventObjectOwner,
    ProviderEventWaitError, TimeSnapshot,
};
use nt_provider_wait::{
    ProviderDispatcherWaitAdmission as Admission, ProviderDispatcherWaitArbiter,
    ProviderDispatcherWaitBackend, ProviderWaitOwner,
};

struct Backend<'a>(&'a mut DispatcherState);
impl ProviderDispatcherWaitBackend for Backend<'_> {
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

fn now() -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns: 10,
        system_time_100ns: 100,
        clock_generation: 0,
    }
}

fn fixture(signaled: bool) -> (Fixture, DispatcherState) {
    let mut state = DispatcherState::new(1, 1);
    let mut f = Fixture::new_with_request(|owner| {
        assert!(state
            .events
            .try_initialize(101, EventKind::Synchronization, signaled));
        let id = state
            .event_objects
            .create_provider_local(
                EventObjectOwner::provider(owner.provider_domain, owner.provider_generation),
                201,
                101,
            )
            .unwrap();
        let mut request = request(owner, 71);
        let object = ProviderWaitObject::new(
            ProviderWaitObjectType::Event,
            id.0.slot() + 1,
            id.0.generation().0.into(),
        );
        request.objects[0] = object;
        request
    });
    assert_eq!(
        f.lanes.rollback_admission(
            f.caller.dispatch.lane(),
            f.caller.binding.reply_object,
            f.capture.key()
        ),
        Ok(f.capture)
    );
    (f, state)
}

fn admit(
    f: &mut Fixture,
    state: &mut DispatcherState,
    arbiter: &mut ProviderDispatcherWaitArbiter<EventLeaseId>,
    sequence: u64,
) -> Result<
    Admission,
    (
        KernelProviderWaitAdmissionError<ProviderEventWaitError>,
        KernelProviderWaitCapture,
    ),
> {
    f.activations.admit_dispatcher_wait(
        f.caller,
        &f.pm,
        &f.catalog,
        &mut f.lanes,
        arbiter,
        &mut Backend(state),
        f.capture,
        sequence,
        now(),
        f.capture,
        |status| status,
    )
}

fn next_capture(f: &mut Fixture, id: u64) -> KernelProviderWaitCapture {
    next_capture_with(f, id, |_| {})
}

fn next_capture_with(
    f: &mut Fixture,
    id: u64,
    update: impl FnOnce(&mut ProviderWaitRequest),
) -> KernelProviderWaitCapture {
    let (_, mut attempt, _) = f.resume().unwrap().into_parts();
    let reply = f.caller.binding.reply_object;
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .observe(&mut attempt, facts(reply, false), None)
        .unwrap();
    let mut request = *f.capture.request();
    request.header.wait_id = id;
    update(&mut request);
    let next = f
        .activations
        .capture_provider_wait(
            f.caller,
            &f.pm,
            &f.catalog,
            &f.lanes,
            reply,
            f.state().progress(),
            request,
        )
        .unwrap();
    f.activations
        .recipient_mut(f.caller)
        .unwrap()
        .state
        .retain_provider_wait(request, Ok(next))
        .unwrap();
    next
}

fn repark(
    f: &mut Fixture,
    state: &mut DispatcherState,
    arbiter: &mut ProviderDispatcherWaitArbiter<EventLeaseId>,
    next: KernelProviderWaitCapture,
    sequence: u64,
) -> Result<
    (Admission, KernelProviderWaitCapture),
    (
        KernelProviderWaitAdmissionError<ProviderEventWaitError>,
        KernelProviderWaitCapture,
    ),
> {
    f.activations.repark_dispatcher_wait(
        f.caller,
        &f.pm,
        &f.catalog,
        &mut f.lanes,
        arbiter,
        &mut Backend(state),
        f.capture,
        next,
        sequence,
        now(),
        next,
        |status| status,
    )
}

#[test]
fn first_wait_publishes_real_event_readiness_and_keeps_original_recipient() {
    for signaled in [false, true] {
        let (mut f, mut state) = fixture(signaled);
        let bank = &*f.activations.recipient(f.caller).unwrap().bank as *const u64;
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        let admission = admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
        let frame = f.lanes.top(f.caller.dispatch.lane()).unwrap().unwrap();
        assert_eq!(frame.continuation, f.capture);
        assert_eq!(frame.owner, f.caller.owner());
        assert_eq!(frame.admission_sequence, 1);
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Suspended)
        );
        if signaled {
            assert_eq!(
                admission,
                Admission::Satisfied {
                    wait_id: 71,
                    status: 0
                }
            );
            assert_eq!(frame.phase, SuspensionPhase::Selected { completion: 0 });
            assert!(arbiter.is_empty());
        } else {
            assert_eq!(admission, Admission::Parked { wait_id: 71 });
            assert_eq!(frame.phase, SuspensionPhase::Waiting);
            assert_eq!(state.event_objects.live_lease_count(), 1);
            assert_eq!(state.events.set_existing(101), Some(false));
            let ready = arbiter.pop_ready(&mut Backend(&mut state)).unwrap();
            assert_eq!(ready.owner, f.caller.owner());
            assert_eq!(ready.admission_sequence, 1);
            f.lanes.select(f.capture.key(), ready.status).unwrap();
        }
        assert_eq!(state.event_objects.live_lease_count(), 0);
        assert!(!state.events.read_state(101));
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
        assert_eq!(
            &*f.activations.recipient(f.caller).unwrap().bank as *const u64,
            bank
        );
        assert!(f.activations.completion(f.caller).is_err());
        let ticket = f.resume().unwrap();
        assert_eq!(ticket.selection().completion, 0);
    }
}

#[test]
fn authority_and_dispatcher_failures_preserve_unpublished_frame_and_captured_wait() {
    for mode in 0..4 {
        let (mut f, mut state) = fixture(true);
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        if mode == 1 {
            f.pm.terminate_thread(f.caller.thread().thread_id(), 0)
                .unwrap();
        }
        if mode == 2 {
            f.catalog.retire(f.provider, 0).unwrap();
        }
        if mode == 3 {
            assert!(state.events.remove_existing(101));
        }
        let error = admit(
            &mut f,
            &mut state,
            &mut arbiter,
            if mode == 0 { 0 } else { 1 },
        )
        .unwrap_err();
        assert_eq!(error.1, f.capture);
        assert_eq!(f.state().captured_wait(), Some(f.capture));
        assert_eq!(
            f.lanes.phase(f.caller.dispatch.lane()),
            Ok(LanePhase::Running)
        );
        assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
        assert_eq!(state.event_objects.live_lease_count(), 0);
        assert!(arbiter.is_empty());
        if mode != 3 {
            assert!(state.events.read_state(101));
        }
        assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
    }
}

#[test]
fn rejected_repark_preserves_both_captures_and_does_not_consume_the_ready_event() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let next = next_capture(&mut f, 71);
    assert_ne!(next, f.capture);
    state.events.set_existing(101).unwrap();
    let before = f.lanes.top(f.caller.dispatch.lane()).unwrap().cloned();
    let error = repark(&mut f, &mut state, &mut arbiter, next, 2).unwrap_err();
    assert!(matches!(error.0, KernelProviderWaitAdmissionError::Lane(_)));
    assert_eq!(error.1, next);
    assert_eq!(
        f.lanes.top(f.caller.dispatch.lane()).unwrap().cloned(),
        before
    );
    assert_eq!(f.state().captured_wait(), Some(next));
    assert_eq!(f.state().active_resume(), Some(f.capture));
    assert_eq!(state.event_objects.live_lease_count(), 0);
    assert!(state.events.read_state(101));
    assert!(arbiter.is_empty());
    assert!(f.activations.completion(f.caller).is_err());
}

#[test]
fn repeated_waits_replace_the_frame_and_bind_same_id_reuse_to_a_fresh_observation() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let original = f.capture;
    for (id, sequence) in [(72, 2), (71, 3)] {
        let next = next_capture(&mut f, id);
        let previous = f.capture;
        state.events.set_existing(101).unwrap();
        let (admission, retired) =
            repark(&mut f, &mut state, &mut arbiter, next, sequence).unwrap();
        assert_eq!(retired, previous);
        assert_eq!(
            admission,
            Admission::Satisfied {
                wait_id: id,
                status: 0
            }
        );
        assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(1));
        assert_eq!(f.state().captured_wait(), Some(next));
        assert!(!state.events.read_state(101));
        assert_eq!(state.event_objects.live_lease_count(), 0);
        f.capture = next;
    }
    assert_ne!(f.capture, original);
    assert!(f
        .activations
        .begin_wait_resume(f.caller, &f.pm, &f.catalog, &mut f.lanes, original)
        .is_err());
    assert_eq!(f.resume().unwrap().selection().completion, 0);
    assert_eq!(references(&f.pm, f.caller.thread()), (1, 1));
}

#[test]
fn repark_rejects_paired_stale_frame_and_source_capture_before_dispatcher_consumption() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let original = f.capture;
    for (id, sequence) in [(72, 2), (71, 3)] {
        let next = next_capture(&mut f, id);
        state.events.set_existing(101).unwrap();
        repark(&mut f, &mut state, &mut arbiter, next, sequence).unwrap();
        f.capture = next;
    }
    let next = next_capture(&mut f, 73);
    let active = f.capture;
    f.lanes
        .frame_mut(f.caller.dispatch.lane(), active.key())
        .unwrap()
        .unwrap()
        .continuation = original;
    f.capture = original;
    state.events.set_existing(101).unwrap();
    let error = repark(&mut f, &mut state, &mut arbiter, next, 4).unwrap_err();
    assert!(matches!(
        error.0,
        KernelProviderWaitAdmissionError::Authority(_)
    ));
    assert_eq!(error.1, next);
    assert_eq!(f.state().active_resume(), Some(active));
    assert_eq!(f.state().captured_wait(), Some(next));
    assert!(state.events.read_state(101));
    assert_eq!(state.event_objects.live_lease_count(), 0);
}

#[test]
fn expired_repark_selects_timeout_without_consuming_an_unsignaled_event() {
    let (mut f, mut state) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    admit(&mut f, &mut state, &mut arbiter, 1).unwrap();
    let previous = f.capture;
    let next = next_capture_with(&mut f, 72, |request| {
        request.header.timeout_kind = ProviderWaitTimeoutKind::Absolute as u32;
        request.header.timeout_100ns = 1;
    });
    let (admission, retired) = repark(&mut f, &mut state, &mut arbiter, next, 2).unwrap();
    assert_eq!(retired, previous);
    assert_eq!(admission, Admission::TimedOut { wait_id: 72 });
    assert_eq!(
        f.lanes
            .top(f.caller.dispatch.lane())
            .unwrap()
            .unwrap()
            .phase,
        SuspensionPhase::Selected {
            completion: nt_provider_wait::STATUS_TIMEOUT
        }
    );
    assert_eq!(state.event_objects.live_lease_count(), 0);
    assert!(!state.events.read_state(101));
    assert!(arbiter.is_empty());
    f.capture = next;
    assert_eq!(
        f.resume().unwrap().selection().completion,
        nt_provider_wait::STATUS_TIMEOUT
    );
}

#[test]
fn foreign_manager_or_offered_continuation_cannot_publish_the_captured_wait() {
    let (mut f, mut state) = fixture(true);
    let (peer, _) = fixture(true);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    for wrong_manager in [false, true] {
        let pm = if wrong_manager { &peer.pm } else { &f.pm };
        let offered = if wrong_manager {
            f.capture
        } else {
            peer.capture
        };
        let error = f
            .activations
            .admit_dispatcher_wait(
                f.caller,
                pm,
                &f.catalog,
                &mut f.lanes,
                &mut arbiter,
                &mut Backend(&mut state),
                f.capture,
                1,
                now(),
                offered,
                |status| status,
            )
            .unwrap_err();
        assert!(matches!(
            error.0,
            KernelProviderWaitAdmissionError::Authority(_)
        ));
        assert_eq!(error.1, offered);
        assert_eq!(f.lanes.suspension_count(f.caller.dispatch.lane()), Ok(0));
        assert_eq!(f.state().captured_wait(), Some(f.capture));
        assert_eq!(state.event_objects.live_lease_count(), 0);
        assert!(state.events.read_state(101));
    }
    assert!(admit(&mut f, &mut state, &mut arbiter, 1).is_ok());
}
