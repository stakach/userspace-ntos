use super::*;
use crate::dispatcher_state::DispatcherState;
use crate::provider_dispatcher_backend::{
    ProviderDispatcherAccess, ProviderDispatcherLease, ProviderDispatcherObjects,
    ProviderEventBacking,
};
use nt_component_suspension::{LaneBinding, SuspensionHostedClient};
use nt_kernel_exec::{EventKind, EventObjectOwner, EventStore, RetiredEventObject, TimeSnapshot};
use nt_provider_wait::{
    ProviderDispatcherWaitAdmission, ProviderDispatcherWaitArbiter, ProviderWaitMode,
    ProviderWaitObject, ProviderWaitObjectType, ProviderWaitOwner, ProviderWaitRequest,
    ProviderWaitRequestMetadata, ProviderWaitTimeoutKind, ProviderWaitType,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Continuation {
    Hosted(SuspensionHostedClient),
    Kernel(LaneHandle),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Completion {
    Hosted(i32),
    Kernel(i32),
}

type Lanes = ComponentSuspensionLanes<Continuation, Completion, ()>;

fn route(
    lane: LaneHandle,
    continuation: &Continuation,
    completion: &ProviderDispatcherWaitCompletion,
) -> Result<Completion, &'static str> {
    match (*continuation, completion.owner.caller) {
        (Continuation::Hosted(retained), SuspensionCaller::Hosted(caller))
            if retained == caller =>
        {
            Ok(Completion::Hosted(completion.status))
        }
        (Continuation::Kernel(retained), SuspensionCaller::Kernel { lane: caller })
            if retained == caller && retained == lane =>
        {
            Ok(Completion::Kernel(completion.status))
        }
        _ => Err("continuation identity"),
    }
}

struct Backing;

impl ProviderEventBacking for Backing {
    fn is_live_event(&self, native_identity: u64) -> bool {
        native_identity == 101
    }

    fn retire_event(&mut self, events: &mut EventStore, retired: RetiredEventObject) {
        assert!(events.remove_existing(retired.native_identity));
    }
}

fn backend(
    state: &mut DispatcherState,
    owner: Option<ProviderWaitOwner>,
) -> ProviderDispatcherObjects<'_, Backing> {
    ProviderDispatcherObjects {
        events: &mut state.events,
        event_objects: &mut state.event_objects,
        timers: state.provider_timers.as_mut(),
        backing: Backing,
        access: owner.map(|owner| match owner.caller {
            SuspensionCaller::Hosted(_) => ProviderDispatcherAccess::hosted(owner, 42).unwrap(),
            SuspensionCaller::Kernel { .. } => {
                ProviderDispatcherAccess::kernel_events(owner).unwrap()
            }
        }),
    }
}

fn now() -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns: 10,
        system_time_100ns: 100,
        clock_generation: 0,
    }
}

struct Fixture {
    lanes: Lanes,
    lane: LaneHandle,
    owner: ProviderWaitOwner,
    state: DispatcherState,
    object: ProviderWaitObject,
    arbiter: ProviderDispatcherWaitArbiter<ProviderDispatcherLease>,
}

impl Fixture {
    fn new(kernel: bool, timeout: bool, external: bool) -> Self {
        let mut lanes = Lanes::new(2, 4);
        let lane = lanes
            .allocate(LaneBinding {
                executor_id: 1,
                receive_endpoint: 2,
                reply_object: 3,
            })
            .unwrap();
        lanes.begin_dispatch(lane, 3).unwrap();
        let caller = if kernel {
            SuspensionCaller::Kernel { lane }
        } else {
            SuspensionCaller::Hosted(SuspensionHostedClient {
                client_pi: 2,
                client_generation: 4,
                client_tid: 11,
                client_badge: 13,
            })
        };
        let owner = ProviderWaitOwner {
            provider_domain: 7,
            provider_generation: 3,
            dispatch_id: lanes
                .active_dispatch_identity(lane)
                .unwrap()
                .unwrap()
                .epoch(),
            caller,
        };
        if external {
            lanes.suspend_running(lane, 3, 99).unwrap();
            lanes.resume_external(lane, 3, 99).unwrap();
        }
        let continuation = match caller {
            SuspensionCaller::Hosted(client) => Continuation::Hosted(client),
            SuspensionCaller::Kernel { lane } => Continuation::Kernel(lane),
        };
        lanes
            .admit_running(
                lane,
                3,
                SuspensionKey::provider_wait(71),
                1,
                owner,
                continuation,
            )
            .unwrap();
        let mut state = DispatcherState::new(1, 1);
        assert!(state
            .events
            .try_initialize(101, EventKind::Synchronization, false));
        let id = state
            .event_objects
            .create_provider_local(EventObjectOwner::provider(7, 3), 201, 101)
            .unwrap();
        let object = ProviderWaitObject::new(
            ProviderWaitObjectType::Event,
            id.0.slot() + 1,
            u64::from(id.0.generation().0),
        );
        let mut request = ProviderWaitRequest::empty();
        request
            .begin(
                ProviderWaitRequestMetadata {
                    wait_id: 71,
                    owner,
                    wait_type: ProviderWaitType::Any,
                    wait_mode: ProviderWaitMode::Kernel,
                    alertable: false,
                    timeout_kind: if timeout {
                        ProviderWaitTimeoutKind::Absolute
                    } else {
                        ProviderWaitTimeoutKind::Infinite
                    },
                    timeout_100ns: if timeout { 200 } else { 0 },
                },
                &[object],
            )
            .unwrap();
        let mut arbiter = ProviderDispatcherWaitArbiter::new();
        assert_eq!(
            arbiter.admit(
                &mut backend(&mut state, Some(owner)),
                &request,
                owner,
                1,
                now()
            ),
            Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 71 })
        );
        assert_eq!(state.events.set_existing(101), Some(false));
        Self {
            lanes,
            lane,
            owner,
            state,
            object,
            arbiter,
        }
    }

    fn preserved(&self) {
        assert_eq!(self.state.event_objects.live_lease_count(), 1);
        assert!(self.state.events.read_state(101));
        assert!(!self.arbiter.is_empty());
    }

    fn select(
        &mut self,
    ) -> Result<
        Option<(ProviderDispatcherWaitCompletion, LaneHandle)>,
        ProviderWaitSelectionError<&'static str>,
    > {
        self.arbiter
            .pop_ready_with(&mut backend(&mut self.state, None), |completion| {
                select_provider_wait(&mut self.lanes, completion, route)
            })
    }

    fn assert_selected(&self, status: i32, consumes_event: bool) {
        assert!(self.arbiter.is_empty());
        assert_eq!(self.state.event_objects.live_lease_count(), 0);
        assert_eq!(self.state.events.read_state(101), !consumes_event);
        let expected = match self.owner.caller {
            SuspensionCaller::Hosted(_) => Completion::Hosted(status),
            SuspensionCaller::Kernel { .. } => Completion::Kernel(status),
        };
        assert_eq!(
            self.lanes
                .frame(self.lane, SuspensionKey::provider_wait(71))
                .unwrap()
                .unwrap()
                .phase,
            SuspensionPhase::Selected {
                completion: expected
            }
        );
    }
}

#[test]
fn exact_hosted_and_kernel_routes_select_before_retiring_event_leases() {
    for kernel in [false, true] {
        let mut f = Fixture::new(kernel, false, false);
        let (completion, lane) = f.select().unwrap().unwrap();
        assert_eq!(lane, f.lane);
        assert_eq!(completion.owner, f.owner);
        assert_eq!(completion.admission_sequence, 1);
        f.assert_selected(0, true);
    }
}

#[test]
fn every_owner_field_mismatch_retains_waiter_and_readiness_for_retry() {
    for kernel in [false, true] {
        for field in 0..if kernel { 6 } else { 8 } {
            let mut f = Fixture::new(kernel, false, false);
            let mut wrong = f.owner;
            match field {
                0 => wrong.provider_domain += 1,
                1 => wrong.provider_generation += 1,
                2 => wrong.dispatch_id += 1,
                field if field == if kernel { 5 } else { 7 } => {
                    wrong.caller = if kernel {
                        SuspensionCaller::Hosted(SuspensionHostedClient {
                            client_pi: 2,
                            client_generation: 4,
                            client_tid: 11,
                            client_badge: 13,
                        })
                    } else {
                        SuspensionCaller::Kernel { lane: f.lane }
                    };
                }
                _ => match &mut wrong.caller {
                    SuspensionCaller::Hosted(client) => match field {
                        3 => client.client_pi += 1,
                        4 => client.client_generation += 1,
                        5 => client.client_tid += 1,
                        _ => client.client_badge += 1,
                    },
                    SuspensionCaller::Kernel { lane } => {
                        if field == 3 {
                            lane.index += 1;
                        } else {
                            lane.generation += 1;
                        }
                    }
                },
            }
            let key = SuspensionKey::provider_wait(71);
            f.lanes.frame_mut(f.lane, key).unwrap().unwrap().owner = wrong;
            assert_eq!(f.select(), Err(ProviderWaitSelectionError::OwnerMismatch));
            f.preserved();
            f.lanes.frame_mut(f.lane, key).unwrap().unwrap().owner = f.owner;
            f.select().unwrap().unwrap();
            f.assert_selected(0, true);
        }
    }
}

#[test]
fn stale_sequence_and_all_nonwaiting_phases_reject_without_effects() {
    for mode in 0..4 {
        let mut f = Fixture::new(true, false, false);
        let key = SuspensionKey::provider_wait(71);
        let frame = f.lanes.frame_mut(f.lane, key).unwrap().unwrap();
        let expected = if mode == 0 {
            frame.admission_sequence = 2;
            ProviderWaitSelectionError::SequenceMismatch
        } else {
            frame.phase = match mode {
                1 => SuspensionPhase::Selected {
                    completion: Completion::Kernel(42),
                },
                2 => SuspensionPhase::Resuming {
                    completion: Completion::Kernel(42),
                    cancelled: false,
                },
                _ => SuspensionPhase::Cancelled {
                    completion: Completion::Kernel(42),
                },
            };
            ProviderWaitSelectionError::Lane(LaneError::Suspension(SuspensionError::InvalidPhase))
        };
        let retained = frame.clone();
        assert_eq!(f.select(), Err(expected));
        f.preserved();
        assert_eq!(f.lanes.frame(f.lane, key).unwrap().unwrap(), &retained);
        let frame = f.lanes.frame_mut(f.lane, key).unwrap().unwrap();
        frame.admission_sequence = 1;
        frame.phase = SuspensionPhase::Waiting;
        f.select().unwrap().unwrap();
        f.assert_selected(0, true);
    }
}

#[test]
fn continuation_kind_and_identity_rejections_preserve_exact_event_selection() {
    for kernel in [false, true] {
        for wrong_kind in [false, true] {
            let mut f = Fixture::new(kernel, false, false);
            let key = SuspensionKey::provider_wait(71);
            let frame = f.lanes.frame_mut(f.lane, key).unwrap().unwrap();
            let original = frame.continuation;
            frame.continuation = match (original, wrong_kind) {
                (Continuation::Hosted(_), true) => Continuation::Kernel(f.lane),
                (Continuation::Kernel(_), true) => Continuation::Hosted(SuspensionHostedClient {
                    client_pi: 2,
                    client_generation: 4,
                    client_tid: 11,
                    client_badge: 13,
                }),
                (Continuation::Hosted(mut client), false) => {
                    client.client_badge += 1;
                    Continuation::Hosted(client)
                }
                (Continuation::Kernel(mut lane), false) => {
                    lane.generation += 1;
                    Continuation::Kernel(lane)
                }
            };
            assert_eq!(
                f.arbiter.pop_event_ready_with(
                    &mut backend(&mut f.state, None),
                    f.object,
                    1,
                    |completion| select_provider_wait(&mut f.lanes, completion, route)
                ),
                Err(ProviderWaitSelectionError::Continuation(
                    "continuation identity"
                ))
            );
            f.preserved();
            f.lanes
                .frame_mut(f.lane, key)
                .unwrap()
                .unwrap()
                .continuation = original;
            f.select().unwrap().unwrap();
            f.assert_selected(0, true);
        }
    }
}

#[test]
fn matching_kernel_owner_on_wrong_physical_lane_is_not_authority() {
    let mut f = Fixture::new(true, false, false);
    let key = SuspensionKey::provider_wait(71);
    let mut wrong = f.owner;
    wrong.caller = SuspensionCaller::Kernel {
        lane: LaneHandle {
            index: f.lane.index + 1,
            generation: f.lane.generation,
        },
    };
    f.lanes.frame_mut(f.lane, key).unwrap().unwrap().owner = wrong;
    assert_eq!(
        f.arbiter
            .pop_ready_with(&mut backend(&mut f.state, None), |mut completion| {
                completion.owner = wrong;
                select_provider_wait(
                    &mut f.lanes,
                    completion,
                    |_, _, _| -> Result<Completion, &'static str> {
                        panic!("wrong physical lane must not route")
                    },
                )
            }),
        Err(ProviderWaitSelectionError::OwnerMismatch)
    );
    f.preserved();
    f.lanes.frame_mut(f.lane, key).unwrap().unwrap().owner = f.owner;
    f.select().unwrap().unwrap();
    f.assert_selected(0, true);
}

#[test]
fn buried_hosted_wait_can_be_selected_without_selecting_newer_frame() {
    let mut f = Fixture::new(false, false, true);
    f.lanes.resume_external(f.lane, 3, 99).unwrap();
    let mut newer_owner = f.owner;
    newer_owner.dispatch_id += 1;
    let newer_key = SuspensionKey::provider_wait(72);
    f.lanes
        .admit_running(
            f.lane,
            3,
            newer_key,
            2,
            newer_owner,
            Continuation::Hosted(newer_owner.hosted_client().unwrap()),
        )
        .unwrap();
    f.select().unwrap().unwrap();
    f.assert_selected(0, true);
    assert_eq!(f.lanes.suspension_count(f.lane), Ok(2));
    let top = f.lanes.top(f.lane).unwrap().unwrap();
    assert_eq!(top.key, newer_key);
    assert_eq!(top.phase, SuspensionPhase::Waiting);
    assert!(f.lanes.next_resumable().is_none());
}

#[test]
fn due_timeout_rejection_and_retry_do_not_consume_signaled_event() {
    let mut f = Fixture::new(true, true, false);
    let key = SuspensionKey::provider_wait(71);
    f.lanes
        .frame_mut(f.lane, key)
        .unwrap()
        .unwrap()
        .admission_sequence = 2;
    let due = TimeSnapshot {
        system_time_100ns: 200,
        monotonic_100ns: 110,
        ..now()
    };
    assert_eq!(
        f.arbiter
            .pop_due_with(&mut backend(&mut f.state, None), due, |completion| {
                select_provider_wait(&mut f.lanes, completion, route)
            }),
        Err(ProviderWaitSelectionError::SequenceMismatch)
    );
    f.preserved();
    assert_eq!(f.arbiter.next_deadline(due), Some(110));
    f.lanes
        .frame_mut(f.lane, key)
        .unwrap()
        .unwrap()
        .admission_sequence = 1;
    let (completion, lane) = f
        .arbiter
        .pop_due_with(&mut backend(&mut f.state, None), due, |completion| {
            select_provider_wait(&mut f.lanes, completion, route)
        })
        .unwrap()
        .unwrap();
    assert_eq!(completion.status, 0x102);
    assert_eq!(lane, f.lane);
    f.assert_selected(0x102, false);
}

#[test]
fn invalid_or_missing_completion_does_not_invoke_route_or_consume_event() {
    for mode in 0..4 {
        let mut f = Fixture::new(false, false, false);
        let result =
            f.arbiter
                .pop_ready_with(&mut backend(&mut f.state, None), |mut completion| {
                    match mode {
                        0 => completion.cancelled = true,
                        1 => completion.wait_id = 0,
                        2 => completion.admission_sequence = 0,
                        _ => completion.wait_id = 72,
                    }
                    select_provider_wait(
                        &mut f.lanes,
                        completion,
                        |_, _, _| -> Result<Completion, &'static str> {
                            panic!("invalid completion must not route")
                        },
                    )
                });
        assert_eq!(
            result,
            Err(if mode == 3 {
                ProviderWaitSelectionError::Lane(LaneError::Suspension(SuspensionError::NotFound))
            } else {
                ProviderWaitSelectionError::InvalidCompletion
            })
        );
        f.preserved();
        f.select().unwrap().unwrap();
        f.assert_selected(0, true);
    }
}
