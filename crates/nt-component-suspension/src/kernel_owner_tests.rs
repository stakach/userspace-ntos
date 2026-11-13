use super::*;

type Lanes = ComponentSuspensionLanes<u64, u32>;

fn binding(id: u64) -> LaneBinding {
    LaneBinding {
        executor_id: 0x100 + id,
        receive_endpoint: 0x200 + id,
        reply_object: 0x300 + id,
    }
}

fn hosted(dispatch_id: u64) -> SuspensionOwner {
    SuspensionOwner {
        provider_domain: 3,
        provider_generation: 7,
        dispatch_id,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 0,
            client_generation: 11,
            client_tid: 24,
            client_badge: 4,
        }),
    }
}

fn kernel(lanes: &Lanes, lane: LaneHandle) -> SuspensionOwner {
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    SuspensionOwner {
        provider_domain: 3,
        provider_generation: 7,
        dispatch_id: dispatch.epoch(),
        caller: SuspensionCaller::Kernel {
            lane: dispatch.lane(),
        },
    }
}

#[test]
fn caller_shape_and_dispatch_namespaces_are_explicit() {
    let lane = LaneHandle {
        index: 0,
        generation: 1,
    };
    let kernel = SuspensionOwner {
        caller: SuspensionCaller::Kernel { lane },
        ..hosted(20)
    };
    assert!(kernel.is_valid());
    assert!(hosted(20).is_valid());
    assert_eq!(kernel.hosted_client(), None);
    assert!(!kernel.same_dispatch(hosted(20)));
    assert!(!hosted(20).same_dispatch(kernel));
    let other_client = SuspensionOwner {
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_generation: 12,
            ..hosted(20).hosted_client().unwrap()
        }),
        ..hosted(20)
    };
    assert!(hosted(20).same_dispatch(other_client));
    assert_ne!(hosted(20), other_client);
    for other_lane in [
        LaneHandle {
            index: 1,
            generation: 1,
        },
        LaneHandle {
            index: 0,
            generation: 2,
        },
    ] {
        assert!(!kernel.same_dispatch(SuspensionOwner {
            caller: SuspensionCaller::Kernel { lane: other_lane },
            ..kernel
        }));
    }
    for invalid in [
        SuspensionOwner {
            provider_domain: 0,
            ..kernel
        },
        SuspensionOwner {
            provider_generation: 0,
            ..kernel
        },
        SuspensionOwner {
            dispatch_id: 0,
            ..kernel
        },
        SuspensionOwner {
            caller: SuspensionCaller::Kernel {
                lane: LaneHandle::INVALID,
            },
            ..kernel
        },
        SuspensionOwner {
            caller: SuspensionCaller::Hosted(SuspensionHostedClient {
                client_generation: 0,
                ..hosted(20).hosted_client().unwrap()
            }),
            ..hosted(20)
        },
    ] {
        assert!(!invalid.is_valid());
    }

    let mut stack = ComponentSuspensionStack::<u64, u32>::new(3);
    stack
        .admit(SuspensionKey::provider_wait(1), 1, kernel, 10)
        .unwrap();
    stack
        .admit(SuspensionKey::lpc_request(2), 2, hosted(20), 20)
        .unwrap();
    assert_eq!(
        stack.admit(SuspensionKey::provider_wait(3), 3, other_client, 30),
        Err(SuspensionError::DuplicateIdentity)
    );
}

#[test]
fn kernel_admission_and_rearm_require_current_lane_and_epoch() {
    let mut lanes = Lanes::new(2, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let other = lanes.allocate(binding(2)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let owner = kernel(&lanes, lane);
    let wrong_lane = SuspensionOwner {
        caller: SuspensionCaller::Kernel { lane: other },
        ..owner
    };
    let wrong_epoch = SuspensionOwner {
        dispatch_id: owner.dispatch_id + 1,
        ..owner
    };
    let key = SuspensionKey::provider_wait(1);
    for wrong in [wrong_lane, wrong_epoch] {
        assert_eq!(
            lanes.admit_running(lane, reply, key, 1, wrong, 10),
            Err(LaneError::InvalidIdentity)
        );
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
        assert_eq!(lanes.suspension_count(lane), Ok(0));
    }
    lanes.admit_running(lane, reply, key, 1, owner, 10).unwrap();
    lanes.select(key, 42).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    let next = SuspensionKey::lpc_request(2);
    for wrong in [wrong_lane, wrong_epoch] {
        assert_eq!(
            lanes.rearm_running(lane, reply, key, next, 2, wrong, 20),
            Err(LaneError::InvalidIdentity)
        );
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
        assert_eq!(lanes.top(lane).unwrap().unwrap().key, key);
        assert_eq!(lanes.top(lane).unwrap().unwrap().owner, owner);
    }
    lanes
        .rearm_running(lane, reply, key, next, 2, owner, 20)
        .unwrap();
    lanes.select(next, 43).unwrap();
    lanes.begin_resume(lane, reply, next).unwrap();
    assert_eq!(
        lanes.retain_terminal_running(lane, reply, next, hosted(owner.dispatch_id), ()),
        Err((LaneError::Suspension(SuspensionError::InvalidIdentity), ()))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    lanes
        .deliver_terminal_for_test(lane, reply, next, owner)
        .unwrap();
    lanes.begin_dispatch(lane, reply).unwrap();
    assert_ne!(kernel(&lanes, lane).dispatch_id, owner.dispatch_id);
    assert_eq!(
        lanes.admit_running(lane, reply, key, 3, owner, 30),
        Err(LaneError::InvalidIdentity)
    );
    lanes.finish_dispatch(lane, reply).unwrap();
}

#[test]
fn failed_kernel_external_transfer_keeps_the_original_token() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let owner = kernel(&lanes, lane);
    lanes.suspend_running(lane, reply, 77).unwrap();
    lanes.resume_external(lane, reply, 77).unwrap();
    let key = SuspensionKey::provider_wait(1);
    let stale = SuspensionOwner {
        dispatch_id: owner.dispatch_id + 1,
        ..owner
    };
    assert_eq!(
        lanes.transfer_external_to_suspension_running(lane, reply, 77, key, 1, stale, 10),
        Err(LaneError::InvalidIdentity)
    );
    assert_eq!(lanes.external_top(lane), Ok(Some(77)));
    assert_eq!(lanes.suspension_count(lane), Ok(0));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    lanes
        .transfer_external_to_suspension_running(lane, reply, 77, key, 1, owner, 10)
        .unwrap();
    assert_eq!(lanes.external_top(lane), Ok(None));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
}

#[test]
fn teardown_is_caller_specific_and_provider_scope_covers_both() {
    let mut lanes = Lanes::new(2, 4);
    let first = lanes.allocate(binding(1)).unwrap();
    let second = lanes.allocate(binding(2)).unwrap();
    lanes
        .begin_dispatch(first, binding(1).reply_object)
        .unwrap();
    let kernel_owner = kernel(&lanes, first);
    let first_key = SuspensionKey::provider_wait(1);
    lanes
        .admit_running(
            first,
            binding(1).reply_object,
            first_key,
            1,
            kernel_owner,
            10,
        )
        .unwrap();
    lanes
        .begin_dispatch(second, binding(2).reply_object)
        .unwrap();
    let hosted_owner = hosted(kernel_owner.dispatch_id);
    let second_key = SuspensionKey::lpc_request(2);
    lanes
        .admit_running(
            second,
            binding(2).reply_object,
            second_key,
            2,
            hosted_owner,
            20,
        )
        .unwrap();
    let kernel_scope = SuspensionScope::KernelLane {
        domain: 3,
        provider_generation: 7,
        lane: first,
    };
    let process_scope = SuspensionScope::Process {
        domain: 3,
        provider_generation: 7,
        client_pi: 0,
        client_generation: 11,
    };
    let thread_scope = SuspensionScope::Thread {
        domain: 3,
        provider_generation: 7,
        client_pi: 0,
        client_generation: 11,
        client_tid: 24,
        client_badge: 4,
    };
    assert!(kernel_scope.is_valid());
    assert!(kernel_scope.matches(kernel_owner));
    assert!(!kernel_scope.matches(hosted_owner));
    assert!(!process_scope.matches(kernel_owner));
    assert!(!thread_scope.matches(kernel_owner));
    assert!(process_scope.matches(hosted_owner));
    assert!(thread_scope.matches(hosted_owner));
    assert!(!SuspensionScope::KernelLane {
        domain: 3,
        provider_generation: 7,
        lane: LaneHandle {
            generation: first.generation + 1,
            ..first
        },
    }
    .matches(kernel_owner));
    assert!(!SuspensionScope::KernelLane {
        domain: 3,
        provider_generation: 8,
        lane: first
    }
    .matches(kernel_owner));
    assert!(!SuspensionScope::KernelLane {
        domain: 3,
        provider_generation: 7,
        lane: second
    }
    .matches(kernel_owner));
    assert_eq!(
        lanes.next_cancellable_in_scope(kernel_scope),
        Some((first, first_key))
    );
    assert_eq!(
        lanes.next_cancellable_in_scope(thread_scope),
        Some((second, second_key))
    );
    let provider = SuspensionScope::Provider {
        domain: 3,
        generation: 7,
    };
    assert!(provider.matches(kernel_owner));
    assert!(provider.matches(hosted_owner));
}

#[test]
fn root_maintenance_parks_exact_dispatch_while_another_lane_runs() {
    // The continuation represents the original root Reply and pending native dispatch. Neither
    // may be consumed by a maintenance pass or reconstructed from a later message.
    let mut lanes = Lanes::new(2, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let other = lanes.allocate(binding(2)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let key = SuspensionKey::root_maintenance(1);
    let continuation = 0xfeed_u64;
    let captured_pass = 8;

    let stale_owner = SuspensionOwner {
        dispatch_id: owner.dispatch_id + 1,
        ..owner
    };
    assert_eq!(
        lanes.admit_root_maintenance_owned(
            lane, reply, dispatch, key, 1, stale_owner, captured_pass, continuation,
        ),
        Err((LaneError::InvalidIdentity, continuation)),
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(lanes.suspension_count(lane), Ok(0));

    lanes
        .admit_root_maintenance_owned(
            lane, reply, dispatch, key, 1, owner, captured_pass, continuation,
        )
        .unwrap();
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, continuation);

    // Root can service independent work while the original dispatch remains retained.
    lanes.begin_dispatch(other, binding(2).reply_object).unwrap();
    lanes.finish_dispatch(other, binding(2).reply_object).unwrap();
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));

    // A provider-style completion is not an outer maintenance pass.
    assert_eq!(
        lanes.select(key, 0),
        Err(LaneError::Suspension(SuspensionError::InvalidPhase)),
    );
    for observed_pass in [captured_pass - 1, captured_pass] {
        assert_eq!(
            lanes.mark_root_maintenance_pass(
                lane, reply, dispatch, key, owner, observed_pass,
            ),
            Err(LaneError::InvalidPhase),
        );
    }
    assert_eq!(
        lanes.mark_root_maintenance_pass(
            lane, reply, dispatch, key, stale_owner, captured_pass + 1,
        ),
        Err(LaneError::InvalidIdentity),
    );
    assert_eq!(
        lanes.mark_root_maintenance_pass(
            lane, binding(2).reply_object, dispatch, key, owner, captured_pass + 1,
        ),
        Err(LaneError::WrongBinding),
    );
    lanes
        .mark_root_maintenance_pass(
            lane, reply, dispatch, key, owner, captured_pass + 1,
        )
        .unwrap();
    assert_eq!(
        lanes.mark_root_maintenance_pass(
            lane, reply, dispatch, key, owner, captured_pass + 2,
        ),
        Err(LaneError::InvalidPhase),
    );
    let stale_lane = LaneHandle {
        generation: lane.generation + 1,
        ..lane
    };
    assert_eq!(
        lanes.begin_root_maintenance_resume(stale_lane, reply, dispatch, key, owner),
        Err(LaneError::StaleGeneration),
    );
    assert_eq!(
        lanes.begin_root_maintenance_resume(
            lane, binding(2).reply_object, dispatch, key, owner,
        ),
        Err(LaneError::WrongBinding),
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, continuation);

    assert_eq!(
        lanes.begin_resume(lane, reply, key),
        Err(LaneError::Suspension(SuspensionError::InvalidPhase)),
    );
    assert_eq!(
        lanes.begin_root_maintenance_resume(lane, reply, dispatch, key, owner),
        Ok(captured_pass + 1),
    );
    assert_eq!(
        lanes.begin_root_maintenance_resume(lane, reply, dispatch, key, owner),
        Err(LaneError::InvalidPhase),
    );
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    let frame = lanes.top(lane).unwrap().unwrap();
    assert_eq!(frame.key, key);
    assert_eq!(frame.owner, owner);
    assert_eq!(frame.continuation, continuation);
    lanes.suspend_running(lane, reply, 77).unwrap();
    lanes.resume_external(lane, reply, 77).unwrap();
    assert_eq!(
        lanes.finish_dispatch(lane, reply),
        Err(LaneError::InvalidPhase),
    );
    lanes.retire_external_running(lane, reply, 77).unwrap();
    assert_eq!(
        lanes.finish_dispatch(lane, reply),
        Err(LaneError::InvalidPhase),
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, continuation);
}

#[test]
fn root_maintenance_teardown_cancels_without_marking_a_pass() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let key = SuspensionKey::root_maintenance(2);
    lanes
        .admit_root_maintenance_owned(lane, reply, dispatch, key, 1, owner, 10, 0xbeef)
        .unwrap();
    let scope = SuspensionScope::KernelLane {
        domain: owner.provider_domain,
        provider_generation: owner.provider_generation,
        lane,
    };
    assert_eq!(lanes.next_cancellable_in_scope(scope), Some((lane, key)));
    lanes.cancel(key, 0xC000_0120).unwrap();
    assert_eq!(
        lanes.mark_root_maintenance_pass(lane, reply, dispatch, key, owner, 11),
        Err(LaneError::InvalidPhase),
    );
    let resume = lanes.begin_resume(lane, reply, key).unwrap();
    assert!(resume.cancelled);
    assert_eq!(resume.completion, 0xC000_0120);
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0xbeef);
    let terminal = lanes.retain_terminal_running(lane, reply, key, owner, ()).unwrap();
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut attempt = lanes.begin_terminal_stage(terminal, reply, stage).unwrap();
        lanes.record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged).unwrap();
    }
    assert_eq!(
        lanes.finish_root_maintenance_terminal(terminal, reply, Err(77)).err(),
        Some(LaneError::InvalidPhase),
    );
    let retired = lanes.finish_terminal(terminal, reply, Ok(())).unwrap().unwrap().suspension;
    assert!(retired.cancelled);
    assert_eq!(retired.completion, 0xC000_0120);
    assert_eq!(retired.continuation, 0xbeef);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
}

#[test]
fn root_maintenance_resume_reparks_into_real_wait_without_losing_either_continuation() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let maintenance = SuspensionKey::root_maintenance(3);
    let provider = SuspensionKey::provider_wait(4);
    lanes
        .admit_root_maintenance_owned(lane, reply, dispatch, maintenance, 1, owner, 8, 0x111)
        .unwrap();
    lanes
        .mark_root_maintenance_pass(lane, reply, dispatch, maintenance, owner, 9)
        .unwrap();
    lanes
        .begin_root_maintenance_resume(lane, reply, dispatch, maintenance, owner)
        .unwrap();

    let next_continuation = 0x222;
    let stale_owner = SuspensionOwner {
        dispatch_id: owner.dispatch_id + 1,
        ..owner
    };
    assert_eq!(
        lanes.rearm_running_owned(
            lane, reply, maintenance, provider, 2, stale_owner, next_continuation,
        ),
        Err((LaneError::InvalidIdentity, next_continuation)),
    );
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x111);
    assert_eq!(
        lanes.rearm_running_owned(
            lane, reply, maintenance, provider, 2, owner, next_continuation,
        ),
        Ok(0x111),
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    let frame = lanes.top(lane).unwrap().unwrap();
    assert_eq!(frame.key, provider);
    assert_eq!(frame.owner, owner);
    assert_eq!(frame.continuation, next_continuation);
    assert_eq!(frame.phase, SuspensionPhase::Waiting);
    lanes.select(provider, 42).unwrap();
    assert_eq!(lanes.begin_resume(lane, reply, provider).unwrap().completion, 42);
}

#[test]
fn maintenance_resume_cannot_be_completed_as_provider_result() {
    let mut stack = ComponentSuspensionStack::<u64, u32>::new(1);
    let lane = LaneHandle { index: 0, generation: 1 };
    let owner = SuspensionOwner {
        provider_domain: 3,
        provider_generation: 7,
        dispatch_id: 1,
        caller: SuspensionCaller::Kernel { lane },
    };
    let key = SuspensionKey::root_maintenance(5);
    assert_eq!(stack.admit(key, 1, owner, 0x333), Err(SuspensionError::InvalidPhase));
    stack
        .admit_owned_with_capacity(key, 1, owner, 0x333, |frames| {
            frames.try_reserve(1).map_err(|_| SuspensionError::NoCapacity)
        })
        .unwrap();
    stack.frames.last_mut().unwrap().phase =
        SuspensionPhase::MaintenanceResuming { observed_pass: 9 };
    assert_eq!(
        stack.complete_dispatch(key, owner),
        Err(SuspensionError::InvalidPhase),
    );
    assert_eq!(stack.top().unwrap().continuation, 0x333);
}

#[test]
fn maintenance_admission_rejects_a_lane_with_a_lower_frame() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let provider = SuspensionKey::provider_wait(6);
    let maintenance = SuspensionKey::root_maintenance(7);
    lanes.admit_running(lane, reply, provider, 1, owner, 0x111).unwrap();
    lanes.select(provider, 42).unwrap();
    lanes.begin_resume(lane, reply, provider).unwrap();
    assert_eq!(
        lanes.admit_root_maintenance_owned(
            lane, reply, dispatch, maintenance, 2, owner, 8, 0x222,
        ),
        Err((LaneError::InvalidPhase, 0x222)),
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    let frame = lanes.top(lane).unwrap().unwrap();
    assert_eq!(frame.key, provider);
    assert_eq!(frame.continuation, 0x111);
}

#[test]
fn generic_admission_and_repark_cannot_bypass_maintenance_pass() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let key = SuspensionKey::root_maintenance(8);
    assert_eq!(
        lanes.admit_running_owned(lane, reply, key, 1, owner, 0x111),
        Err((LaneError::InvalidPhase, 0x111)),
    );
    assert_eq!(lanes.suspension_count(lane), Ok(0));
    lanes
        .admit_root_maintenance_owned(lane, reply, dispatch, key, 1, owner, 8, 0x111)
        .unwrap();
    lanes
        .mark_root_maintenance_pass(lane, reply, dispatch, key, owner, 9)
        .unwrap();
    lanes
        .begin_root_maintenance_resume(lane, reply, dispatch, key, owner)
        .unwrap();
    assert_eq!(
        lanes.rearm_running_owned(
            lane, reply, key, SuspensionKey::root_maintenance(9), 2, owner, 0x222,
        ),
        Err((LaneError::InvalidPhase, 0x222)),
    );
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x111);
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
}

#[test]
fn returned_root_maintenance_retains_original_reply_until_terminal_ack() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let key = SuspensionKey::root_maintenance(10);
    lanes
        .admit_root_maintenance_owned(lane, reply, dispatch, key, 1, owner, 8, 0x111)
        .unwrap();
    lanes
        .mark_root_maintenance_pass(lane, reply, dispatch, key, owner, 9)
        .unwrap();
    lanes
        .begin_root_maintenance_resume(lane, reply, dispatch, key, owner)
        .unwrap();

    // A maintenance pass has no provider completion; only its own terminal path may retire it.
    assert_eq!(
        lanes.retain_terminal_running(lane, reply, key, owner, ()),
        Err((LaneError::InvalidPhase, ())),
    );
    assert_eq!(
        lanes.retain_root_maintenance_terminal_running(
            lane, reply, dispatch, key, SuspensionOwner { dispatch_id: owner.dispatch_id + 1, ..owner }, (),
        ),
        Err((LaneError::Suspension(SuspensionError::InvalidIdentity), ())),
    );
    assert_eq!(
        lanes.retain_root_maintenance_terminal_running(
            lane, reply,
            LaneDispatchIdentity { epoch: dispatch.epoch() + 1, ..dispatch },
            key, owner, (),
        ),
        Err((LaneError::InvalidIdentity, ())),
    );
    let terminal = lanes
        .retain_root_maintenance_terminal_running(lane, reply, dispatch, key, owner, ())
        .unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Terminal));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x111);
    assert_eq!(
        lanes.finish_root_maintenance_terminal(terminal, reply, Ok(())).err(),
        Some(LaneError::InvalidPhase),
    );
    for stage in [
        TerminalStage::Output,
        TerminalStage::Context,
        TerminalStage::Publication,
        TerminalStage::Reply,
    ] {
        let mut attempt = lanes.begin_terminal_stage(terminal, reply, stage).unwrap();
        assert_eq!(
            lanes.record_terminal_stage(
                &mut attempt,
                binding(2).reply_object,
                TerminalStageOutcome::Acknowledged,
            ),
            Err(LaneError::WrongBinding),
        );
        lanes
            .record_terminal_stage(&mut attempt, reply, TerminalStageOutcome::Acknowledged)
            .unwrap();
    }
    assert_eq!(
        lanes.finish_terminal(terminal, reply, Ok(())).err(),
        Some(LaneError::Suspension(SuspensionError::InvalidPhase)),
    );
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x111);
    assert_eq!(
        lanes.finish_root_maintenance_terminal(terminal, reply, Err(77)).unwrap().is_none(),
        true,
    );
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x111);
    assert_eq!(
        lanes.finish_root_maintenance_terminal(terminal, binding(2).reply_object, Ok(())).err(),
        Some(LaneError::WrongBinding),
    );
    let retired = lanes
        .finish_root_maintenance_terminal(terminal, reply, Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(retired.key, key);
    assert_eq!(retired.owner, owner);
    assert_eq!(retired.continuation, 0x111);
    assert_eq!(retired.payload, ());
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert_eq!(
        lanes.finish_root_maintenance_terminal(terminal, reply, Ok(())).err(),
        Some(LaneError::InvalidPhase),
    );
    lanes.begin_dispatch(lane, reply).unwrap();
    assert_ne!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
}

#[test]
fn resumed_root_maintenance_reparks_same_frame_for_later_outer_pass() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let owner = kernel(&lanes, lane);
    let key = SuspensionKey::root_maintenance(11);
    lanes.admit_root_maintenance_owned(lane, reply, dispatch, key, 1, owner, 8, 0x111).unwrap();
    lanes.mark_root_maintenance_pass(lane, reply, dispatch, key, owner, 9).unwrap();
    lanes.begin_root_maintenance_resume(lane, reply, dispatch, key, owner).unwrap();
    assert_eq!(lanes.repark_root_maintenance_owned(
        lane, binding(2).reply_object, dispatch, key, owner, 9, 2, 0x222,
    ), Err((LaneError::WrongBinding, 0x222)));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x111);
    assert_eq!(lanes.repark_root_maintenance_owned(
        lane, reply, dispatch, key, owner, 9, 2, 0x222,
    ), Ok(0x111));
    assert_eq!(lanes.suspension_count(lane), Ok(1));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(Some(dispatch)));
    assert_eq!(lanes.top(lane).unwrap().unwrap().continuation, 0x222);
    assert!(matches!(lanes.top(lane).unwrap().unwrap().phase,
        SuspensionPhase::MaintenanceWaiting { captured_pass: 9 }));
    assert_eq!(lanes.mark_root_maintenance_pass(lane, reply, dispatch, key, owner, 9),
        Err(LaneError::InvalidPhase));
    lanes.mark_root_maintenance_pass(lane, reply, dispatch, key, owner, 10).unwrap();
    lanes.begin_root_maintenance_resume(lane, reply, dispatch, key, owner).unwrap();
}
