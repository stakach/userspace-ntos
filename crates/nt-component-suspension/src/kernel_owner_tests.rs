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
