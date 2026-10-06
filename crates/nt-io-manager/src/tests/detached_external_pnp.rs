use super::*;

fn prepare(io: &mut IoManager<MockObjectPort>) -> (PreparedExternalPnpIrp, DeviceId) {
    let (client, root, _, device) = pnp_test_stack(io, Box::new(MockDriverBackend::new()));
    let payload = alloc::vec![0x5a; nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE];
    (
        io.prepare_external_pnp_to_device(
            client,
            root,
            42,
            PnpParameters::query_capabilities(),
            &payload,
        )
        .unwrap(),
        device,
    )
}

#[test]
fn detached_pnp_invocation_allows_nested_short_manager_borrow() {
    let mut io = io();
    let (prepared, device) = prepare(&mut io);
    let id = prepared.irp_id();
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|context, projection| {
        assert_eq!(projection.device_id, device);
        assert!(io.device(device).is_some());
        io.irp_mut(id).unwrap().information = 19;
        context.system_buffer.fill(0x71);
        PnpBackendDispatch::Returned {
            status: NtStatus::SUCCESS,
            information: 23,
        }
    });
    match io.finish_external_pnp(returned).unwrap() {
        ExternalPnpFinishResult::Terminal(ExternalPnpDispatchResult::ReturnedPayload {
            payload,
            receipt,
            information,
            ..
        }) => {
            assert!(payload.iter().all(|byte| *byte == 0x71));
            assert_eq!(information, 23);
            assert_eq!(receipt.irp_id(), id);
        }
        outcome => panic!("unexpected detached outcome: {outcome:?}"),
    }
    assert!(io.irp(id).is_none());
}

#[test]
fn detached_pnp_wrong_manager_preserves_owner_payload_and_original_irp() {
    let mut first = io();
    let mut other = io();
    let (prepared, _) = prepare(&mut first);
    let (collision, _) = prepare(&mut other);
    let collision_id = collision.irp_id();
    let id = prepared.irp_id();
    let invocation = first.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|_, _| PnpBackendDispatch::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    });
    let rejection = other.finish_external_pnp(returned).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert_eq!(rejection.owner().payload()[0], 0x5a);
    assert_eq!(first.irp(id).unwrap().state, IrpState::Dispatched);
    assert_eq!(
        other.irp(collision_id).unwrap().state,
        IrpState::Initialized
    );
    assert!(matches!(
        first.finish_external_pnp(rejection.into_owner()).unwrap(),
        ExternalPnpFinishResult::Terminal(_)
    ));
    other.discard_prepared_external_pnp(collision).unwrap();
}

#[test]
fn detached_pnp_receipt_mismatch_refuses_before_mutation_and_preserves_payload() {
    let mut io = io();
    let (prepared, _) = prepare(&mut io);
    let id = prepared.irp_id();
    let original_tid = io.irp(id).unwrap().requestor_tid;
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|_, _| PnpBackendDispatch::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    });
    io.irp_mut(id).unwrap().requestor_tid += 1;
    let rejection = io.finish_external_pnp(returned).unwrap_err();
    assert_eq!(rejection.owner().payload()[0], 0x5a);
    assert_eq!(io.irp(id).unwrap().state, IrpState::Dispatched);
    io.irp_mut(id).unwrap().requestor_tid = original_tid;
    assert!(matches!(
        io.finish_external_pnp(rejection.into_owner()).unwrap(),
        ExternalPnpFinishResult::Terminal(_)
    ));
}

#[test]
fn detached_pnp_pending_and_not_entered_match_combined_state_policy() {
    for pending in [true, false] {
        let mut io = io();
        let (prepared, _) = prepare(&mut io);
        let id = prepared.irp_id();
        let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
        let returned = invocation.invoke(|_, _| {
            if pending {
                PnpBackendDispatch::Pending
            } else {
                PnpBackendDispatch::NotDispatched {
                    status: NtStatus::DEVICE_NOT_CONNECTED,
                }
            }
        });
        let retained = match io.finish_external_pnp(returned).unwrap() {
            ExternalPnpFinishResult::Retained(owner) => owner,
            outcome => panic!("nonterminal owner lost: {outcome:?}"),
        };
        assert!(retained.payload().iter().all(|byte| *byte == 0x5a));
        let outcome = retained.outcome();
        if pending {
            assert_eq!(outcome, &ExternalPnpDispatchResult::Pending { irp_id: id });
            assert_eq!(io.irp(id).unwrap().state, IrpState::Pending);
        } else {
            assert_eq!(
                outcome,
                &ExternalPnpDispatchResult::Indeterminate {
                    irp_id: id,
                    transport_status: NtStatus::DEVICE_NOT_CONNECTED
                }
            );
            assert_eq!(io.irp(id).unwrap().state, IrpState::Indeterminate);
        }
    }
}

#[test]
fn detached_pnp_indeterminate_preserves_exact_payload_without_reinvocation() {
    let mut io = io();
    let (prepared, _) = prepare(&mut io);
    let id = prepared.irp_id();
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|context, _| {
        context.system_buffer.fill(0xa7);
        PnpBackendDispatch::Indeterminate {
            transport_status: NtStatus::DEVICE_NOT_CONNECTED,
        }
    });
    let retained = match io.finish_external_pnp(returned).unwrap() {
        ExternalPnpFinishResult::Retained(owner) => owner,
        outcome => panic!("uncertain payload lost: {outcome:?}"),
    };
    assert_eq!(retained.irp_id(), id);
    assert!(retained.payload().iter().all(|byte| *byte == 0xa7));
    assert_eq!(io.irp(id).unwrap().state, IrpState::Indeterminate);
}

#[test]
fn detached_pnp_postbackend_state_change_keeps_original_payload_and_completion_state() {
    let mut io = io();
    let (prepared, _) = prepare(&mut io);
    let id = prepared.irp_id();
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|context, _| {
        context.system_buffer[0] = 0x91;
        assert!(io.irp_mut(id).unwrap().transition(IrpState::Pending));
        PnpBackendDispatch::Returned {
            status: NtStatus::SUCCESS,
            information: 12,
        }
    });
    let retained = match io.finish_external_pnp(returned).unwrap() {
        ExternalPnpFinishResult::Retained(owner) => owner,
        outcome => panic!("changed-state payload lost: {outcome:?}"),
    };
    assert_eq!(retained.payload()[0], 0x91);
    assert_eq!(
        retained.outcome(),
        &ExternalPnpDispatchResult::Pending { irp_id: id }
    );
    assert_eq!(io.irp(id).unwrap().state, IrpState::Pending);
}

#[test]
fn detached_pnp_non_pnp_current_major_is_rejected_before_entry() {
    let mut io = io();
    let (prepared, _) = prepare(&mut io);
    let id = prepared.irp_id();
    let location = io.irp(id).unwrap().current_location as usize;
    io.irp_mut(id).unwrap().stack[location].major = nt_io_abi::major::IRP_MJ_READ;
    let rejection = io.begin_prepared_external_pnp(prepared).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert_eq!(rejection.prepared().irp_id(), id);
    assert_eq!(io.irp(id).unwrap().state, IrpState::Initialized);
    io.irp_mut(id).unwrap().stack[location].major = nt_io_abi::major::IRP_MJ_PNP;
    let invocation = io
        .begin_prepared_external_pnp(rejection.into_prepared())
        .unwrap();
    assert!(invocation.payload().iter().all(|byte| *byte == 0x5a));
}

#[test]
fn detached_pnp_lower_stack_handoff_receipt_uses_actual_completion_driver() {
    let mut io = io();
    let (prepared, _) = prepare(&mut io);
    let id = prepared.irp_id();
    let lower = io.irp(id).unwrap().stack[1].clone();
    let expected_driver = lower.driver_id;
    let expected_device = lower.device_id;
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|_, projection| {
        io.irp_mut(id)
            .unwrap()
            .handoff_to_next_stack(projection.driver_id, lower)
            .unwrap();
        PnpBackendDispatch::Returned {
            status: NtStatus::SUCCESS,
            information: 1,
        }
    });
    match io.finish_external_pnp(returned).unwrap() {
        ExternalPnpFinishResult::Terminal(ExternalPnpDispatchResult::ReturnedPayload {
            receipt,
            ..
        }) => {
            assert_eq!(receipt.completion_driver_id(), expected_driver);
            assert_eq!(receipt.completion_device_id(), expected_device);
            assert_eq!(receipt.irp_id(), id);
        }
        outcome => panic!("forwarded terminal receipt missing: {outcome:?}"),
    }
}

#[test]
fn detached_pnp_changed_completion_major_refuses_before_free_and_keeps_return_owner() {
    let mut io = io();
    let (prepared, _) = prepare(&mut io);
    let id = prepared.irp_id();
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let returned = invocation.invoke(|context, _| {
        context.system_buffer.fill(0x36);
        let location = io.irp(id).unwrap().current_location as usize;
        io.irp_mut(id).unwrap().stack[location].major = nt_io_abi::major::IRP_MJ_READ;
        PnpBackendDispatch::Returned {
            status: NtStatus::SUCCESS,
            information: 5,
        }
    });
    let rejection = io.finish_external_pnp(returned).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert_eq!(io.irp(id).unwrap().state, IrpState::Dispatched);
    assert!(rejection.owner().payload().iter().all(|byte| *byte == 0x36));
    let location = io.irp(id).unwrap().current_location as usize;
    io.irp_mut(id).unwrap().stack[location].major = nt_io_abi::major::IRP_MJ_PNP;
    match io.finish_external_pnp(rejection.into_owner()).unwrap() {
        ExternalPnpFinishResult::Terminal(ExternalPnpDispatchResult::ReturnedPayload {
            payload,
            receipt,
            information,
            ..
        }) => {
            assert!(payload.iter().all(|byte| *byte == 0x36));
            assert_eq!(receipt.irp_id(), id);
            assert_eq!(information, 5);
        }
        outcome => panic!("repaired genuine terminal missing: {outcome:?}"),
    }
    assert!(io.irp(id).is_none());
}
