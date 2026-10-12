//! Detached status-only PnP completion ownership regressions.
use super::*;
use crate::detached_file_irp::ExternalFileIrpAcknowledgement;

fn pending(
    io: &mut IoManager<MockObjectPort>,
) -> (RetainedExternalPnp, std::rc::Rc<std::cell::Cell<bool>>) {
    pending_for(
        io,
        PnpParameters::start(32, 32).unwrap(),
        alloc::vec![0x63; 64],
    )
}

fn pending_for(
    io: &mut IoManager<MockObjectPort>,
    parameters: PnpParameters,
    payload: Vec<u8>,
) -> (RetainedExternalPnp, std::rc::Rc<std::cell::Cell<bool>>) {
    let release = std::rc::Rc::new(std::cell::Cell::new(false));
    let (client, root, _, _) = pnp_test_stack(
        io,
        Box::new(PendingPnpBackend {
            ready: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            release: release.clone(),
        }),
    );
    let prepared = io
        .prepare_external_pnp_to_device(client, root, 29, parameters, &payload)
        .unwrap();
    let invocation = io.begin_prepared_external_pnp(prepared).unwrap();
    let backend = io
        .driver(invocation.projection().driver_id)
        .unwrap()
        .backend
        .0 as usize;
    let returned = invocation
        .invoke(|context, projection| io.backends[backend].dispatch_pnp_irp(context, projection));
    let owner = match io.finish_external_pnp(returned).unwrap() {
        ExternalPnpFinishResult::Retained(owner) => owner,
        result => panic!("pending owner missing: {result:?}"),
    };
    (owner, release)
}

#[test]
fn detached_pnp_completion_requires_actual_driver_terminal_before_ack_entry() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    let refusal = io.prepare_external_pnp_completion(retained).unwrap_err();
    assert_eq!(refusal.status(), NtStatus::PENDING);
    assert!(refusal.owner().payload().iter().all(|byte| *byte == 0x63));
    assert_eq!(io.irp(id).unwrap().state, IrpState::Pending);
    release.set(true);
    assert_eq!(io.pump(), 1);
    let invocation = io
        .prepare_external_pnp_completion(refusal.into_owner())
        .unwrap();
    assert_eq!(
        invocation.completion().completion_origin,
        IrpCompletionOrigin::Driver
    );
    assert_eq!(invocation.completion().id, id);
    assert_eq!(
        io.acknowledge_completed_irp_strict(id),
        Err(NtStatus::DELETE_PENDING)
    );
    assert!(io.completed_irp(id).is_some());
}

#[test]
fn detached_pnp_completion_foreign_ack_runs_without_manager_borrow_and_returns_exact_payload() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    assert!(io.take_completed_external_pnp_receipt(id).is_none());
    let mut entered = 0;
    let returned = invocation.invoke(|completion| {
        entered += 1;
        assert_eq!(completion.id, id);
        assert!(io.irp(id).is_some());
        assert!(io.completed_irp(id).is_some());
        ExternalFileIrpAcknowledgement::Acknowledged
    });
    let (receipt, payload) = io.finish_external_pnp_completion(returned).unwrap();
    assert_eq!(entered, 1);
    assert_eq!(receipt.irp_id(), id);
    assert!(receipt.driver_pending());
    assert!(payload.iter().all(|byte| *byte == 0x63));
    assert!(io.irp(id).is_none());
    assert!(io.completed_irp(id).is_none());
}

#[test]
fn detached_pnp_completion_wrong_manager_preserves_accepted_ack_for_local_finish_only() {
    let mut first = io();
    let mut foreign = io();
    let (retained, release) = pending(&mut first);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(first.pump(), 1);
    let invocation = first.prepare_external_pnp_completion(retained).unwrap();
    let returned = invocation.invoke(|_| ExternalFileIrpAcknowledgement::Acknowledged);
    let rejection = foreign
        .finish_external_pnp_completion(returned)
        .unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert!(rejection.owner().payload().iter().all(|byte| *byte == 0x63));
    assert!(first.completed_irp(id).is_some());
    let returned = rejection.into_owner().retry().unwrap_err();
    let (_, payload) = first.finish_external_pnp_completion(returned).unwrap();
    assert!(payload.iter().all(|byte| *byte == 0x63));
}

#[test]
fn detached_pnp_completion_uncertain_ack_or_reply_only_success_never_frees_or_reinvokes() {
    for uncertain in [false, true] {
        let mut io = io();
        let (retained, release) = pending(&mut io);
        let id = retained.irp_id();
        release.set(true);
        assert_eq!(io.pump(), 1);
        let invocation = io.prepare_external_pnp_completion(retained).unwrap();
        let returned = invocation.invoke(|_| {
            if uncertain {
                ExternalFileIrpAcknowledgement::Indeterminate {
                    transport_status: NtStatus::UNSUCCESSFUL,
                }
            } else {
                // A successful IPC Reply without provider completion is explicitly not an ACK.
                ExternalFileIrpAcknowledgement::NotEntered {
                    status: NtStatus::DEVICE_NOT_READY,
                }
            }
        });
        let rejection = io.finish_external_pnp_completion(returned).unwrap_err();
        assert!(io.completed_irp(id).is_some());
        assert!(rejection.owner().payload().iter().all(|byte| *byte == 0x63));
        let retry = rejection.into_owner().retry();
        if uncertain {
            assert!(retry.is_err());
        } else {
            assert!(retry.is_ok());
        }
        assert!(io.irp(id).is_some());
    }
}

#[test]
fn detached_pnp_retry_requires_proven_no_entry_and_revalidates_reserved_completion() {
    let mut primary_io = io();
    let (retained, release) = pending_for(
        &mut primary_io,
        PnpParameters::lifecycle(nt_pnp_abi::IRP_MN_STOP_DEVICE).unwrap(),
        Vec::new(),
    );
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(primary_io.pump(), 1);
    let invocation = primary_io.prepare_external_pnp_completion(retained).unwrap();
    let completion = *invocation.completion();
    let first = invocation.invoke(|_| ExternalFileIrpAcknowledgement::NotEntered {
        status: NtStatus::DEVICE_NOT_READY,
    });
    let rejected = primary_io.finish_external_pnp_completion(first).unwrap_err();
    assert_eq!(primary_io.completed_irp(id), Some(completion));
    let retry = primary_io.retry_external_pnp_completion(rejected.into_owner()).unwrap();
    assert_eq!(retry.completion(), &completion);
    let second = retry.invoke(|_| ExternalFileIrpAcknowledgement::Acknowledged);
    let (receipt, payload) = primary_io.finish_external_pnp_completion(second).unwrap();
    assert!(payload.is_empty());
    assert_eq!(receipt.irp_id(), id);
    assert!(primary_io.irp(id).is_none());

    for acknowledgement in [
        ExternalFileIrpAcknowledgement::Rejected {
            status: NtStatus::DEVICE_NOT_READY,
        },
        ExternalFileIrpAcknowledgement::Indeterminate {
            transport_status: NtStatus::UNSUCCESSFUL,
        },
    ] {
        let mut other_io = io();
        let (retained, release) = pending(&mut other_io);
        let id = retained.irp_id();
        release.set(true);
        assert_eq!(other_io.pump(), 1);
        let invocation = other_io.prepare_external_pnp_completion(retained).unwrap();
        let returned = invocation.invoke(|_| acknowledgement);
        let rejected = other_io.finish_external_pnp_completion(returned).unwrap_err();
        let rejected = other_io.retry_external_pnp_completion(rejected.into_owner()).unwrap_err();
        assert_eq!(rejected.owner().acknowledgement(), acknowledgement);
        assert!(other_io.irp(id).is_some());
    }
}

#[test]
fn detached_pnp_no_entry_retry_rejects_changed_terminal_before_foreign_reentry() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    let original = io.irp(id).unwrap().information;
    let first = invocation.invoke(|_| ExternalFileIrpAcknowledgement::NotEntered {
        status: NtStatus::DEVICE_NOT_READY,
    });
    let rejected = io.finish_external_pnp_completion(first).unwrap_err();
    io.irps.get_mut(id).unwrap().information += 1;
    let rejected = io.retry_external_pnp_completion(rejected.into_owner()).unwrap_err();
    assert_eq!(rejected.status(), NtStatus::INVALID_PARAMETER);
    assert_eq!(rejected.owner().payload(), &[0x63; 64]);
    io.irps.get_mut(id).unwrap().information = original;
    let retry = io.retry_external_pnp_completion(rejected.into_owner()).unwrap();
    let second = retry.invoke(|_| ExternalFileIrpAcknowledgement::Acknowledged);
    assert!(io.finish_external_pnp_completion(second).is_ok());
}

#[test]
fn detached_pnp_completion_changed_backend_retains_accepted_ack_until_exact_route_restored() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    let completion = *invocation.completion();
    let driver = completion.completion_driver_id;
    let original_backend = io.driver(driver).unwrap().backend;
    let changed_backend = DriverBackendId(original_backend.0.checked_add(1).unwrap());
    let mut entered = 0;
    let returned = invocation.invoke(|_| {
        entered += 1;
        io.driver_mut(driver).unwrap().backend = changed_backend;
        ExternalFileIrpAcknowledgement::Acknowledged
    });
    let rejection = io.finish_external_pnp_completion(returned).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert_eq!(rejection.owner().payload(), &[0x63; 64]);
    assert_eq!(io.completed_irp(id), Some(completion));
    assert!(io.irp(id).is_some());
    let returned = rejection.into_owner().retry().unwrap_err();
    io.driver_mut(driver).unwrap().backend = original_backend;
    let (receipt, payload) = io.finish_external_pnp_completion(returned).unwrap();
    assert_eq!(entered, 1, "accepted ACK must never be invoked again");
    assert_eq!(receipt.irp_id(), id);
    assert_eq!(payload, alloc::vec![0x63; 64]);
    assert!(io.irp(id).is_none());
    assert!(io.completed_irp(id).is_none());
}

#[test]
fn detached_pnp_completion_changed_terminal_snapshot_keeps_ack_and_payload_until_local_repair() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    let original = io.irp(id).unwrap().information;
    let returned = invocation.invoke(|_| ExternalFileIrpAcknowledgement::Acknowledged);
    // Deliberate private corruption: public irp_mut must be fenced during ACK ownership.
    io.irps.get_mut(id).unwrap().information += 1;
    let rejection = io.finish_external_pnp_completion(returned).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert!(io.completed_irp(id).is_some());
    let returned = rejection.into_owner().retry().unwrap_err();
    io.irps.get_mut(id).unwrap().information = original;
    let (_, payload) = io.finish_external_pnp_completion(returned).unwrap();
    assert!(payload.iter().all(|byte| *byte == 0x63));
    assert!(io.irp(id).is_none());
}

#[test]
fn detached_pnp_completion_reservation_fences_all_legacy_competitors_before_and_during_ack() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let client = io.irp(id).unwrap().client_id;
    let completion = io.completed_irp(id).unwrap();
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    let assert_fenced = |io: &mut IoManager<MockObjectPort>| {
        assert!(io.free_irp(id).is_none());
        assert!(
            io.irp_mut(id).is_none(),
            "whole-record replacement cannot erase reservation"
        );
        assert_eq!(
            io.acknowledge_completed_irp(id),
            Err(NtStatus::DELETE_PENDING)
        );
        assert_eq!(
            io.acknowledge_completed_irp_strict(id),
            Err(NtStatus::DELETE_PENDING)
        );
        assert_eq!(io.cancel(client, id), Err(NtStatus::DELETE_PENDING));
        assert_eq!(
            io.cancel_if_pending(client, id),
            Err(NtStatus::DELETE_PENDING)
        );
        let mut bytes = [0xa5; 8];
        assert_eq!(
            io.copy_completed_irp_output(id, 0, &mut bytes),
            Err(NtStatus::DELETE_PENDING)
        );
        assert_eq!(
            io.copy_completed_pnp_payload(id, 0, &mut bytes),
            Err(NtStatus::DELETE_PENDING)
        );
        assert_eq!(bytes, [0xa5; 8]);
        assert_eq!(io.completed_irp(id), Some(completion));
    };
    assert_fenced(&mut io);
    let returned = invocation.invoke(|_| {
        assert_fenced(&mut io);
        ExternalFileIrpAcknowledgement::Indeterminate {
            transport_status: NtStatus::UNSUCCESSFUL,
        }
    });
    let rejection = io.finish_external_pnp_completion(returned).unwrap_err();
    assert_fenced(&mut io);
    assert!(rejection.owner().payload().iter().all(|byte| *byte == 0x63));
    assert!(rejection.into_owner().retry().is_err());
}

#[test]
fn detached_pnp_reserved_record_cannot_be_readmitted_as_another_irp() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    // IrpRecord is deliberately not Clone. This private corruption fixture tests the allocator's
    // defensive admission of an already-reserved record moved out of its original GenStore;
    // public free_irp/irp_mut cannot produce this record while its reservation is held.
    let reserved = io.irps.remove(id).unwrap();
    let before = io.irp_count();
    assert_eq!(io.allocate_irp(reserved), Err(NtStatus::DELETE_PENDING));
    assert_eq!(io.irp_count(), before);
    let returned = invocation.invoke(|_| ExternalFileIrpAcknowledgement::Acknowledged);
    let refusal = io.finish_external_pnp_completion(returned).unwrap_err();
    assert!(refusal.owner().payload().iter().all(|byte| *byte == 0x63));
}

#[test]
fn detached_pnp_completion_refuses_output_and_pointer_results_before_reservation() {
    for parameters in [
        PnpParameters::query_capabilities(),
        PnpParameters::query_id(nt_pnp_abi::BUS_QUERY_DEVICE_ID),
    ] {
        let mut io = io();
        let payload = alloc::vec![0x63; parameters.payload_len() as usize];
        let original = payload.clone();
        let (retained, release) = pending_for(&mut io, parameters, payload);
        let id = retained.irp_id();
        release.set(true);
        assert_eq!(io.pump(), 1);
        let before = io.completed_irp(id).unwrap();
        let refusal = io.prepare_external_pnp_completion(retained).unwrap_err();
        assert_eq!(refusal.status(), NtStatus::NOT_SUPPORTED);
        assert_eq!(refusal.owner().payload(), original);
        assert_eq!(io.completed_irp(id), Some(before));
        assert!(
            io.irp_mut(id).is_some(),
            "unsupported result must not reserve ACK ownership"
        );
    }
}

#[test]
fn detached_pnp_completion_rechecks_canonical_result_shape_before_reservation() {
    let mut io = io();
    let (retained, release) = pending(&mut io);
    let id = retained.irp_id();
    release.set(true);
    assert_eq!(io.pump(), 1);
    let irp = io.irp_mut(id).unwrap();
    let stack = &mut irp.stack[irp.current_location as usize];
    stack.minor = nt_pnp_abi::IRP_MN_QUERY_CAPABILITIES;
    stack.parameters = IoParameters::Pnp(PnpParameters::query_capabilities());
    let refusal = io.prepare_external_pnp_completion(retained).unwrap_err();
    assert_eq!(refusal.status(), NtStatus::NOT_SUPPORTED);
    assert!(io.irp_mut(id).is_some(), "refusal must not reserve ACK ownership");
    assert_eq!(refusal.owner().payload(), &[0x63; 64]);
}
