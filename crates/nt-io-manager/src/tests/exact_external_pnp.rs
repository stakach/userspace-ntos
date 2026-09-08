use super::*;
use alloc::vec;

fn parameters() -> PnpParameters {
    PnpParameters::query_device_relations(nt_pnp_abi::TARGET_DEVICE_RELATION)
}

fn attach_filter(io: &mut IoManager<MockObjectPort>, lower: DeviceId) -> (DriverId, DeviceId) {
    let backend = io.register_backend(Box::new(MockDriverBackend::new()));
    let mut dispatch = MajorFunctionTable::new();
    dispatch.set_all(DispatchTarget::DriverPeer(DriverPeerId(backend as u64)));
    let driver = io.register_driver(DriverRecord::new(
        ObjectId::NULL,
        path("\\Driver\\UpperFilter"),
        DriverBackendId(backend as u64),
        dispatch,
    ));
    let device = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    io.attach_device_to_stack(device, lower).unwrap();
    (driver, device)
}

#[test]
fn exact_entry_excludes_upper_filter_and_preserves_lower_forwarding_stack() {
    let mut io = io();
    let (client, root, function_driver, function) =
        pnp_test_stack(&mut io, Box::new(MockDriverBackend::new()));
    let (_, filter) = attach_filter(&mut io, function);
    let top = io
        .prepare_external_pnp_to_device(client, root, 41, parameters(), &[])
        .unwrap();
    let exact = io
        .prepare_external_pnp_to_exact_device(client, function, 42, parameters(), &[])
        .unwrap();
    let top_record = io.irp(top.irp_id()).unwrap();
    assert_eq!(top_record.origin_device_id, root);
    assert_eq!(top_record.current_stack().unwrap().device_id, filter);
    assert_eq!(
        top_record
            .stack
            .iter()
            .map(|s| s.device_id)
            .collect::<Vec<_>>(),
        vec![filter, function, root]
    );
    let exact_record = io.irp(exact.irp_id()).unwrap();
    assert_eq!(exact_record.origin_device_id, function);
    assert_eq!(exact_record.origin_driver_id, function_driver);
    assert_eq!(exact_record.requestor_tid, 42);
    assert_eq!(exact_record.status, NtStatus::NOT_SUPPORTED);
    assert_eq!(exact_record.current_stack().unwrap().device_id, function);
    assert_eq!(
        exact_record
            .stack
            .iter()
            .map(|s| s.device_id)
            .collect::<Vec<_>>(),
        vec![function, root]
    );
    io.discard_prepared_external_pnp(exact).unwrap();
    assert!(io.irp(top.irp_id()).is_some());
    io.discard_prepared_external_pnp(top).unwrap();
    assert_eq!(io.irp_count(), 0);
}

#[test]
fn exact_terminal_receipt_names_supplied_device_not_upper_filter_or_pdo() {
    let mut io = io();
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let (client, _, driver, device) = pnp_test_stack(
        &mut io,
        Box::new(RecordingBackend {
            seen: seen.clone(),
            status: NtStatus::SUCCESS,
            information: 64,
            file_context: None,
            output: Vec::new(),
        }),
    );
    attach_filter(&mut io, device);
    let prepared = io
        .prepare_external_pnp_to_exact_device(client, device, 9, parameters(), &[])
        .unwrap();
    let id = prepared.irp_id();
    match io.dispatch_prepared_external_pnp(prepared).unwrap() {
        ExternalPnpDispatchResult::Returned {
            status,
            information,
            receipt,
        } => {
            assert_eq!(status, NtStatus::SUCCESS);
            assert_eq!(information, 64);
            assert_eq!(receipt.irp_id(), id);
            assert_eq!(receipt.origin_device_id(), device);
            assert_eq!(receipt.origin_driver_id(), driver);
            assert_eq!(receipt.completion_device_id(), device);
            assert_eq!(receipt.completion_driver_id(), driver);
            assert_eq!(receipt.minor(), nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS);
            assert!(!receipt.driver_pending());
        }
        result => panic!("unexpected exact PnP result: {result:?}"),
    }
    assert_eq!(seen.borrow().len(), 1);
    assert_eq!(seen.borrow()[0].device_id, device);
    assert!(io.irp(id).is_none());
}

#[test]
fn missing_exact_route_never_falls_back_to_attached_driver() {
    let mut io = io();
    let (client, root, _, _) = pnp_test_stack(&mut io, Box::new(MockDriverBackend::new()));
    let before = io.irp_count();
    assert!(matches!(
        io.prepare_external_pnp_to_exact_device(client, root, 1, parameters(), &[]),
        Err(NtStatus::INVALID_DEVICE_REQUEST)
    ));
    assert_eq!(io.irp_count(), before);
    let top = io
        .prepare_external_pnp_to_device(client, root, 1, parameters(), &[])
        .unwrap();
    io.discard_prepared_external_pnp(top).unwrap();
}

#[test]
fn invalid_deleted_and_wrong_extent_targets_publish_no_irp() {
    let mut io = io();
    let (client, _, _, device) = pnp_test_stack(&mut io, Box::new(MockDriverBackend::new()));
    assert!(matches!(
        io.prepare_external_pnp_to_exact_device(client, DeviceId(u64::MAX), 1, parameters(), &[]),
        Err(NtStatus::INVALID_PARAMETER)
    ));
    assert!(matches!(
        io.prepare_external_pnp_to_exact_device(
            client,
            device,
            1,
            PnpParameters::start(2, 2).unwrap(),
            &[1, 2]
        ),
        Err(NtStatus::INVALID_PARAMETER)
    ));
    io.device_mut(device).unwrap().delete_pending = true;
    assert!(matches!(
        io.prepare_external_pnp_to_exact_device(client, device, 1, parameters(), &[]),
        Err(NtStatus::DELETE_PENDING)
    ));
    assert!(matches!(
        io.prepare_external_pnp_owned_to_exact_device(client, device, 1, parameters(), Vec::new()),
        Err(NtStatus::DELETE_PENDING)
    ));
    assert_eq!(io.irp_count(), 0);
}

#[test]
fn exact_pending_irp_remains_owned_until_real_completion_and_strict_ack() {
    let mut io = io();
    let ready = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let release = std::rc::Rc::new(std::cell::Cell::new(false));
    let (client, _, driver, device) = pnp_test_stack(
        &mut io,
        Box::new(PendingPnpBackend {
            ready,
            release: release.clone(),
        }),
    );
    attach_filter(&mut io, device);
    let prepared = io
        .prepare_external_pnp_owned_to_exact_device(client, device, 11, parameters(), Vec::new())
        .unwrap();
    let id = prepared.irp_id();
    assert_eq!(
        io.dispatch_prepared_external_pnp(prepared).unwrap(),
        ExternalPnpDispatchResult::Pending { irp_id: id }
    );
    assert_eq!(io.irp(id).unwrap().state, IrpState::Pending);
    assert_eq!(io.irp(id).unwrap().requestor_tid, 11);
    assert!(io.acknowledge_completed_irp_strict(id).is_err());
    assert_eq!(io.pump(), 0);
    release.set(true);
    assert_eq!(io.pump(), 1);
    let receipt = io.take_completed_external_pnp_receipt(id).unwrap();
    assert_eq!(receipt.origin_device_id(), device);
    assert_eq!(receipt.completion_device_id(), device);
    assert_eq!(receipt.origin_driver_id(), driver);
    assert_eq!(receipt.completion_driver_id(), driver);
    assert!(receipt.driver_pending());
    assert!(io.take_completed_external_pnp_receipt(id).is_none());
    assert!(io.irp(id).is_some());
    io.acknowledge_completed_irp_strict(id).unwrap();
    assert!(io.irp(id).is_none());
}

#[test]
fn exact_transport_uncertainty_retains_the_canonical_target() {
    let mut io = io();
    let (client, _, driver, device) = pnp_test_stack(&mut io, Box::new(IndeterminatePnpBackend));
    attach_filter(&mut io, device);
    let prepared = io
        .prepare_external_pnp_to_exact_device(client, device, 12, parameters(), &[])
        .unwrap();
    let id = prepared.irp_id();
    assert_eq!(
        io.dispatch_prepared_external_pnp(prepared).unwrap(),
        ExternalPnpDispatchResult::Indeterminate {
            irp_id: id,
            transport_status: NtStatus::DEVICE_NOT_CONNECTED,
        }
    );
    assert_eq!(io.irp(id).unwrap().origin_device_id, device);
    assert_eq!(io.irp(id).unwrap().state, IrpState::Indeterminate);
    assert_eq!(io.fault_driver(driver), 0);
    assert!(io.completed_irp(id).is_none());
    assert!(io.acknowledge_completed_irp_strict(id).is_err());
    assert!(io.irp(id).is_some());
}

#[test]
fn foreign_dispatch_rejects_colliding_irp_and_returns_original_preparation() {
    let mut issuer = io();
    let (client, _, _, device) = pnp_test_stack(&mut issuer, Box::new(ReturnedFailurePnpBackend));
    let original = issuer
        .prepare_external_pnp_to_exact_device(client, device, 21, parameters(), &[])
        .unwrap();
    let mut other = io();
    let (other_client, _, _, other_device) =
        pnp_test_stack(&mut other, Box::new(ReturnedFailurePnpBackend));
    let resident = other
        .prepare_external_pnp_to_exact_device(other_client, other_device, 21, parameters(), &[])
        .unwrap();
    let id = original.irp_id();
    assert_eq!(resident.irp_id(), id);
    let rejection = other.dispatch_prepared_external_pnp(original).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
    assert_eq!(rejection.prepared().irp_id(), id);
    assert_eq!(other.irp(id).unwrap().state, IrpState::Initialized);
    assert_eq!(issuer.irp(id).unwrap().state, IrpState::Initialized);
    let result = issuer
        .dispatch_prepared_external_pnp(rejection.into_prepared())
        .unwrap();
    assert!(matches!(
        result,
        ExternalPnpDispatchResult::Returned {
            status: NtStatus::ACCESS_DENIED,
            ..
        }
    ));
    assert!(issuer.irp(id).is_none());
    assert_eq!(other.irp(id).unwrap().state, IrpState::Initialized);
    other.discard_prepared_external_pnp(resident).unwrap();
}

#[test]
fn foreign_discard_cannot_remove_colliding_top_stack_preparation() {
    let mut issuer = io();
    let (client, root, _, _) = pnp_test_stack(&mut issuer, Box::new(MockDriverBackend::new()));
    let original = issuer
        .prepare_external_pnp_to_device(client, root, 22, parameters(), &[])
        .unwrap();
    let mut other = io();
    let (other_client, other_root, _, _) =
        pnp_test_stack(&mut other, Box::new(MockDriverBackend::new()));
    let resident = other
        .prepare_external_pnp_to_device(other_client, other_root, 22, parameters(), &[])
        .unwrap();
    let id = original.irp_id();
    assert_eq!(id, resident.irp_id());
    let (status, original) = other
        .discard_prepared_external_pnp(original)
        .unwrap_err()
        .into_parts();
    assert_eq!(status, NtStatus::INVALID_PARAMETER);
    assert_eq!(other.irp(id).unwrap().state, IrpState::Initialized);
    assert_eq!(issuer.irp(id).unwrap().state, IrpState::Initialized);
    issuer.discard_prepared_external_pnp(original).unwrap();
    assert!(issuer.irp(id).is_none());
    assert!(other.irp(id).is_some());
    other.discard_prepared_external_pnp(resident).unwrap();
}

#[test]
fn manager_move_preserves_prepared_and_device_reference_ownership_together() {
    let mut original = io();
    let (client, root, _, device) =
        pnp_test_stack(&mut original, Box::new(ReturnedFailurePnpBackend));
    let mut reference = original.retain_device_reference(device).unwrap();
    let identity = original.ownership_identity();
    let exact = original
        .prepare_external_pnp_to_exact_device(client, device, 23, parameters(), &[])
        .unwrap();
    let top = original
        .prepare_external_pnp_to_device(client, root, 24, parameters(), &[])
        .unwrap();
    assert_eq!(original.ownership_identity(), identity);
    let mut moved = original;
    moved.discard_prepared_external_pnp(top).unwrap();
    assert!(matches!(
        moved.dispatch_prepared_external_pnp(exact).unwrap(),
        ExternalPnpDispatchResult::Returned {
            status: NtStatus::ACCESS_DENIED,
            ..
        }
    ));
    assert_eq!(moved.device_reference_count(device), 1);
    moved.release_device_reference(&mut reference).unwrap();
    assert!(!reference.is_held());
    assert_eq!(moved.irp_count(), 0);
}
