//! A POWER lower edge retains both canonical and native owners until terminal ACK.

use super::*;
use crate::power_irp_request::PowerParameters;
use crate::CompletionAcknowledgement;
use std::vec;

#[test]
fn exact_power_entry_excludes_upper_filter_and_preserves_request_fields() {
    let mut io = io();
    let (client, root, _, device) = pnp_test_stack(&mut io, Box::new(MockDriverBackend::new()));
    let (_, upper) = {
        let backend = io.register_backend(Box::new(MockDriverBackend::new()));
        let mut dispatch = MajorFunctionTable::new();
        dispatch.set_all(DispatchTarget::DriverPeer(DriverPeerId(backend as u64)));
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL, path("\\Driver\\PowerUpper"), DriverBackendId(backend as u64), dispatch,
        ));
        let upper = io.create_device(driver, None, DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
        io.attach_device_to_stack(upper, device).unwrap();
        (driver, upper)
    };
    let parameters = PowerParameters::device(nt_power_types::IRP_MN_SET_POWER, 3).unwrap();
    let prepared = io.prepare_external_power_to_exact_device(client, device, 42, parameters).unwrap();
    let irp = io.irp(prepared.irp_id()).unwrap();
    assert_eq!(irp.origin_device_id, device);
    assert_eq!(irp.origin_minor, nt_power_types::IRP_MN_SET_POWER);
    assert_eq!(irp.current_stack().unwrap().parameters, IoParameters::Power(parameters));
    assert_eq!(irp.stack.iter().map(|s| s.device_id).collect::<Vec<_>>(), vec![device, root]);
    assert!(!irp.stack.iter().any(|s| s.device_id == upper));
    io.discard_prepared_external_power(prepared).unwrap();
    assert_eq!(io.irp_count(), 0);
}

#[test]
fn pending_power_completion_requires_real_terminal_and_one_exact_ack() {
    let mut io = io();
    let ready = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let release = std::rc::Rc::new(std::cell::Cell::new(false));
    let (client, _, _, device) = pnp_test_stack(&mut io,
        Box::new(PendingPnpBackend { ready, release: release.clone() }));
    let parameters = PowerParameters::device(nt_power_types::IRP_MN_QUERY_POWER, 1).unwrap();
    let prepared = io.prepare_external_power_to_exact_device(client, device, 11, parameters).unwrap();
    let id = prepared.irp_id();
    let invocation = io.begin_prepared_external_power(prepared).unwrap();
    let backend = io.driver(invocation.projection().driver_id).unwrap().backend.0 as usize;
    let returned = invocation.invoke(|ctx, projection|
        io.backends[backend].dispatch_power_irp(ctx, projection));
    let retained = match io.finish_external_power(returned).unwrap() {
        ExternalPowerFinishResult::Retained(owner) => owner,
        result => panic!("pending POWER owner missing: {result:?}"),
    };
    assert_eq!(retained.irp_id(), id);
    let rejection = io.prepare_external_power_completion(retained).unwrap_err();
    assert_eq!(rejection.status(), NtStatus::PENDING);
    let retained = rejection.into_owner();
    assert_eq!(io.pump(), 0);
    release.set(true);
    assert_eq!(io.pump(), 1);
    let completion = io.prepare_external_power_completion(retained).unwrap();
    assert_eq!(completion.completion().minor, nt_power_types::IRP_MN_QUERY_POWER);
    let returned = completion.invoke(|_| CompletionAcknowledgement::Acknowledged);
    let receipt = io.finish_external_power_completion(returned).unwrap();
    assert_eq!(receipt.status(), NtStatus::SUCCESS);
    assert!(io.irp(id).is_none());
}
