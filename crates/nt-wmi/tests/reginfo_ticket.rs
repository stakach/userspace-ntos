use nt_wmi::{
    WmiDeviceIdentity, WmiEventOwnership, WmiGuid, WmiRegistry, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_WMI_GUID_NOT_FOUND,
};

const DEVICE: WmiDeviceIdentity = WmiDeviceIdentity {
    domain: 7,
    generation: 11,
    device_object: 0x1000,
};
const GUID: WmiGuid = WmiGuid([0x42; 16]);

fn reginfo(guid: WmiGuid) -> Vec<u8> {
    let mut bytes = vec![0; 56];
    bytes[0..4].copy_from_slice(&56u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..40].copy_from_slice(&guid.0);
    bytes
}

#[test]
fn registration_requires_a_dispatched_ticket_and_terminal_packet() {
    let mut registry = WmiRegistry::new();
    let provider = registry.register_device(DEVICE).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    assert_eq!(registry.begin_reginfo(DEVICE), Err(STATUS_INVALID_HANDLE));
    assert_eq!(registry.complete_reginfo(ticket, 0, &reginfo(GUID)), Err(STATUS_INVALID_HANDLE));
    assert_eq!(registry.plan_device_event(provider, GUID, 0), Err(STATUS_WMI_GUID_NOT_FOUND));
    registry.mark_reginfo_dispatched(ticket).unwrap();
    registry.complete_reginfo(ticket, 0, &reginfo(GUID)).unwrap();
    assert_eq!(registry.plan_device_event(provider, GUID, 0), Ok((DEVICE, WmiEventOwnership::TransferPoolOnSuccess)));
    assert_eq!(registry.complete_reginfo(ticket, 0, &reginfo(GUID)), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn failed_terminal_and_pre_dispatch_abort_preserve_prior_publication() {
    let mut registry = WmiRegistry::new();
    let provider = registry.register_device(DEVICE).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.abort_reginfo_before_dispatch(ticket).unwrap();
    assert_eq!(registry.mark_reginfo_dispatched(ticket), Err(STATUS_INVALID_HANDLE));
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(ticket).unwrap();
    assert_eq!(registry.complete_reginfo(ticket, STATUS_INVALID_PARAMETER, &[]), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(registry.plan_device_event(provider, GUID, 0), Err(STATUS_WMI_GUID_NOT_FOUND));
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(ticket).unwrap();
    registry.complete_reginfo(ticket, 0, &reginfo(GUID)).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(ticket).unwrap();
    assert_eq!(registry.complete_reginfo(ticket, 0, &[0; 8]), Err(STATUS_INVALID_PARAMETER));
    assert!(registry.plan_device_event(provider, GUID, 0).is_ok());
}

#[test]
fn retired_dispatched_ticket_blocks_address_reuse_until_terminal_result() {
    let mut registry = WmiRegistry::new();
    registry.register_device(DEVICE).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(ticket).unwrap();
    registry.unregister_device(DEVICE).unwrap();
    let replacement = WmiDeviceIdentity { generation: DEVICE.generation + 1, ..DEVICE };
    assert_eq!(registry.register_device(replacement), Err(STATUS_INVALID_HANDLE));
    assert_eq!(registry.complete_reginfo(ticket, 0, &reginfo(GUID)), Err(STATUS_INVALID_HANDLE));
    let fresh = registry.register_device(replacement).unwrap();
    assert_eq!(registry.plan_device_event(fresh, GUID, 0), Err(STATUS_WMI_GUID_NOT_FOUND));
}

#[test]
fn deregistration_clears_guid_publication_only_after_pending_effect_finishes() {
    let mut registry = WmiRegistry::new();
    let provider = registry.register_device(DEVICE).unwrap();
    let ticket = registry.begin_reginfo(DEVICE).unwrap();
    registry.mark_reginfo_dispatched(ticket).unwrap();
    assert_eq!(registry.deregister_device_guids(DEVICE), Err(STATUS_INVALID_HANDLE));
    registry.complete_reginfo(ticket, 0, &reginfo(GUID)).unwrap();
    registry.deregister_device_guids(DEVICE).unwrap();
    assert_eq!(registry.plan_device_event(provider, GUID, 0), Err(STATUS_WMI_GUID_NOT_FOUND));
    assert_eq!(registry.device_provider_id(DEVICE), Ok(provider));
}
