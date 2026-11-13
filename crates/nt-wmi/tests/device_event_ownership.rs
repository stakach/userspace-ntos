use nt_wmi::{
    WmiDeviceIdentity, WmiEventOwnership, WmiGuid, WmiRegistry, STATUS_INVALID_HANDLE,
    STATUS_WMI_GUID_NOT_FOUND, WMIGUID_NOTIFICATION,
};

const DEVICE: WmiDeviceIdentity = WmiDeviceIdentity {
    domain: 7,
    generation: 11,
    device_object: 0x1000,
};
const GUID: WmiGuid = WmiGuid([0x42; 16]);

#[test]
fn event_requires_live_provider_and_published_notification_guid() {
    let mut registry = WmiRegistry::new();
    assert_eq!(
        registry.plan_device_event(1, GUID, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    let provider = registry.register_device(DEVICE).unwrap();
    assert_eq!(
        registry.plan_device_event(provider, GUID, 0),
        Err(STATUS_WMI_GUID_NOT_FOUND)
    );
    registry
        .publish_device_guids(DEVICE, &[(GUID, WMIGUID_NOTIFICATION)])
        .unwrap();
    assert_eq!(
        registry.plan_device_event(provider, GUID, 0),
        Ok((DEVICE, WmiEventOwnership::TransferPoolOnSuccess))
    );
    assert_eq!(
        registry.plan_device_event(provider, GUID, 0x0002_0000),
        Ok((DEVICE, WmiEventOwnership::RetainCaller))
    );
    registry.unregister_device(DEVICE).unwrap();
    assert_eq!(
        registry.plan_device_event(provider, GUID, 0),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn replacement_generation_cannot_receive_old_provider_events() {
    let mut registry = WmiRegistry::new();
    let old = registry.register_device(DEVICE).unwrap();
    registry
        .publish_device_guids(DEVICE, &[(GUID, WMIGUID_NOTIFICATION)])
        .unwrap();
    registry.unregister_device(DEVICE).unwrap();
    let replacement = WmiDeviceIdentity {
        generation: DEVICE.generation + 1,
        ..DEVICE
    };
    let fresh = registry.register_device(replacement).unwrap();
    assert_ne!(old, fresh);
    assert_eq!(registry.plan_device_event(old, GUID, 0), Err(STATUS_INVALID_HANDLE));
    assert_eq!(registry.plan_device_event(fresh, GUID, 0), Err(STATUS_WMI_GUID_NOT_FOUND));
    assert_eq!(
        registry.publish_device_guids(DEVICE, &[(GUID, WMIGUID_NOTIFICATION)]),
        Err(STATUS_INVALID_HANDLE)
    );
}
