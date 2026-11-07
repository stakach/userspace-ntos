use nt_wmi::{WmiDeviceIdentity, WmiRegistry, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

const ORIGINAL: WmiDeviceIdentity = WmiDeviceIdentity {
    domain: 7,
    generation: 11,
    device_object: 0x1000,
};

#[test]
fn provider_id_is_stable_for_one_live_device_and_distinct_for_another() {
    let mut registry = WmiRegistry::new();
    assert_eq!(registry.device_provider_id(ORIGINAL), Err(STATUS_INVALID_HANDLE));

    let first = registry.register_device(ORIGINAL).unwrap();
    assert_ne!(first, 0);
    assert_eq!(registry.device_provider_id(ORIGINAL), Ok(first));
    assert_eq!(registry.register_device(ORIGINAL), Ok(first));

    let second_device = WmiDeviceIdentity {
        device_object: 0x2000,
        ..ORIGINAL
    };
    let second = registry.register_device(second_device).unwrap();
    assert_ne!(first, second);
    assert_eq!(registry.device_provider_id(second_device), Ok(second));
}

#[test]
fn retired_and_stale_generations_cannot_retarget_a_reused_device_address() {
    let mut registry = WmiRegistry::new();
    let original_id = registry.register_device(ORIGINAL).unwrap();
    registry.unregister_device(ORIGINAL).unwrap();
    assert_eq!(registry.device_provider_id(ORIGINAL), Err(STATUS_INVALID_HANDLE));

    let replacement = WmiDeviceIdentity {
        generation: ORIGINAL.generation + 1,
        ..ORIGINAL
    };
    let replacement_id = registry.register_device(replacement).unwrap();
    assert_ne!(original_id, replacement_id);
    assert_eq!(registry.device_provider_id(replacement), Ok(replacement_id));
    assert_eq!(registry.unregister_device(ORIGINAL), Err(STATUS_INVALID_HANDLE));
    assert_eq!(registry.register_device(ORIGINAL), Err(STATUS_INVALID_HANDLE));
    assert_eq!(registry.device_provider_id(replacement), Ok(replacement_id));
}

#[test]
fn zero_identity_components_are_not_registerable() {
    let mut registry = WmiRegistry::new();
    for invalid in [
        WmiDeviceIdentity { domain: 0, ..ORIGINAL },
        WmiDeviceIdentity { generation: 0, ..ORIGINAL },
        WmiDeviceIdentity { device_object: 0, ..ORIGINAL },
    ] {
        assert_eq!(registry.register_device(invalid), Err(STATUS_INVALID_PARAMETER));
    }
    assert_eq!(registry.device_provider_id(ORIGINAL), Err(STATUS_INVALID_HANDLE));
}
