use nt_hive_core::{
    boot_object_protection_mode_from_image, encode_image, BootObjectPolicyError, Hive, HiveKind,
    RegistryValueType,
};

fn system(selected: u32) -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    assert!(hive.set_dword(select, "Current", selected));
    hive.create_key(&format!("ControlSet{selected:03}"));
    hive
}

#[test]
fn composed_core_transport_uses_the_actual_selected_control_set() {
    let mut hive = system(2);
    let stale = hive.create_key("ControlSet001\\Control\\Session Manager");
    assert!(hive.set_dword(stale, "ProtectionMode", 7));
    let selected = hive.create_key("ControlSet002\\Control\\Session Manager");
    assert!(hive.set_dword(selected, "ProtectionMode", 1));
    assert_eq!(boot_object_protection_mode_from_image(&encode_image(&hive)), Ok(1));
}

#[test]
fn only_absent_policy_uses_the_nt_zero_initial_value() {
    let mut hive = system(1);
    assert_eq!(boot_object_protection_mode_from_image(&encode_image(&hive)), Ok(0));
    hive.create_key("ControlSet001\\Control\\Session Manager");
    assert_eq!(boot_object_protection_mode_from_image(&encode_image(&hive)), Ok(0));
}

#[test]
fn policy_retains_the_full_dword_not_a_boolean() {
    for value in [0, 1, 2, 0x8000_0001, u32::MAX] {
        let mut hive = system(1);
        let key = hive.create_key("ControlSet001\\Control\\Session Manager");
        assert!(hive.set_dword(key, "ProtectionMode", value));
        assert_eq!(boot_object_protection_mode_from_image(&encode_image(&hive)), Ok(value));
    }
}

#[test]
fn malformed_present_policy_does_not_become_absence() {
    for (kind, data) in [
        (RegistryValueType::Binary, vec![1, 0, 0, 0]),
        (RegistryValueType::Dword, vec![1, 0, 0]),
        (RegistryValueType::Dword, vec![]),
        (RegistryValueType::Dword, vec![1, 0, 0, 0, 0]),
    ] {
        let mut hive = system(1);
        let key = hive.create_key("ControlSet001\\Control\\Session Manager");
        assert!(hive.set_value(key, "ProtectionMode", kind, data));
        assert_eq!(boot_object_protection_mode_from_image(&encode_image(&hive)),
            Err(BootObjectPolicyError::InvalidProtectionMode));
    }
}

#[test]
fn invalid_selection_and_corrupt_transport_are_rejected() {
    for hive in [Hive::new(HiveKind::System), Hive::new(HiveKind::Software), system(0)] {
        assert!(matches!(boot_object_protection_mode_from_image(&encode_image(&hive)),
            Err(BootObjectPolicyError::Selection(_))));
    }
    let mut hive = system(1);
    let select = hive.open_key("Select").unwrap();
    assert!(hive.set_value(select, "Current", RegistryValueType::Binary, vec![1, 0, 0, 0]));
    assert!(matches!(boot_object_protection_mode_from_image(&encode_image(&hive)),
        Err(BootObjectPolicyError::Selection(_))));
    assert!(hive.set_dword(select, "Current", 9));
    assert!(matches!(boot_object_protection_mode_from_image(&encode_image(&hive)),
        Err(BootObjectPolicyError::Selection(_))));
    let mut bytes = encode_image(&system(1));
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert!(matches!(boot_object_protection_mode_from_image(&bytes),
        Err(BootObjectPolicyError::Image(_))));
}
