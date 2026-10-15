//! ReactOS class drivers open the registered PDO interface during START, before enabling it.

#[test]
fn registration_publishes_the_exact_pdo_interface_before_class_start_open() {
    let reference = include_str!(
        "../../../references/reactos/drivers/input/kbdclass/kbdclass.c"
    );
    let class_start = &reference[reference.find("case IRP_MN_START_DEVICE:").unwrap()..];
    assert!(class_start.find("ZwOpenFile(").unwrap()
        < class_start.find("IoSetDeviceInterfaceState(").unwrap());

    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let registration = &driver[driver
        .find("unsafe fn register_hosted_device_interface(")
        .unwrap()..];
    let registration = &registration[..registration.find("\n}\n").unwrap()];

    // IoRegisterDeviceInterface returns a name that the class driver opens immediately.
    // The namespace link must therefore exist at registration, bound to this PDO's
    // authenticated target, even while its enabled state remains false.
    assert!(registration.contains("hosted_device_interface_target(pdo_device_id)"));
    assert!(registration.contains("create_symbolic_link(&link, &target)"));
    assert!(registration.contains("enabled: false"));

    let state = &driver[driver
        .find("unsafe fn set_hosted_device_interface_state(")
        .unwrap()..];
    let state = &state[..state.find("\n}\n").unwrap()];
    assert!(state.contains("slot.enabled = enable"));
    assert!(!state.contains("create_symbolic_link("));
    assert!(!state.contains("delete_symbolic_link("));

    let cleanup = &driver[driver.find("unsafe fn clear_hosted_device_interfaces(").unwrap()..];
    let cleanup = &cleanup[..cleanup.find("\n}\n").unwrap()];
    assert!(cleanup.contains("delete_symbolic_link(&link)"));
    assert!(!cleanup.contains("if registration.enabled"));
}

#[test]
fn projected_pdo_registration_uses_its_canonical_devnode_instance() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let resolver = &driver[driver
        .find("unsafe fn hosted_interface_instance_path(")
        .unwrap()..];
    let resolver = &resolver[..resolver.find("\n}\n").unwrap()];

    // A class driver has its own physical projection of the same PDO. Its
    // binding and shared request slot belong to different dispatches, while
    // the PnP devnode retains the exact instance path and generation.
    assert!(resolver.contains("devnode_identity_for_pdo(pdo_device_id)"));
    assert!(resolver.contains("instance_id("));
    assert!(!resolver.contains("SH_REQ_FILEID"));
    assert!(!resolver.contains("hosted_device_bindings()"));
}
