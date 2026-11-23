//! The native interrupt projection must use the translated resource level as DIRQL.

#[test]
fn hosted_interrupt_policy_uses_translated_level_independently_of_vector() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let grant = &driver[driver
        .find("pub(crate) unsafe fn grant_hosted_device_resources(")
        .unwrap()..];
    let grant = &grant[..grant.find("\n}\n").unwrap()];
    assert!(grant.contains("interrupt_irql: u8"));
    assert!(grant.contains("interrupt_irql,"));
    assert!(!grant.contains("interrupt_vector.min(0xF) as u8"));
    let state = &driver[driver.find("struct HostedDeviceResourceState {").unwrap()..];
    let state = &state[..state.find("\n}").unwrap()];
    assert!(state.contains("interrupt_irql: u8"));
    assert!(driver.contains("hosted_interrupt_policy(\n            state.interrupt_irql,"));
    assert!(driver.contains("HalResourceDescriptor::interrupt_args(\n            interrupt_vector,\n            interrupt_irql,"));
    let hal = &driver[driver
        .find("extern \"win64\" fn s_hal_get_interrupt_vector(")
        .unwrap()..];
    let hal = &hal[..hal.find("\n}\n").unwrap()];
    assert!(hal.contains("SH_RESOURCE_INTERRUPT_POLICY"));
    assert!(!hal.contains("granted_vector.min(0xF)"));
    let acpi = main
        .split_once("unsafe fn grant_hosted_acpi_child_devnode_resources(")
        .unwrap()
        .1
        .split_once("\n}\n")
        .unwrap()
        .0;
    let (preflight, grant) = acpi.split_once("claim_acpi_child_interrupt(").unwrap();
    assert!(preflight.contains("let interrupt_irql = u8::try_from(interrupt.level)"));
    assert!(grant.contains("assignment.route.vector,\n        interrupt_irql,"));
}
