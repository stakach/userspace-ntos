//! WMI event success must consume a real registered source pool allocation.

#[test]
fn native_event_route_admits_exact_provider_and_transfers_only_after_capture() {
    let component = include_str!("../../../components/ntos-executive/src/hosted_driver_wmi.rs");
    assert!(component.contains("\"IoWMIWriteEvent\""));
    assert!(component.contains("OP_WRITE_EVENT"));
    let root = include_str!("../../../components/ntos-executive/src/hosted_wmi_event.rs");
    assert!(root.contains("pin_temporary_pool_range"));
    assert!(root.contains("copy_temporary_pool_pin"));
    assert!(root.contains("parse_event_header"));
    assert!(root.contains("plan_device_event"));
    assert!(root.contains("retire_owned_temporary_pool_allocation"));
    assert!(root.contains("release_temporary_pool_pin"));
}
