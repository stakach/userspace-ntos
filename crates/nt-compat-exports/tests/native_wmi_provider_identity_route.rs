//! A native WMI provider ID must derive from a live canonical device pointer
//! registration and retire with that same incarnation.

#[test]
fn provider_id_route_is_bound_to_exact_live_pointer_and_retirement() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let service = include_str!("../../../components/ntos-executive/src/hosted_driver_wmi.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");

    assert!(launch.contains("hosted_driver_wmi::bind(reg);"));
    assert!(launch.contains("hosted_driver_wmi::retire_device(registration)"));
    assert!(pump.contains("service_hosted_driver_wmi("));
    assert!(service.contains("hosted_driver_caller(index, inst, badge)"));
    assert!(service.contains("hosted_device_pointer_registration(domain, device_object)"));
    assert!(service.contains("hosted_device_binding_by_device_id(registration.device_id().raw())"));
    assert!(service.contains("generation: registration.generation()"));
    assert!(service.contains("registry.register_device(identity)"));
    assert!(service.contains("registry.unregister_device(identity)"));
}
