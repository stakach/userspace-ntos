//! The native class driver must reach a live interface registration and the CM Key broker.
//! A resolved path or a synthetic numeric handle alone cannot satisfy this contract.

#[test]
fn native_interface_key_uses_registered_identity_and_canonical_key_publication() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let registration = launch
        .split_once("struct HostedDeviceInterfaceRegistration {")
        .expect("native interface registration")
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert!(registration.contains("owner_domain"));
    assert!(registration.contains("pdo_device_id"));
    assert!(registration.contains("devnode_generation"));
    assert!(registration.contains("instance_path"));
    assert!(registration.contains("symbolic_link"));

    let provider = include_str!("../../../components/ntos-executive/src/hosted_driver_interface_registry.rs");
    assert!(provider.contains("extern \"win64\" fn open("));
    assert!(provider.contains("HOSTED_REGISTRY_OP_OPEN_INTERFACE_KEY"));
    assert!(provider.contains("acknowledge_registry_handle_output(handle)"));

    assert!(launch.contains("hosted_driver_interface_registry::bind(reg);"));
    assert!(launch.contains("hosted_driver_interface_registry::service_open("));
    assert!(launch.contains("hosted_driver_interface_registry::service_register("));
    assert!(provider.contains("resolve_interface_instance_key("));
    assert!(provider.contains("service_hosted_driver_create_registry_path("));

    let retained = include_str!("../../../components/ntos-executive/src/registry_mutation_provider.rs");
    assert!(retained.contains("SystemHiveMutation::CreateKey { path: &value.registry_parent }"));
    assert!(retained.contains("ProviderAdmission::InterfaceRegister(value) => match value.publish()"));
    assert!(provider.contains("register_hosted_device_interface("));
}

#[test]
fn interface_revision_retry_retains_mount_and_revalidates_live_registration() {
    let provider = include_str!("../../../components/ntos-executive/src/hosted_driver_interface_registry.rs");
    let mutation = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    assert!(provider.contains("revalidate_interface_registration_revision("));
    assert!(provider.contains("hosted_interface_instance_path(self.pdo.raw())"));
    assert!(provider.contains("devnode_identity_for_pdo(pdo.raw())"));
    assert!(mutation.contains("validate_system_hive_mount(value.mount, generation)"));
    assert!(mutation.contains("value.revalidate_for_revision_retry("));
    assert!(mutation.contains("retry_acknowledged_revision(attempt, value.mount, generation)"));
}
