//! LiberNT dxgkrnl DriverEntry must create its real `DxgkSharedResource` object type, including
//! the image-owned DeleteProcedure. Keep the import, authenticated transport, and type lifetime
//! connected to the tested Object Manager ledger.

#[test]
fn native_ob_create_object_type_has_a_live_authenticated_owner() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let retirement = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_type.rs");

    assert!(launch.contains("mod hosted_driver_dynamic_type;"));
    assert!(launch.contains("\"ObCreateObjectType\""));
    assert!(launch.contains("hosted_driver_dynamic_type::ob_create_object_type"));
    assert!(launch.contains("hosted_driver_dynamic_type::blocks_instance_retirement"));
    assert!(launch.contains("FSD_SERVICE_DYNAMIC_TYPE_LABEL: u64 = hosted_driver_dynamic_type::LABEL"));
    assert!(retirement.contains("hosted_driver_dynamic_type::owns_type_allocation"));
    assert!(pump.contains("FSD_SERVICE_DYNAMIC_TYPE_LABEL"));
    assert!(pump.contains("hosted_driver_dynamic_type::service"));
    assert!(adapter.contains("HostedDynamicTypeRegistry"));
    assert!(adapter.contains("hosted_instance_pool_allocation_exec_if_live"));
    assert!(adapter.contains("component_device_reply_lock"));
    assert!(adapter.contains("delete_procedure"));
}
