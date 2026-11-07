//! Pinned LiberNT dxgkrnl creates an `DxgkSharedResource` body before inserting its NT handle.

#[test]
fn native_dynamic_object_creation_uses_authenticated_type_and_owned_body() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_object.rs");
    assert!(launch.contains("\"ObCreateObject\""));
    assert!(launch.contains("hosted_driver_dynamic_object::ob_create_object"));
    assert!(pump.contains("FSD_SERVICE_DYNAMIC_OBJECT_LABEL"));
    assert!(pump.contains("hosted_driver_dynamic_object::service"));
    assert!(adapter.contains("type_binding_for_instance"));
    assert!(adapter.contains("hosted_instance_pool_allocation_exec_if_live"));
    assert!(adapter.contains("publish_object"));
    assert!(adapter.contains("component_device_reply_lock"));
}

#[test]
fn native_dynamic_object_insert_uses_a_reserved_process_handle() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_object.rs");
    assert!(launch.contains("\"ObInsertObject\""));
    assert!(launch.contains("hosted_driver_dynamic_object::ob_insert_object"));
    assert!(pump.contains("FSD_SERVICE_DYNAMIC_OBJECT_INSERT_LABEL"));
    assert!(pump.contains("hosted_driver_dynamic_object::insert_service"));
    assert!(adapter.contains("pending_object_for_instance"));
    assert!(adapter.contains("try_reserve_handle_slot"));
    assert!(adapter.contains("bind_reserved_handle"));
    assert!(adapter.contains("publish_reserved_handle"));
    assert!(adapter.contains("DynamicHandleOwner"));
    assert!(adapter.contains("fail_pending_insert(lease)"),
        "authenticated insertion failures must consume the creator reference");
}

#[test]
fn dynamic_handle_reference_checks_canonical_table_and_exact_type() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_object.rs");
    assert!(launch.contains("hosted_driver_dynamic_object::reference_object_by_handle"));
    assert!(pump.contains("FSD_SERVICE_DYNAMIC_OBJECT_REFERENCE_LABEL"));
    assert!(pump.contains("hosted_driver_dynamic_object::reference_service"));
    assert!(adapter.contains("HandleObject::DynamicObject"));
    assert!(adapter.contains("registry.reference_handle"));
    assert!(adapter.contains("type_binding_for_instance"));
    assert!(adapter.contains("pm.lookup_handle"));
}
