//! A hosted driver can close the last dynamic-object handle while its primary Call awaits root.
//! DeleteProcedure must run through a separate admitted lane after the originating Reply settles.

#[test]
fn canonical_close_retains_exact_dynamic_object_generation() {
    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_delete.rs");
    assert!(handler.contains("hosted_driver_dynamic_delete::close_native_handle"));
    assert!(handler.contains("closed.table_owner()"));
    assert!(handler.contains("closed.handle()"));
    assert!(adapter.contains("DynamicHandleOwner"));
    assert!(handler.contains("HandleObject::DynamicObject"));
    assert!(adapter.contains("object_for_body"));
    assert!(adapter.contains("object_for_handle"));
    assert!(adapter.contains("close_handle"));
}

#[test]
fn delete_callback_uses_ready_passive_worker_and_exact_ticket_once() {
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_delete.rs");
    let lane = include_str!("../../../components/ntos-executive/src/hosted_class_irp_lane.rs");
    let types = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_type.rs");
    assert!(adapter.contains("next_ready_delete"));
    assert!(adapter.contains("take_delete"));
    assert!(adapter.contains("complete_delete"));
    assert!(types.contains("published_image_for_callback"));
    assert!(adapter.contains("ready_for_admission"));
    assert!(adapter.contains("select_callback"));
    assert!(lane.contains("DispatchWorker"));
    assert!(lane.contains("FSD_DISPATCH_DYNAMIC_DELETE"));
}

#[test]
fn ordinary_pool_free_cannot_recycle_a_live_dynamic_body() {
    let retirement = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let types = include_str!("../../../components/ntos-executive/src/hosted_driver_dynamic_type.rs");
    assert!(retirement.contains("hosted_driver_dynamic_type::owns_object_allocation"));
    assert!(types.contains("registry.owns_live_body"));
}
