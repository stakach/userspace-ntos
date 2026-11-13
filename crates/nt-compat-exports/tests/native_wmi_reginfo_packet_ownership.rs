//! REGINFO must enter driver dispatch only after its IRP and output allocation
//! have been adopted as a single source-owned graph.

#[test]
fn reginfo_packet_uses_source_ledger_publication_and_guarded_rollback() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_synchronous_fsd_request.rs");
    let guard = source
        .split_once("struct UnpublishedRequest {")
        .expect("unpublished source guard")
        .1
        .split_once("pub(super) unsafe fn device_contract")
        .expect("guard implementation")
        .0;
    assert!(guard.contains("fn allocate_system_buffer"));
    assert!(guard.contains("(FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4"));
    assert!(guard.contains("self.irp = 0;"));
    assert!(guard.contains("self.system_buffer = 0;"));
    assert!(guard.contains("impl Drop for UnpublishedRequest"));
    assert!(guard.contains("s_io_free_irp(self.irp)"));
    assert!(guard.contains("pool_free(self.system_buffer)"));

    let builder = source
        .split_once("pub(super) unsafe fn build_wmi_reginfo(")
        .expect("WMI builder")
        .1;
    let allocation = builder.find("request.allocate_system_buffer(capacity)").unwrap();
    let stack = builder.find("write_wdm_io_stack_location(stack_bytes, plan.stack)").unwrap();
    let publish = builder.find("request.publish(plan, event, iosb)").unwrap();
    assert!(allocation < stack && stack < publish);
    assert!(builder.contains("request.publish(plan, event, iosb)"));
    assert!(!builder.contains("s_iof_call_driver("));

    let source_ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    assert!(source_ledger.contains("major::IRP_MJ_SYSTEM_CONTROL"));
    assert!(source_ledger.contains("minor == 8"));
    assert!(source_ledger.contains("wmi_buffer != system_address"));
    assert!(source_ledger.contains("wmi_provider_id != device_object"));
}
