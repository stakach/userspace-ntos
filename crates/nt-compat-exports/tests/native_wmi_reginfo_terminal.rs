//! REGINFO driver dispatch must retain its source packet across pending
//! completion, capture the bounded result, then resume terminal reclamation.

#[test]
fn native_reginfo_waits_for_exact_terminal_before_returning_bytes() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_wmi_reginfo.rs");
    assert!(source.contains("hosted_synchronous_fsd_request::build_wmi_reginfo("));
    assert!(source.contains("s_io_forward_sync_completion"));
    assert!(source.contains("s_iof_call_driver(device, irp)"));
    assert!(source.contains("s_ke_wait_for_single_object"));
    assert!(source.contains("completed.load(Ordering::Acquire)"));
    assert!(source.contains("component_pool_allocation_capacity(buffer)"));
    assert!(source.contains("copy_nonoverlapping"));
    assert!(source.contains("s_io_complete_request(self.irp, 0)"));
}
