//! A parked native SCSI command must identify the exact hosted worker and Reply in diagnostics.

const DRIVER_LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const TCB_TRACE: &str = include_str!("../../../components/ntos-executive/src/scsi_srb_owner_tcb_trace.rs");

#[test]
fn active_scsi_owner_census_reads_its_exact_worker_and_reply_state() {
    let census = DRIVER_LAUNCH
        .split_once("fn print_scsi_srb_pump_timing()")
        .expect("SCSI owner census")
        .1
        .split_once("unsafe fn dispatch_irp_for_instance_exact(")
        .expect("census boundary")
        .0;
    assert!(census.contains("scsi_srb_owner_tcb_trace::print(&owner)"));
    assert!(TCB_TRACE.contains("tcb_read_debug_state(owner.tcb, owner.reply_cap"));
    assert!(TCB_TRACE.contains("TCB_DBG_PENDING_REPLY"));
    assert!(TCB_TRACE.contains("TCB_DBG_REPLY_BOUND_TCB"));
}
