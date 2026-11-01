//! An entered native disk proof can still be completed by the physical controller's IRQ.
//! A parked user process is not evidence that this retained hardware operation is terminal.

const PROOF: &str = include_str!("../../../components/ntos-executive/src/native_disk_relation.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn entered_native_disk_proof_defers_terminal_quiesce() {
    assert!(PROOF.contains("fn entered_irp(&self) -> Option<IrpId>"),
        "the proof must expose its retained exact IRP, not a generic busy flag");
    assert!(DRIVER.contains("pub(crate) unsafe fn native_disk_proof_hardware_irp_pending() -> bool"),
        "quiesce must inspect the retained relation publication owner");
    let query = DRIVER.split_once("pub(crate) unsafe fn native_disk_proof_hardware_irp_pending() -> bool")
        .expect("proof query").1.split_once("pub(crate) unsafe fn hosted_bus_relation_pending()")
        .expect("query boundary").0;
    assert!(query.contains("HOSTED_DEVICE_RELATION_QUERY")
        && query.contains("HostedRelationPublicationPhase::ProveNativeDisk")
        && query.contains("entered_irp()"),
        "only the exact entered hardware proof may defer terminal quiesce");
    let waiting_gate = SERVICE.split_once("macro_rules! mark_wait_parked")
        .expect("waiting gate").1.split_once("// Boot-milestone watchdog")
        .expect("gate boundary").0;
    assert!(waiting_gate.contains("!driver_launch::native_disk_proof_hardware_irp_pending()"),
        "all user processes waiting must not terminate a live physical disk proof");
    assert_eq!(SERVICE.matches("!driver_launch::native_disk_proof_hardware_irp_pending()")
        .count(), 2, "both waiting and LSASS-fault quiesce paths must retain the proof");
}
