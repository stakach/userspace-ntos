//! A retained physical SCSI IRP remains a signaler after its logical READ owner settles.

const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn pending_physical_irp_predicate_reads_the_retained_command_owner() {
    let start = BLOCK.find("pub(super) fn pending_physical_irp()").expect("physical IRP owner predicate");
    let predicate = &BLOCK[start..start + BLOCK[start..].find("\n}").unwrap()];
    assert!(predicate.contains("addr_of!(PENDING)"));
    assert!(predicate.contains("pending.irp.raw()"));
    assert!(!predicate.contains("NATIVE_PENDING_IRP.load"),
        "the census atomic is an observation, not the retained command authority");

    let bridge = LAUNCH.find("pub(crate) fn mounted_native_physical_irp_pending()").expect("driver-launch bridge");
    assert!(LAUNCH[bridge..].starts_with("pub(crate) fn mounted_native_physical_irp_pending() -> bool {\n    mounted_native_block::pending_physical_irp()"));
}

#[test]
fn every_no_signaler_gate_retains_the_physical_irp_and_reports_it() {
    assert_eq!(SERVICE.matches("!driver_launch::mounted_native_physical_irp_pending()").count(), 3,
        "all-live-parked, all-live-waiting, and lsass-post-signal-fault must retain the physical IRP");
    let snapshot = &BLOCK[BLOCK.find("pub(super) fn print_quiesce_snapshot()").expect("quiesce snapshot")..];
    for evidence in ["physical-pending-irp=", "source=", "bytes=", "outstanding-Mtick="] {
        assert!(snapshot.contains(evidence), "bounded quiesce snapshot should report {evidence}");
    }
}
