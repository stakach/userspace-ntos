//! A parked class CONNECT must drive only its exact port's queued I/O worker.

#[test]
fn nested_connect_redrive_requires_targeted_io_queue_drain() {
    let connect = include_str!("../../../components/ntos-executive/src/hosted_connect_live.rs");
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let redrive = &connect[connect.find("pub(super) unsafe fn redrive() {").unwrap()..];
    assert!(
        redrive.contains("drain_hosted_connect_io_work_item("),
        "pending CONNECT must drive the exact provider's queued IO work"
    );
    let candidate = &driver[driver
        .find("unsafe fn hosted_connect_io_work_candidate(")
        .expect("exact nested I/O candidate")..];
    let candidate = candidate.split_once("\nunsafe fn ").unwrap().0;
    assert!(candidate.contains("ready_for_admission"));
    assert!(candidate.contains("HOSTED_WORK_QUEUE_KIND_IO"));
    let drain = &driver[driver
        .find("unsafe fn drain_hosted_connect_io_work_item(")
        .expect("targeted nested I/O drain")..];
    let drain = drain.split_once("\nunsafe fn ").unwrap().0;
    assert!(drain.contains("hosted_connect_io_work_candidate("));
    assert!(drain.contains("HostedWorkQueueDrainGuard::enter"));
}
