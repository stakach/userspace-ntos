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
    let helper = &driver[driver
        .find("unsafe fn drain_hosted_connect_io_work_item(")
        .expect("targeted nested I/O drain")..];
    let end = helper.find("\nunsafe fn ").unwrap();
    let helper = &helper[..end];
    assert!(helper.contains("ready_for_admission"));
    assert!(helper.contains("HOSTED_WORK_QUEUE_KIND_IO"));
    assert!(helper.contains("HostedWorkQueueDrainGuard::enter"));
}
