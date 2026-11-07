//! GDI image bytes must come from the mounted File route after storage handoff.

const OWNER: &str =
    include_str!("../../../components/ntos-executive/src/mounted_system_image_read.rs");

#[test]
fn mounted_system_image_snapshot_retains_exact_file_io_through_ack() {
    assert!(
        OWNER.contains("exec_volume_device()"),
        "the registered mount selects the File device"
    );
    assert!(OWNER.contains("allocate_external_file("));
    assert!(OWNER.contains("IRP_MJ_CREATE"));
    assert!(OWNER.contains("FILE_STANDARD_INFORMATION"));
    assert!(OWNER.contains("RoutedImageRead"));
    assert!(OWNER.contains("IRP_MJ_READ"));
    assert!(OWNER.contains("completed_irp_exact("));
    assert!(OWNER.contains("copy_completed_irp_output_exact("));
    assert!(OWNER.contains("acknowledge_completed_irp_strict("));
    assert!(OWNER.contains("queue_external_file_release("));
    assert!(
        OWNER.contains("system_image_load_plan::retry_driver_path"),
        "Drivers fallback requires proven absence"
    );
    assert!(!OWNER.contains("fat_read_file("));
}

#[test]
fn terminal_copy_anomaly_flows_to_exact_ack_instead_of_waiting_forever() {
    let query = OWNER
        .split_once("Phase::QueryCopy(irp, mut bytes, copied) =>")
        .expect("pending query copy")
        .1;
    let query = query
        .split_once("let copied = copied + copied_now;")
        .expect("query copy terminal")
        .0;
    assert!(
        query.contains("Phase::QueryAck(irp, Err(IO_ERROR))"),
        "zero or invalid copied bytes must become an ACK-owned I/O error"
    );
    assert!(
        query.contains("Phase::QueryAck(irp, Err(status))"),
        "a terminal copy error must retain the exact query IRP for strict ACK"
    );

    let read = OWNER
        .split_once("unsafe fn advance_read(&mut self)")
        .expect("routed READ owner")
        .1;
    let ack = read
        .find("RoutedImageRead::acknowledgment_key")
        .expect("READ ACK boundary");
    let read = &read[..ack];
    assert!(
        read.contains("fail_copy(irp, IO_ERROR)"),
        "zero or invalid copied READ bytes must flow into the read's ACK state"
    );
    assert!(
        read.contains("fail_copy(irp, status)"),
        "terminal READ copy errors must flow into the read's ACK state"
    );
}

#[test]
fn pending_terminal_matches_the_exact_completion_route() {
    let exact = OWNER.split_once("fn exact(&self, completion:")
        .expect("pending image completion validator").1;
    let exact = exact.split_once("unsafe fn cancel_pending")
        .expect("validator boundary").0;
    assert!(exact.contains("completion.completion_driver_id == self.driver"));
    assert!(exact.contains("completion.completion_device_id == self.device"));
}
