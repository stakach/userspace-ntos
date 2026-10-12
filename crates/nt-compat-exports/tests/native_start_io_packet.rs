//! The first packet owner must be admitted from the root's exact op6 projection.
//! The callback and terminal path are separate work; packet imports stay unbound until then.

use std::path::Path;

fn native(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    std::fs::read_to_string(path).expect("native StartIo source")
}

#[test]
fn projected_packet_admission_uses_root_node_and_physical_source_owner() {
    let source = native("hosted_source_irp_ledger.rs");
    let adapter = native("hosted_start_io.rs");
    let memory = native("hosted_start_io_packet.rs");
    assert!(source.contains("fn admit_projected_start_io_packet("));
    assert!(source.contains("StartIoAdmission::acquire_projected("));
    assert!(source.contains("caller_projections()"));
    assert!(source.contains("projected_node("));
    assert!(adapter.contains("fn prepare_first_projected_packet("));
    assert!(adapter.contains("CurrentReceipt::new("));
    assert!(adapter.contains("LivePacket::new("));
    assert!(memory.contains("hosted_instance_pool_lock("));
    assert!(memory.contains("impl LockedStartIoMemory for LockedFirstPacketMemory"));
}

#[test]
fn packet_imports_wait_for_callback_and_terminal_integration() {
    let launch = native("driver_launch.rs");
    let registry = launch
        .split("fn register_fsd_trampolines(")
        .nth(1)
        .expect("import registry");
    for import in ["IoStartPacket", "IoStartNextPacket", "IoStartNextPacketByKey"] {
        assert!(!registry.contains(&format!("reg.bind(\"{import}\"")));
        assert!(!registry.contains(&format!("\"{import}\",")));
    }
}

#[test]
fn first_packet_commit_retains_current_and_callback_before_reply() {
    let adapter = native("hosted_start_io.rs");
    let memory = native("hosted_start_io_packet.rs");
    assert!(adapter.contains("fn commit_first_projected_packet("));
    assert!(adapter.contains("CommittedStartIo::new("));
    assert!(adapter.contains("fn begin_first_packet_reply("));
    assert!(adapter.contains("fn first_packet_callback_returned("));
    assert!(adapter.contains("retain_hosted_device_projection_reference("));
    assert!(adapter.contains("release_prepared_first_packet("));
    assert!(adapter.contains("release_projected_start_io_packet("));
    assert!(memory.contains("start_io::start_packet::<_, ()>("));
    assert!(memory.contains("prepare_update("));
    assert!(memory.contains("prepared_update.commit("));
}
