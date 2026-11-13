//! Repeated native checkpoints must retain one captured image buffer across calls. The immutable
//! image remains owned through physical I/O; the SYSTEM WAL fold uses the same capture contract.

#[test]
fn native_checkpoint_and_system_fold_reuse_the_captured_snapshot_storage() {
    let checkpoint = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let fold = include_str!("../../../components/ntos-executive/src/writable_fs/system_wal_fold.rs");
    assert!(checkpoint.contains("snapshot_capture::CapturedSnapshot::capture"));
    assert!(fold.contains("snapshot_capture::CapturedSnapshot::capture"));
    assert!(!checkpoint.contains("fs.export_volume_snapshot()"));
    assert!(!fold.contains("fs.export_volume_snapshot()"));
}
