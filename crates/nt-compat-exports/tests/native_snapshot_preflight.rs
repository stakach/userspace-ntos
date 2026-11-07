//! A boot-route checkpoint may start inside a nearly full transient syscall scope. Its cursor
//! must be prepared in durable storage before disk I/O, and a refused preparation must return
//! the exact WAL authority rather than permanently poisoning the mounted volume.

#[test]
fn synchronous_wal_checkpoint_prepares_durably_and_restores_unentered_authority() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let start = source.find("unsafe fn checkpoint_volume_snapshot(").unwrap();
    let end = source[start..].find("pub(crate) unsafe fn verify_durable_system_wal").unwrap() + start;
    let checkpoint = &source[start..end];
    let durable = checkpoint.find("allocator::enter_durable()").expect("durable scratch scope");
    let prepare = checkpoint.find("AsyncSnapshotCommit::new(").expect("pre-entry cursor preparation");
    let execute = checkpoint.find("commit.run_sync(dev)").expect("prepared cursor enters disk");
    assert!(durable < prepare && prepare < execute);

    let dirty_start = source.find("pub(crate) unsafe fn checkpoint_dirty_volume()").unwrap();
    let dirty_end = source[dirty_start..].find("pub(crate) unsafe fn compact_unreferenced_blobs").unwrap() + dirty_start;
    let dirty = &source[dirty_start..dirty_end];
    assert!(dirty.contains("SnapshotCommitFailure::Unentered(status)"));
    assert!(dirty.contains("restore_unwritten_checkpoint_authority(dev, authority, status)"));
    assert!(dirty.contains("SnapshotCommitFailure::Entered(status)"));
}
