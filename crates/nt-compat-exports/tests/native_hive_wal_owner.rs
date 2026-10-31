//! Native non-SYSTEM hive publication must retain each physical effect through ACK.

#[test]
fn mounted_hive_journal_uses_retained_native_claims() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs/hive_wal_native.rs");
    let start = source.find("pub(crate) unsafe fn begin_native_hive_journal(")
        .expect("mounted hive journal admission");
    let body = &source[start..];
    assert!(source.contains("claim_next_native_hive_io"));
    assert!(source.contains("mark_native_hive_io_entered"));
    assert!(source.contains("complete_native_hive_io"));
    assert!(source.contains("AsyncWalSnapshotAnchorUpdate"));
    assert!(source.contains("snapshot_storage::take_rechecked_wal_continuation"));
    assert!(source.contains("update.into_anchored_publication()"));
    assert!(source.contains("snapshot_storage::install_wal_continuation"));
    assert!(!body.contains("wal.prepare()"));
    assert!(!body.contains("wal.commit()"));
    assert!(!body.contains("update.advance()"));
    assert!(!body.contains("checkpoint_dirty_volume()"));
}
