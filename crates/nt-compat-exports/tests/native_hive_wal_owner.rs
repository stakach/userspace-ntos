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

#[test]
fn mounted_hive_log_capacity_is_reserved_before_baseline_and_consumed_after_anchor() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs/hive_wal_native.rs");
    let begin = source.find("pub(crate) unsafe fn begin_native_hive_journal(")
        .expect("native hive admission");
    let poll = source.find("pub(crate) unsafe fn poll_native_hive_journal(")
        .expect("native hive polling");
    let admission = &source[begin..poll];
    let reserve = admission.find("reserve_snapshot_append_by_path(")
        .expect("exact LOG create/append capacity reservation");
    let baseline = admission.find("inspect_baseline_with_reservation(")
        .expect("baseline may create a missing LOG");
    assert!(reserve < baseline, "disk-full must refuse before LOG creation or WAL effects");
    assert!(admission.contains("capacity_reservation"),
        "the retained Journal must own the capacity reservation across BUSY and effects");

    let anchor = source.find("update.into_anchored_publication()")
        .expect("durable paired anchor");
    let replay = source.find("replay_anchored_record_reserved(&journal.path, &journal.record")
        .expect("post-anchor mounted LOG append");
    assert!(anchor < replay, "the reserved append follows the durable WAL and anchor");
    let mounted = include_str!("../../../components/ntos-executive/src/writable_fs/hive_wal.rs");
    assert!(mounted.contains("replay_hive_log_wal_payload_reserved("),
        "post-anchor LOG append consumes the exact prior reservation");
    assert!(source.contains("cancel_snapshot_reservation("),
        "only a proven no-effect abort may return the capacity reservation");
    assert!(source.contains("if journal.capacity_reservation.is_some()"),
        "a retained charge cannot be discarded by successful publication");
}
