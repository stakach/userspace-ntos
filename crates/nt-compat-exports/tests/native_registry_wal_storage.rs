//! Native v2 SYSTEM storage owner: source boundary until the executive has a host test harness.

#[test]
fn v2_system_wal_owner_admits_exact_paired_anchor_before_any_write() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs/registry_wal.rs");
    let admit = &source[source.find("pub(crate) unsafe fn admit(").unwrap()
        ..source.find("\n    pub(crate) fn prepare(").unwrap()];
    let mount = admit.find("ensure_mounted()").unwrap();
    let manifest = admit.find("current_wal_checkpoint_manifest").unwrap();
    let paired = admit.find("validate_wal_journal_manifest").unwrap();
    let recovered = admit.find("RegistryWal::recover").unwrap();
    let exact = admit.find("wal.settled_anchor()").unwrap();
    let begin = admit.find("wal.begin(").unwrap();
    assert!(mount < manifest && manifest < paired && paired < recovered
        && recovered < exact && exact < begin);
    assert!(admit.contains("legacy_snapshot_writes_allowed()"));
}

#[test]
fn v2_system_wal_owner_keeps_marker_anchor_and_ack_release_separate() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs/registry_wal.rs");
    let prepare = &source[source.find("pub(crate) fn prepare(").unwrap()
        ..source.find("\n    pub(crate) fn commit_marker(").unwrap()];
    assert!(prepare.contains("wal.prepare()"));
    let marker = &source[source.find("pub(crate) fn commit_marker(").unwrap()
        ..source.find("\n    pub(crate) fn anchor(").unwrap()];
    assert!(marker.contains("wal.commit()"));
    assert!(marker.contains("wal.into_verified_device()"));
    let anchor = &source[source.find("pub(crate) fn anchor(").unwrap()
        ..source.find("\n    pub(crate) fn abort_prepared(").unwrap()];
    assert!(anchor.contains("WalSnapshotAnchorUpdate::admit_verified_wal"));
    assert!(anchor.contains("update.advance()"));
    let release = &source[source.find("pub(crate) fn release_after_ack(").unwrap()..];
    assert!(release.contains("Stage::Anchored"));
    assert!(release.contains("self.commit_receipt != Some(ack.receipt())"),
        "an unrelated CM ACK must not release this WAL lease");
    assert!(release.contains("self.abort_receipt != Some(ack.receipt())"),
        "an unrelated CM abort ACK must not release this WAL lease");
    assert!(source.contains("core::mem::forget(stage)"),
        "an unresolved native owner must keep its exact reserve unavailable");
}

#[test]
fn v2_system_wal_owner_rejects_crossed_preparation_and_receipts_before_disk_effects() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs/registry_wal.rs");
    let admit = &source[source.find("pub(crate) unsafe fn admit(").unwrap()
        ..source.find("\n    pub(crate) fn prepare(").unwrap()];
    assert!(admit.contains("prepared.durable_journal()"));
    assert!(admit.contains("prepared.storage_binding()"));
    assert!(admit.contains("binding,"));
    let marker = &source[source.find("pub(crate) fn commit_marker(").unwrap()
        ..source.find("\n    pub(crate) fn anchor(").unwrap()];
    assert!(marker.contains("receipt.matches_storage_binding(self.binding)"));
    assert!(marker.find("receipt.matches_storage_binding(self.binding)").unwrap()
        < marker.find("wal.commit()").unwrap());
    let abort = &source[source.find("pub(crate) fn abort_prepared(").unwrap()
        ..source.find("\n    pub(crate) fn release_after_ack(").unwrap()];
    assert!(abort.contains("receipt.matches_storage_binding(self.binding)"));
    assert!(abort.find("receipt.matches_storage_binding(self.binding)").unwrap()
        < abort.find("wal.abort_prepared()").unwrap());
}
