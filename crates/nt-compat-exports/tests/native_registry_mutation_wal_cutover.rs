//! Source boundary for the shared retained SYSTEM mutation storage owner.

#[test]
fn shared_owner_selects_exact_mounted_format_and_binds_receipts() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let owner = &source[source.find("pub(crate) struct MutationPersistence").unwrap()
        ..source.find("struct Work {").unwrap()];
    assert!(source.contains("use writable_fs::registry_wal::Journal as WalJournal"));
    assert!(source.contains("Wal(WalJournal)"));
    assert!(owner.contains("prepared: &PreparedSystemHiveMutation"));
    assert!(owner.contains("writable_fs::legacy_snapshot_writes_allowed()"));
    assert!(owner.contains("WalJournal::admit(prepared, bytes)"));
    assert!(owner.contains("wal.prepare()"));
    assert!(owner.contains("wal.commit_marker(receipt)"));
    assert!(owner.contains("wal.anchor()"));
    assert!(owner.contains("wal.abort_prepared(receipt)"));
    assert!(owner.contains("wal.release_after_ack(ack)"));
    assert!(owner.contains("wal.release_after_abort(ack)"));
    assert!(owner.contains("ack.receipt()"));
}

#[test]
fn zero_durable_bytes_keep_exact_cm_commit_without_wal_effect() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let owner = &source[source.find("pub(crate) struct MutationPersistence").unwrap()
        ..source.find("struct Work {").unwrap()];
    assert!(owner.contains("prepared.storage_binding()"));
    assert!(owner.contains("if bytes.is_empty()"));
    assert!(owner.contains("PersistenceOwner::NoStorage"));
    assert!(!owner.contains("if bytes.is_empty() {\n                return Err(nt_fs::STATUS_DATA_ERROR)"));
    assert!(owner.contains("receipt.matches_storage_binding(binding)"));
    assert!(owner.contains("self.commit_receipt = Some(receipt)"));
    assert!(owner.contains("self.abort_receipt = Some(receipt)"));
}

#[test]
fn main_worker_durably_marks_and_anchors_before_local_publication_and_exact_ack() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let drive = &source[source.find("Phase::Admit => {").unwrap()..source.find("Phase::Complete => {").unwrap()];
    let admit = drive.find("work.persistence.admit(prepared, bytes)").unwrap();
    let commit = drive.find("Phase::Commit => {").unwrap();
    let durable_commit = drive.find("Phase::CommitDurable => {").unwrap();
    let marker = drive.find("work.persistence.commit_durable(receipt)").unwrap();
    let open = drive.find("Phase::Open => {").unwrap();
    let ack = drive.find("Phase::Acknowledge => {").unwrap();
    let release = drive.find("Phase::ReleasePublication(ack) => {").unwrap();
    assert!(admit < commit && commit < durable_commit && durable_commit < marker
        && marker < open && open < ack && ack < release);
    assert!(drive.contains("cm_mutation_transport::acknowledge(work.receipt.unwrap())"));
    assert!(drive.contains("release_after_publication(*ack)"));
    assert!(drive.contains("abort_after_receipt(*receipt)"));
    assert!(drive.contains("release_rolled_back(*ack)"));
}
