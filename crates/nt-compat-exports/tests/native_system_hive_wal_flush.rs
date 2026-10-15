#[test]
fn explicit_system_flush_checks_the_durable_v2_wal_without_rewriting_primary() {
    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = handler
        .find("fn checkpoint_system_hive_from_config_manager(")
        .expect("SYSTEM flush entrypoint");
    let end = handler[start..]
        .find("\n    fn checkpoint_non_system_boot_mutable_hive(")
        .expect("SYSTEM flush boundary")
        + start;
    let flush = &handler[start..end];
    let v2 = flush
        .find("if !crate::writable_fs::legacy_snapshot_writes_allowed()")
        .expect("v2 SYSTEM flush must be selected before CM checkpoint preparation");
    let prepare = flush
        .find("config_manager_prepare_system_hive_checkpoint()")
        .expect("legacy CM image checkpoint");
    assert!(v2 < prepare);
    assert!(flush[v2..prepare].contains("verify_durable_system_wal()"),
        "v2 NtFlushKey must prove the exact mounted WAL prefix before returning success");

    let fs = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let start = fs
        .find("pub(crate) unsafe fn verify_durable_system_wal()")
        .expect("mounted v2 WAL flush barrier");
    let end = fs[start..]
        .find("\n/// ")
        .map(|offset| start + offset)
        .unwrap_or(fs.len());
    let barrier = &fs[start..end];
    assert!(barrier.contains("snapshot_storage::acquire()"));
    assert!(barrier.contains("current_wal_checkpoint_manifest"));
    assert!(barrier.contains("validate_wal_journal_manifest"));
    assert!(barrier.contains("RegistryWal::recover"));
    assert!(barrier.contains("settled_anchor()"));
    assert!(!barrier.contains("write_primary_image_atomic_owned"));
}
