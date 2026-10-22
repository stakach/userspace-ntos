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
    assert!(barrier.contains("snapshot_storage::peek_wal_continuation(&mut lease)"));
    let storage = include_str!("../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs");
    let peek = &storage[storage.find("pub(super) fn peek_wal_continuation(").unwrap()
        ..storage.find("\nfn manifest_anchor(").unwrap()];
    assert!(peek.contains("recheck_verified_paired_wal_snapshot(lease, &cached.pair)"));
    assert!(!barrier.contains("RegistryWal::recover"),
        "a live flush must use the mount-bound verified continuation");
    assert!(barrier.contains("WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true"));
    assert!(!barrier.contains("write_primary_image_atomic_owned"));
}

#[test]
fn mounted_v2_volume_checkpoint_captures_one_image_before_disk_effects() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let start = source.find("pub(crate) unsafe fn checkpoint_dirty_volume()")
        .expect("mounted checkpoint entrypoint");
    let end = source[start..].find("\n/// ").map(|offset| start + offset).unwrap_or(source.len());
    let checkpoint = &source[start..end];
    assert!(checkpoint.contains("snapshot_capture::CapturedSnapshot::capture(&dev, fs)"),
        "v2 checkpoint must capture one immutable image before any physical write");
    assert!(checkpoint.find("snapshot_capture::CapturedSnapshot::capture(&dev, fs)").unwrap()
        < checkpoint.find("checkpoint_volume_snapshot(").unwrap());
    assert!(checkpoint.contains("WRITABLE_FS_SNAPSHOT_DIRTY.store(true"),
        "failed pre-effect capture must preserve the dirty owner");
    assert!(checkpoint.find("WRITABLE_FS_SNAPSHOT_DIRTY.swap(false").unwrap()
        < checkpoint.find("snapshot_storage::take_wal_continuation(&mut dev)").unwrap(),
        "a clean checkpoint poll must not acquire WAL proof or read snapshot headers");
    let start = source.find("unsafe fn checkpoint_volume_snapshot(")
        .expect("checkpoint writer");
    let end = source[start..].find("\n/// ").map(|offset| start + offset).unwrap_or(source.len());
    let writer = &source[start..end];
    assert!(writer.contains("nt_fs::AsyncSnapshotCommit::new(")
        && writer.contains("store, image, manifest, dev.sector_size(), dev.sector_count()")
        && writer.contains("commit.run_sync(dev)"),
        "v2 checkpoint must prepare the captured bytes and exact WAL manifest before disk I/O");
    assert!(!writer.contains("commit_volume_snapshot_with_wal_manifest"),
        "v2 checkpoint must not rerun mutable volume serialization during disk I/O");
}
