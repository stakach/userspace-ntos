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
