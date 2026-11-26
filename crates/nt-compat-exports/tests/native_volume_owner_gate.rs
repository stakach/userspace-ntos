const WRITABLE: &str = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
const JOURNAL: &str = include_str!("../../../components/ntos-executive/src/writable_fs/registry_journal.rs");
const CLEANUP: &str = include_str!("../../../components/ntos-executive/src/writable_fs/file_cleanup.rs");
const CHECKPOINT: &str = include_str!("../../../components/ntos-executive/src/writable_fs/native_checkpoint.rs");
const FOLD: &str = include_str!("../../../components/ntos-executive/src/writable_fs/system_wal_fold.rs");

fn function<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source.find(signature).expect("native access function");
    let end = source[start..].find("\n}").map(|offset| start + offset).unwrap_or(source.len());
    &source[start..end]
}

#[test]
fn generic_volume_owner_fences_public_and_direct_filesystem_access() {
    assert!(WRITABLE.contains("pub(crate) mod volume_owner;"));
    for signature in [
        "unsafe fn install_writable_fs(",
        "unsafe fn writable_fs()",
        "unsafe fn mounted_namespace_fs()",
        "pub(crate) unsafe fn restore_boot_system_persistence(",
        "unsafe fn checkpoint_volume_snapshot(",
        "unsafe fn with_durable_wal_fence<F>(",
        "pub(crate) unsafe fn with_clean_v2_volume_at_quiesce<F>(",
        "pub(crate) unsafe fn compact_unreferenced_blobs()",
    ] {
        assert!(function(WRITABLE, signature).contains("volume_owner::owns_volume()"),
            "{signature} must refuse a moved-out owner before touching the volume");
    }
    assert!(function(CLEANUP, "pub(crate) unsafe fn redrive_file_cleanup_work()")
        .contains("volume_owner::owns_volume()"));
    assert!(function(CHECKPOINT, "pub(super) unsafe fn checkpoint_dirty_native()")
        .contains("volume_owner::owns_volume()"));
    assert!(function(CHECKPOINT, "unsafe fn advance_recheck()")
        .contains("volume_owner::owns_volume()"));
    assert!(function(FOLD, "pub(crate) unsafe fn fold_system_wal_if_dirty()")
        .contains("volume_owner::owns_volume()"));
    for signature in ["unsafe fn fold_retained(", "unsafe fn install_retained()"] {
        assert!(function(FOLD, signature).contains("volume_owner::owns_volume()"));
    }
}

#[test]
fn legacy_journal_retains_the_exact_generic_owner_through_release() {
    assert!(JOURNAL.contains("owner: nt_fs::VolumeOwner<'static>"));
    let admission = function(JOURNAL, "pub(crate) unsafe fn admit(");
    assert!(admission.find("volume_owner::claim()").expect("claim before move")
        < admission.find("EXEC_WRITABLE_FS").expect("moved filesystem"));
    assert!(JOURNAL.contains("restore(filesystem, self.owner)"));
    let restoration = function(JOURNAL, "unsafe fn restore(");
    assert!(restoration.find("*slot = Some(filesystem)").expect("restore same instance")
        < restoration.find("owner.release()").expect("exact owner release"));
    assert!(!JOURNAL.contains("static OWNED:"));
}
