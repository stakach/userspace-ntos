//! Exercise the native CM storage admission seam without replacing its persistence policy.

use std::process::Command;

#[test]
fn native_registry_mount_requires_wal_replay_admission() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let start = source.find("unsafe fn restore_snapshot_volume(").unwrap();
    let end = source[start..]
        .find("\nunsafe fn restore_snapshot_volume_once(")
        .unwrap()
        + start;
    let restore = &source[start..end];
    assert!(
        restore.contains("restore_volume_snapshot_before_wal_replay_from_store")
            || source.contains("verified_boot_system_log("),
        "native boot must refuse an advanced WAL snapshot until its suffix is verified"
    );
    assert!(
        !restore.contains("restore_volume_snapshot_from_store("),
        "the format-blind reader could publish a snapshot without its committed WAL suffix"
    );
}

#[test]
fn native_boot_verifies_wal_suffix_before_publishing_volume_for_cm_import() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let fs_source = include_str!("../../nt-fs/src/fs.rs");
    assert!(
        fs_source.contains("read_latest_streaming_with_metadata(dev,"),
        "boot must decode the selected payload and WAL metadata under one snapshot lease"
    );
    let boot = &source[source.find("fn verified_boot_log(").unwrap()
        ..source.find("\n/// Whether the volume has been mounted").unwrap()];
    assert!(
        boot.contains("RegistryWal::recover("),
        "boot must parse the disjoint WAL before publishing persisted SYSTEM state"
    );
    assert!(boot.contains("verified_boot_system_log(&log, &wal)"));
    assert!(
        boot.contains("complete_log_sequence_span(&record.payload)"),
        "each committed WAL payload must contain complete semantic log records"
    );
    assert!(boot.contains("fs: Some(fs)"), "boot must retain the unpublished volume");

    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let prepare = &main[main.find("unsafe fn prepare_boot_system_hive_image()").unwrap()..];
    let restore = prepare.find("restore_boot_system_persistence(").unwrap();
    let import = prepare.find("compose_boot_system_hive(").unwrap();
    let wal_import = prepare.find("compose_boot_system_hive_with_wal_suffix(").unwrap();
    let publish = prepare.find("restored.publish()").unwrap();
    assert!(restore < import, "CM import must consume the verified boot log");
    assert!(wal_import < publish, "strict WAL replay must precede writable mount publication");
    assert!(import < publish, "CM semantic replay must precede writable mount publication");
}

#[test]
fn mounted_v2_volume_refuses_legacy_cm_journal_before_effects() {
    let journal = include_str!("../../../components/ntos-executive/src/writable_fs/registry_journal.rs");
    let admission = &journal[journal.find("pub(crate) unsafe fn admit(").unwrap()
        ..journal.find("\n    pub(crate) fn context(").unwrap()];
    let format_guard = admission
        .find("legacy_snapshot_writes_allowed()")
        .expect("CM v1 journal admission must guard mounted v2 format");
    let effect = admission.find("snapshot_storage::acquire()").unwrap();
    assert!(format_guard < effect, "v2 refusal must precede storage or file effects");
}

#[test]
fn generic_checkpoint_uses_exact_v2_manifest_and_retains_uncertain_reserve() {
    let writable = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let writer = &writable[writable.find("unsafe fn checkpoint_volume_snapshot(").unwrap()
        ..writable.find("\n/// Commit pending volume bytes").unwrap()];
    let checkpoint = &writable[writable.find("pub(crate) unsafe fn checkpoint_dirty_volume()").unwrap()
        ..writable.find("\n/// Reclaim immutable blob payloads").unwrap()];
    assert!(checkpoint.contains("current_wal_checkpoint_manifest"),
        "the mounted v2 writer must derive the included base and anchor from both slots under its lease");
    assert!(checkpoint.contains("let wal_manifest = if wal_format {"),
        "every v2 checkpoint must select its manifest before the dirty swap, including a concurrent dirty transition");
    assert!(writer.contains("commit_volume_snapshot_with_wal_manifest"),
        "an unrelated dirty-file checkpoint must retain v2 format and WAL floor");
    assert!(checkpoint.contains("core::mem::forget(dev)"),
        "an uncertain v2 checkpoint must keep the exact reserve unavailable");
    assert!(checkpoint.contains("WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true"),
        "an uncertain v2 checkpoint must block later writes and success replies");
}

#[test]
fn journal_bearing_cm_mutations_still_require_precommit_storage() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let start = source.find("enum SystemMutationStorage {").unwrap();
    let end = source[start..].find("\nenum Phase {").unwrap() + start;
    let seam = &source[start..end];
    syn::parse_str::<syn::File>(seam).expect("native storage seam parses");
    let harness = format!(
        "struct PreparedSystemHiveMutation {{ journal: Vec<u8> }}\n\
         impl PreparedSystemHiveMutation {{ fn durable_journal(&self) -> &[u8] {{ &self.journal }} }}\n\
         {seam}\n\
         fn main() {{\n\
             let empty = PreparedSystemHiveMutation {{ journal: Vec::new() }};\n\
             assert!(matches!(system_mutation_storage(&empty), Ok(SystemMutationStorage::NoJournal)));\n\
             let prepared = PreparedSystemHiveMutation {{ journal: vec![1, 2, 3] }};\n\
             assert!(matches!(system_mutation_storage(&prepared), Ok(SystemMutationStorage::PrecommitJournal(bytes)) if bytes == [1, 2, 3]));\n\
         }}"
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-registry-writeback-boundary-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native storage seam must compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "native storage admission contract failed");
}

#[test]
fn cm_persistence_owner_retains_refused_release_for_exact_retry() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let start = source.find("struct MutationPersistence {").unwrap();
    let end = source[start..].find("\nstruct Work {").unwrap() + start;
    let owner = &source[start..end];
    syn::parse_str::<syn::File>(owner).expect("native persistence owner parses");
    let harness = format!(r#"
        mod writable_fs {{ pub mod registry_journal {{
            pub struct Journal<C> {{ pub context: C, pub phase: u8, pub refuse_release: bool }}
            impl Journal<()> {{
                pub unsafe fn admit(_: Vec<u8>, context: ()) -> Result<Self, (u32, Vec<u8>, ())> {{
                    Ok(Self {{ context, phase: 0, refuse_release: true }})
                }}
                pub fn make_durable(&mut self) -> Result<(), u32> {{
                    assert_eq!(self.phase, 0); self.phase = 1; Ok(())
                }}
                pub fn begin_publication(&mut self) -> Result<&mut (), u32> {{
                    assert_eq!(self.phase, 1); self.phase = 2; Ok(&mut self.context)
                }}
                pub fn rollback(&mut self) -> Result<(), u32> {{
                    assert_eq!(self.phase, 1); self.phase = 3; Ok(())
                }}
                pub unsafe fn release_after_publication(mut self) -> Result<(), Self> {{
                    assert_eq!(self.phase, 2);
                    if self.refuse_release {{ self.refuse_release = false; Err(self) }} else {{ Ok(()) }}
                }}
                pub unsafe fn release_rolled_back(mut self) -> Result<(), Self> {{
                    assert_eq!(self.phase, 3);
                    if self.refuse_release {{ self.refuse_release = false; Err(self) }} else {{ Ok(()) }}
                }}
            }}
        }} }}
        {owner}
        fn main() {{ unsafe {{
            let mut committed = MutationPersistence::new();
            committed.admit(vec![1]).unwrap();
            committed.make_durable().unwrap();
            committed.begin_publication().unwrap();
            assert_eq!(committed.release_after_publication(), Err(0xC000_000D));
            assert!(committed.has_journal());
            committed.release_after_publication().unwrap();
            assert!(!committed.has_journal());

            let mut aborted = MutationPersistence::new();
            aborted.admit(vec![2]).unwrap();
            aborted.make_durable().unwrap();
            aborted.rollback().unwrap();
            assert_eq!(aborted.release_rolled_back(), Err(0xC000_000D));
            assert!(aborted.has_journal());
            aborted.release_rolled_back().unwrap();
            assert!(!aborted.has_journal());
        }} }}
    "#);
    let directory = std::env::temp_dir().join(format!(
        "nt-registry-persistence-owner-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native persistence owner must compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "persistence owner lost a refused release");
}
