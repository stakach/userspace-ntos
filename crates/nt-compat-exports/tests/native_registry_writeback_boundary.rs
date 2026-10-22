//! Exercise the native CM storage admission seam without replacing its persistence policy.

use std::process::Command;

fn source_block<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source.find(marker).unwrap_or_else(|| panic!("missing source block: {marker}"));
    let open = source[start..].find('{').expect("source block body") + start;
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated source block: {marker}");
}

#[test]
fn completed_relation_publications_reuse_one_cm_begin_requester() {
    let admission = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let relation = include_str!("../../../components/ntos-executive/src/hosted_relation_publication.rs");
    let admission = source_block(admission, "unsafe fn publish_hosted_bus_relations(");
    assert!(admission.contains("reserve_relation_mutation_begin("));
    assert!(!admission.contains("CmMutationBeginAttempts::new()"));
    assert!(relation.contains("static mut RELATION_BEGIN_ATTEMPTS: CmMutationBeginAttempts"));
    assert!(!relation.contains("attempts: CmMutationBeginAttempts,"));
}

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
    assert!(boot.contains("wal.verified_prefix()")
        && boot.contains("wal.verified_record_end_lba(anchor.serial)"),
        "boot must bind the selected snapshot anchor to the recovered physical WAL prefix");
    assert!(
        boot.contains("decode_volume_wal_payload(&record.payload)")
            && boot.contains("complete_log_sequence_span(bytes)")
            && boot.contains("complete_log_sequence_span_from(bytes, previous)")
            && boot.contains("hive_wal::validate_first_record(")
            && boot.contains("payload.expected_log_len, payload.record")
            && boot.contains("fs.replay_hive_log_wal_payload(payload)"),
        "boot must route mixed records and verify complete contiguous hive journals before publication"
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
fn retained_wal_files_and_checkpoint_images_escape_transient_request_scope() {
    let fold = include_str!("../../../components/ntos-executive/src/writable_fs/system_wal_fold.rs");
    let commit = include_str!("../../../components/ntos-executive/src/writable_fs/hive_wal_native.rs");
    let fold_entry = source_block(fold, "pub(crate) unsafe fn fold_system_wal_if_dirty(");
    let commit_entry = source_block(commit, "pub(crate) unsafe fn begin_native_hive_journal(");
    assert!(fold_entry.find("allocator::enter_durable()").expect("durable fold admission")
        < fold_entry.find("config_manager_prepare_system_hive_checkpoint()")
            .expect("CM checkpoint transfer"),
        "CM image transferred into the mounted filesystem must outlive the transient timer scope");
    assert!(commit_entry.find("allocator::enter_durable()").expect("durable log admission")
        < commit_entry.find("inspect_baseline(&path, &record)").expect("log baseline"),
        "retained log catalog and WAL replay bytes must be allocated durably");
}

#[test]
fn folded_hive_log_cache_requires_a_new_baseline_before_reuse() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs/hive_wal_native.rs");
    let cache = include_str!("../../../components/ntos-executive/src/writable_fs/hive_wal.rs");
    let fold = source_block(cache, "pub(super) unsafe fn note_volume_wal_folded(");
    let baseline = source_block(source, "unsafe fn inspect_baseline(");
    let finish = source_block(source, "unsafe fn finish_baseline(");
    assert!(fold.contains("baseline.has_wal_records = false"));
    assert!(baseline.contains(
        "entry.has_wal_records && entry.file_id == file_id && entry.expected_len == length"
    ), "a fold releases write protection, so file ID and length cannot authenticate cached bytes");
    assert!(baseline.contains("mark_snapshot_dirty()")
        && source.contains("native_checkpoint::checkpoint_dirty_native()")
        && finish.contains("validate_first_record(fs, &journal.path"),
        "the first append after a fold must checkpoint and verify a fresh durable baseline");
}

#[test]
fn native_system_fold_keeps_prepared_hive_private_until_ack() {
    let native = include_str!("../../../components/ntos-executive/src/writable_fs/system_wal_fold/native.rs");
    let fold = include_str!("../../../components/ntos-executive/src/writable_fs/system_wal_fold.rs");
    let stage = source_block(native, "unsafe fn advance_recheck()");
    assert!(stage.contains("FileSystem::from_volume_snapshot(baseline.as_slice())")
        && stage.contains("stage_prepared_checkpoint(&mut staged, &prepared)")
        && stage.contains("CapturedSnapshot::capture(&lease, &staged)"));
    assert!(!stage.contains("apply_prepared_checkpoint(fs,"));
    let ack = source_block(fold, "unsafe fn acknowledge_retained()");
    let install = source_block(fold, "unsafe fn install_retained()");
    assert!(ack.find("config_manager_acknowledge_system_hive_checkpoint(prepared)")
        < ack.find("install_retained()"));
    assert!(install.find("apply_prepared_checkpoint(fs, &mut work.prepared)")
        < install.find("snapshot_storage::install_wal_continuation(&work.lease"));
}

#[test]
fn rollback_keeps_admitting_system_wal_owner_until_header_recheck_is_settled() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let start = source.find("pub(crate) unsafe fn release_rolled_back(").unwrap();
    let release = &source[start..source[start..].find("\n}\n\nstruct Work {").unwrap() + start];
    assert!(!release.contains("PersistenceOwner::Admitting { .. } => {}"),
        "rollback ACK must not discard retained CM bytes while header recheck owns the reserve");
    assert!(release.contains("snapshot_storage::take_rechecked_wal_continuation"),
        "rollback must distinguish completed/no-effect recheck from entered uncertainty");
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
    assert!(checkpoint.contains("snapshot_storage::take_wal_continuation(&mut dev)"),
        "the mounted v2 writer must move the exact WAL and paired snapshot proof under its lease");
    assert!(checkpoint.contains("let (wal_manifest, authority) = if wal_format {"),
        "every dirty v2 checkpoint must select its manifest and authority under the reserve lease");
    assert!(checkpoint.contains("verify_paired_wal_snapshot(&mut dev)"),
        "a settled checkpoint must refresh its payload proof before later writers can enter");
    assert!(writer.contains("commit_next_with_wal_manifest")
        && checkpoint.contains("snapshot_capture::CapturedSnapshot::capture(&dev, fs)")
        && checkpoint.contains("captured_image.as_ref().map(snapshot_capture::CapturedSnapshot::as_slice)"),
        "an unrelated dirty-file checkpoint must freeze its image and retain the v2 WAL floor");
    assert!(checkpoint.contains("core::mem::forget(dev)"),
        "an uncertain v2 checkpoint must keep the exact reserve unavailable");
    assert!(checkpoint.contains("WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true"),
        "an uncertain v2 checkpoint must block later writes and success replies");
}

#[test]
fn writable_hive_provider_refuses_every_v2_legacy_log_append_before_file_effect() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let guard = &source[source.find("fn require_legacy_file_mutation(").unwrap()
        ..source.find("\n    pub(crate) fn truncate_log_to(").unwrap()];
    assert!(guard.contains("legacy_snapshot_writes_allowed()"),
        "the file mutation gate must refuse every v2 legacy log append");
    assert!(guard.contains("ensure_mounted()"),
        "a lazy restored v2 volume must be classified before its legacy provider writes");
    let provider = &source[source.find("impl nt_hive_core::HiveIoProvider for WritableHiveIoProvider {").unwrap()
        ..source.find("\n/// `NtFlushBuffersFile` on a writable-volume file object.").unwrap()];
    let append = &provider[provider.find("fn append_log_record(").unwrap()
        ..provider.find("\n    fn truncate_log(").unwrap()];
    let guard = append.find("require_legacy_file_mutation()")
        .expect("the ordinary provider must refuse mounted v2 before any append");
    let effect = append.find("append_file(").expect("legacy provider append effect");
    assert!(guard < effect, "v2 refusal must precede the file append");
}

#[test]
fn retired_one_shot_system_mutation_path_cannot_bypass_retained_owner() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    assert!(!main.contains("fn persist_and_publish_system_hive_mutation("));
    assert!(!main.contains("fn config_manager_publish_system_hive_mutation("));

    let worker = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let owner = &worker[worker.find("pub(crate) struct MutationPersistence").unwrap()
        ..worker.find("struct Work {").unwrap()];
    assert!(owner.contains("ensure_mounted()") && owner.contains("legacy_snapshot_writes_allowed()"),
        "retained CM work must classify a lazy restored volume before storage effects");
    assert!(owner.contains("WalJournal::admit(prepared, bytes)"),
        "v2 admission uses the exact CM preparation instead of legacy journal storage");
    let admit = &worker[worker.find("Phase::Admit => {").unwrap()..worker.find("Phase::Durable => {").unwrap()];
    assert!(admit.contains("work.persistence.admit(prepared, bytes)"));
    assert!(admit.contains("work.phase = Phase::Abort"),
        "a refused v2 v1-storage admission must abort the still-prepared CM mutation");
}

#[test]
fn journal_bearing_cm_mutations_still_require_precommit_storage() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let start = source.find("fn system_mutation_storage(").unwrap();
    let end = source[start..].find("\nenum Phase {").unwrap() + start;
    let seam = &source[start..end];
    syn::parse_str::<syn::File>(seam).expect("native storage seam parses");
    let harness = format!(
        "struct PreparedSystemHiveMutation {{ journal: Vec<u8> }}\n\
         impl PreparedSystemHiveMutation {{ fn durable_journal(&self) -> &[u8] {{ &self.journal }} }}\n\
         {seam}\n\
         fn main() {{\n\
             let empty = PreparedSystemHiveMutation {{ journal: Vec::new() }};\n\
             assert!(matches!(system_mutation_storage(&empty), Ok(bytes) if bytes.is_empty()));\n\
             let prepared = PreparedSystemHiveMutation {{ journal: vec![1, 2, 3] }};\n\
             assert!(matches!(system_mutation_storage(&prepared), Ok(bytes) if bytes == [1, 2, 3]));\n\
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
    let start = source.find("enum PersistenceOwner {").unwrap();
    let end = source[start..].find("\nstruct Work {").unwrap() + start;
    let owner = &source[start..end];
    syn::parse_str::<syn::File>(owner).expect("native persistence owner parses");
    let harness = String::from(r#"
        use std::vec::Vec;
        #[derive(Clone, Copy, PartialEq, Eq)] struct SystemHiveMutationStorageBinding(u8);
        struct PreparedSystemHiveMutation(SystemHiveMutationStorageBinding);
        impl PreparedSystemHiveMutation {
            fn storage_binding(&self) -> SystemHiveMutationStorageBinding { self.0 }
        }
        #[derive(Clone, Copy, PartialEq, Eq)] struct SystemHiveMutationCommitReceipt(u8);
        impl SystemHiveMutationCommitReceipt {
            fn matches_storage_binding(self, binding: SystemHiveMutationStorageBinding) -> bool { self.0 == binding.0 }
        }
        #[derive(Clone, Copy, PartialEq, Eq)] struct SystemHiveMutationAbortReceipt(u8);
        impl SystemHiveMutationAbortReceipt {
            fn matches_storage_binding(self, binding: SystemHiveMutationStorageBinding) -> bool { self.0 == binding.0 }
        }
        #[derive(Clone, Copy)] struct SystemHiveMutationAcknowledgement(SystemHiveMutationCommitReceipt);
        impl SystemHiveMutationAcknowledgement {
            fn receipt(self) -> SystemHiveMutationCommitReceipt { self.0 }
        }
        #[derive(Clone, Copy)] struct SystemHiveMutationAbortAcknowledgement(SystemHiveMutationAbortReceipt);
        impl SystemHiveMutationAbortAcknowledgement {
            fn receipt(self) -> SystemHiveMutationAbortReceipt { self.0 }
        }
        mod nt_fs {
            pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
            pub const STATUS_DATA_ERROR: u32 = 0xC000_003E;
            pub const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;
            pub struct AsyncWalIoRequest;
            pub enum BlockOperation { Flush }
            pub enum BlockSourceKind { Draining, Native }
        }
        mod nt_memory_manager { pub struct SectionMountId; }
        mod nt_status {
            pub struct NtStatus(pub u32);
            impl NtStatus {
                pub const DEVICE_BUSY: Self = Self(0x8000_0011);
                pub fn raw(self) -> u32 { self.0 }
            }
        }
        mod fs_loader {
            pub fn exec_fs_mount_identity() -> Option<crate::nt_memory_manager::SectionMountId> { None }
            pub fn exec_block_route_kind(_: crate::nt_memory_manager::SectionMountId)
                -> Option<crate::nt_fs::BlockSourceKind> { None }
        }
        mod writable_fs {
            use super::*;
            pub fn ensure_mounted() -> Result<(), u32> { Ok(()) }
            pub fn block_uncertain_snapshot_reserve() {}
            pub static LEGACY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
            pub fn legacy_snapshot_writes_allowed() -> bool {
                LEGACY.load(std::sync::atomic::Ordering::Relaxed)
            }
            pub mod snapshot_storage {
                use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
                pub static OUTCOME: AtomicU8 = AtomicU8::new(0);
                pub static INSTALLS: AtomicUsize = AtomicUsize::new(0);
                pub struct Lease;
                pub struct Token;
                pub struct Pair;
                pub struct Proof;
                impl Proof { pub fn into_pair(self) -> Pair { Pair } }
                pub fn take_rechecked_wal_continuation(_: u64)
                    -> Result<Option<(Lease, Token, Proof)>, u32> {
                    match OUTCOME.load(Ordering::Relaxed) {
                        0 => Ok(None),
                        1 => Ok(Some((Lease, Token, Proof))),
                        2 => Err(0xC000_00A3),
                        _ => Err(0xC000_003E),
                    }
                }
                pub fn recheck_was_aborted_no_effect(_: u64) -> bool {
                    OUTCOME.load(Ordering::Relaxed) == 2
                }
                pub fn install_wal_continuation(_: &Lease, token: Token, pair: Pair)
                    -> Result<(), (u32, Token, Pair)> {
                    INSTALLS.fetch_add(1, Ordering::Relaxed);
                    let _ = (token, pair);
                    Ok(())
                }
                pub fn begin_wal_continuation_recheck() -> Result<u64, u32> { Ok(1) }
            }
            pub mod native_snapshot_io {
                pub fn admission_busy(_: u32) -> bool { false }
            }
            pub mod registry_journal {
                use super::*;
                pub struct Journal<C> { pub context: C, pub phase: u8, pub refuse_release: bool }
                impl Journal<()> {
                    pub unsafe fn admit(_: Vec<u8>, context: ()) -> Result<Self, (u32, Vec<u8>, ())> {
                        Ok(Self { context, phase: 0, refuse_release: true })
                    }
                    pub fn make_durable(&mut self) -> Result<(), u32> {
                        assert_eq!(self.phase, 0); self.phase = 1; Ok(())
                    }
                    pub fn begin_publication(&mut self) -> Result<&mut (), u32> {
                        assert_eq!(self.phase, 1); self.phase = 2; Ok(&mut self.context)
                    }
                    pub fn rollback(&mut self) -> Result<(), u32> {
                        assert_eq!(self.phase, 1); self.phase = 3; Ok(())
                    }
                    pub unsafe fn release_after_publication(mut self) -> Result<(), Self> {
                        assert_eq!(self.phase, 2);
                        if self.refuse_release { self.refuse_release = false; Err(self) } else { Ok(()) }
                    }
                    pub unsafe fn release_rolled_back(mut self) -> Result<(), Self> {
                        assert_eq!(self.phase, 3);
                        if self.refuse_release { self.refuse_release = false; Err(self) } else { Ok(()) }
                    }
                }
            }
            pub mod registry_wal {
                use super::*;
                pub struct Journal;
                impl Journal {
                    pub unsafe fn admit(_: &PreparedSystemHiveMutation, _: Vec<u8>) -> Result<Self, u32> { Ok(Self) }
                    pub fn admit_rechecked(_: &PreparedSystemHiveMutation, _: Vec<u8>,
                        _: crate::writable_fs::snapshot_storage::Lease,
                        _: crate::writable_fs::snapshot_storage::Token,
                        _: crate::writable_fs::snapshot_storage::Proof) -> Result<Self, u32> { Ok(Self) }
                    pub fn mount(&self) -> crate::nt_memory_manager::SectionMountId {
                        crate::nt_memory_manager::SectionMountId
                    }
                    pub fn claim_native_io(&mut self)
                        -> Result<Option<(crate::nt_fs::AsyncWalIoRequest,
                            crate::nt_fs::BlockOperation, Vec<u8>)>, u32> { Ok(None) }
                    pub fn prepare(&mut self) -> Result<(), u32> { Ok(()) }
                    pub fn commit_marker(&mut self, _: SystemHiveMutationCommitReceipt) -> Result<(), u32> { Ok(()) }
                    pub fn anchor(&mut self) -> Result<(), u32> { Ok(()) }
                    pub fn abort_prepared(&mut self, _: SystemHiveMutationAbortReceipt) -> Result<(), u32> { Ok(()) }
                    pub fn release_after_ack(self, _: SystemHiveMutationAcknowledgement) -> Result<(), Self> { Ok(()) }
                    pub fn release_after_abort(self, _: SystemHiveMutationAbortAcknowledgement) -> Result<(), Self> { Ok(()) }
                }
            }
        }
        use writable_fs::registry_wal::Journal as WalJournal;
    "#) + owner + r#"
        fn main() { unsafe {
            let prepared = PreparedSystemHiveMutation(SystemHiveMutationStorageBinding(7));
            let receipt = SystemHiveMutationCommitReceipt(7);
            let ack = SystemHiveMutationAcknowledgement(receipt);
            let mut committed = MutationPersistence::new();
            committed.admit(&prepared, vec![1]).unwrap();
            committed.make_durable().unwrap();
            committed.begin_publication().unwrap();
            committed.commit_durable(receipt).unwrap();
            assert_eq!(committed.release_after_publication(ack), Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST));
            assert!(committed.has_journal());
            committed.release_after_publication(ack).unwrap();
            assert!(!committed.has_journal());

            let receipt = SystemHiveMutationAbortReceipt(8);
            let ack = SystemHiveMutationAbortAcknowledgement(receipt);
            let prepared = PreparedSystemHiveMutation(SystemHiveMutationStorageBinding(8));
            let mut aborted = MutationPersistence::new();
            aborted.admit(&prepared, vec![2]).unwrap();
            aborted.make_durable().unwrap();
            aborted.rollback().unwrap();
            aborted.abort_after_receipt(receipt).unwrap();
            assert_eq!(aborted.release_rolled_back(ack), Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST));
            assert!(aborted.has_journal());
            aborted.release_rolled_back(ack).unwrap();
            assert!(!aborted.has_journal());

            use std::sync::atomic::Ordering;
            use writable_fs::snapshot_storage::{OUTCOME, INSTALLS};
            let mut pending = MutationPersistence::new();
            pending.owner = PersistenceOwner::Admitting { recheck_id: 41, bytes: vec![4] };
            pending.abort_receipt = Some(receipt);
            OUTCOME.store(0, Ordering::Relaxed);
            assert_eq!(pending.release_rolled_back(ack), Err(nt_fs::STATUS_DEVICE_NOT_READY));
            assert!(pending.admitting());
            OUTCOME.store(1, Ordering::Relaxed);
            pending.release_rolled_back(ack).unwrap();
            assert!(!pending.admitting());
            assert_eq!(INSTALLS.load(Ordering::Relaxed), 1);

            let mut no_effect = MutationPersistence::new();
            no_effect.owner = PersistenceOwner::Admitting { recheck_id: 42, bytes: vec![5] };
            no_effect.abort_receipt = Some(receipt);
            OUTCOME.store(2, Ordering::Relaxed);
            no_effect.release_rolled_back(ack).unwrap();
            assert!(!no_effect.admitting());

            let mut uncertain = MutationPersistence::new();
            uncertain.owner = PersistenceOwner::Admitting { recheck_id: 43, bytes: vec![6] };
            uncertain.abort_receipt = Some(receipt);
            OUTCOME.store(3, Ordering::Relaxed);
            assert_eq!(uncertain.release_rolled_back(ack), Err(nt_fs::STATUS_DATA_ERROR));
            assert!(uncertain.admitting());

            writable_fs::LEGACY.store(false, std::sync::atomic::Ordering::Relaxed);
            let prepared = PreparedSystemHiveMutation(SystemHiveMutationStorageBinding(9));
            let receipt = SystemHiveMutationCommitReceipt(9);
            let ack = SystemHiveMutationAcknowledgement(receipt);
            let mut volatile = MutationPersistence::new();
            volatile.admit(&prepared, Vec::new()).unwrap();
            assert!(!volatile.has_journal());
            volatile.commit_durable(receipt).unwrap();
            volatile.release_after_publication(ack).unwrap();
        } }
    "#;
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

#[test]
fn hosted_relation_query_owns_publication_before_cm_transport() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let query = source_block(driver, "struct HostedDeviceRelationQuery {");
    assert!(query.contains("publication: Option<HostedRelationPublication>"),
        "the already-retained relation query must own PnP preparation and CM progress");
    let start = source_block(driver, "unsafe fn start_hosted_device_relation_query() -> usize {");
    assert!(start.contains("publication: None"), "a new query starts without a publication owner");

    let publish = source_block(driver, "unsafe fn publish_hosted_bus_relations() -> Result<(), HostedRelationPublishError> {");
    assert!(publish.contains("query.publication.as_mut()"),
        "a retry must redrive the installed publication instead of preparing another provider batch");
    let install = publish.find("query.publication = Some(")
        .expect("install the exact PnP and CM owner in the query before transport");
    let before_install = &publish[..install];
    assert!(!before_install.contains("cm_mutation_transport::begin(")
        && !before_install.contains("cm_mutation_transport::prepare(")
        && !before_install.contains("cm_mutation_transport::commit(")
        && !before_install.contains("advance_hosted_relation_publication("),
        "first CM transport/advance must follow installation of the relation owner");
    assert!(publish[install..].contains("advance_hosted_relation_publication("),
        "the installed publication must be advanced by the relation pump");
}

#[test]
fn hosted_relation_uncertain_cm_keeps_provider_batch_and_invalidation_claim() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let publish = source_block(driver, "unsafe fn publish_hosted_bus_relations() -> Result<(), HostedRelationPublishError> {");
    assert!(!publish.contains("crate::persist_and_publish_system_hive_mutation("),
        "the one-shot CM path cannot distinguish an uncertain reply from a confirmed refusal");
    let pending = source_block(publish, "HostedRelationPublicationProgress::Pending => {");
    assert!(pending.contains("Err(HostedRelationPublishError::Retry)"),
        "uncertain CM progress must return Retry for the same query owner");
    for forbidden in ["publication.take()", "provider_batch.abort(", "complete_terminal(",
        "set_hosted_relation_query_disposition("] {
        assert!(!pending.contains(forbidden), "pending CM arm may not release {forbidden}");
    }
    let pump = source_block(driver, "unsafe fn drain_hosted_device_relation_query() -> usize {");
    assert!(pump.contains("Err(HostedRelationPublishError::Retry) => return progress"),
        "pending CM progress must retain the relation query and invalidation claim");
}

#[test]
fn hosted_relation_definite_preparation_refusal_cancels_exact_token() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let owner = source_block(&helper, "struct HostedRelationPublication {");
    assert!(owner.contains("SystemHiveMutationPreparation"),
        "the preparation token must remain owned through cancellation");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let prepare = source_block(advance, "Phase::Prepare => {");
    assert!(prepare.contains("CmMutationPreparationPhase::Cancelled")
        || (prepare.contains("CmMutationPreparationPhase as P")
            && prepare.contains("P::Cancelled")));
    for required in ["take_cancelled()",
        "CmMutationPreparationOperation::Cancel",
        "CmMutationPreparationOperation::AcknowledgeCancellation"] {
        assert!(prepare.contains(required),
            "a definite preparation refusal must retain and cancel the exact CM token: {required}");
    }
    assert!(prepare.contains("Phase::AbortProvider"),
        "only an acknowledged cancellation may release the provider batch");
}

#[test]
fn hosted_relation_local_publication_precedes_exact_cm_ack() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let owner = source_block(&helper, "struct HostedRelationPublication {");
    for field in ["PreparedBusRelations", "PreparedEnumeratedPdoBatch",
        "PreparedAcceptedPdoProviderBatch", "CmMutationBeginAttempt",
        "SystemHiveMutationPreparation", "SystemHiveMutationCommitReceipt"] {
        assert!(owner.contains(field), "retained relation publication is missing {field}");
    }
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let local = source_block(&helper, "unsafe fn finish_hosted_relation_local_publication(");
    let cm_commit = advance.find("cm_mutation_transport::commit(")
        .expect("CM COMMIT needs an exact retained receipt");
    let publication = advance.find("commit_prospective_relation_with_lease(")
        .expect("prevalidate and publish the retained devnode, bus, and provider owners together");
    let finish = advance.find("finish_hosted_relation_local_publication(owner)")
        .expect("finish local publication in the same PnP step");
    let catalog = local.find("try_commit_hosted_acpi_pci_relation_sources(")
        .expect("publish the retained ACPI catalog after preflight");
    let claim = local.find(".complete_terminal(")
        .expect("complete the exact invalidation claim from the owner");
    let ack = advance.find("cm_mutation_transport::acknowledge(")
        .expect("acknowledge the exact retained CM COMMIT receipt");
    assert!(cm_commit < publication && publication < finish && finish < ack
        && catalog < claim,
        "the exact CM receipt must remain owned until local PnP publication finishes before ACK");
    assert!(advance.contains("PostCommitRepair"),
        "fallible PnP publication after CM COMMIT requires a retained repair phase");
    assert!(advance.contains("Phase::Reprepare")
        && advance.contains("batch.abort(io_manager_mut())")
        && advance.contains("prepare_bus_relations(")
        && advance.contains("prepare_relation("),
        "drift after CM COMMIT must release the old exact provider lease and reprepare all owners");
}

#[test]
fn hosted_relation_preflights_terminal_owners_before_pnp_effects() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let repair = source_block(&helper, "Phase::PostCommitRepair => {");
    let pnp_effect = repair.find("commit_prospective_relation_with_lease(")
        .expect("combined PnP publication must remain retained");
    for admission in ["validate_prospective_reservations(",
        "preview_complete_terminal(", "validate_hosted_pci_relation_completion("] {
        let index = repair.find(admission)
            .unwrap_or_else(|| panic!("missing pre-effect terminal admission: {admission}"));
        assert!(index < pnp_effect,
            "{admission} must refuse before any PnP/provider publication");
    }
    assert!(repair.contains("Phase::Reprepare"),
        "a pre-effect terminal refusal must retain the CM receipt for forward repair");
}

#[test]
fn hosted_relation_retains_same_bus_exclusion_through_cm_ack() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let owner = source_block(&helper, "struct HostedRelationPublication {");
    assert!(owner.contains("BusRelationPublicationLease"),
        "the relation owner must retain exact same-bus exclusion through uncertain CM effects");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    assert!(advance.contains("commit_prospective_relation_with_lease("),
        "only the retained relation owner may publish while the bus is excluded");
    let ack = advance.find("cm_mutation_transport::acknowledge(").unwrap();
    let release = advance.find("release_publication_lease(")
        .expect("the bus lease must be released after exact CM ACK");
    assert!(ack < release);
}

#[test]
fn hosted_relation_never_reenters_pnp_commit_after_local_publication() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let precommit = source_block(advance, "Phase::PostCommitRepair => {");
    let terminal = source_block(advance, "Phase::FinishLocalPublication => {");
    assert!(precommit.contains("commit_prospective_relation_with_lease(")
        && precommit.contains("owner.phase = Phase::FinishLocalPublication"),
        "successful PnP/provider commit must enter a forward-only terminal phase");
    assert!(!terminal.contains("commit_prospective_relation_with_lease(")
        && !terminal.contains("Phase::Reprepare"),
        "catalog or terminal refusal after PnP publication must retain exact state without replay");
}

#[test]
fn hosted_relation_budget_edge_finishes_catalog_before_yield() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let post = source_block(advance, "Phase::PostCommitRepair => {");
    let success = source_block(post, "Ok(()) => {");
    assert!(success.contains("finish_hosted_relation_local_publication(owner)"),
        "the same pump step that publishes PnP must finish catalog and terminal owners");
    assert!(!success.contains("continue;"),
        "a 16-step budget edge must not yield after PnP before catalog publication");
}

#[test]
fn hosted_relation_v2_wal_barriers_precede_local_publication_and_ack() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let durable = advance.find("owner.persistence.make_durable(").unwrap();
    let cm_commit = advance.find("cm_mutation_transport::commit(").unwrap();
    let durable_commit = advance.find("owner.persistence.commit_durable(")
        .expect("exact CM receipt must authorize marker and paired-header barriers");
    let local = advance.find("commit_prospective_relation_with_lease(").unwrap();
    let ack = advance.find("cm_mutation_transport::acknowledge(").unwrap();
    let storage_release = advance.find("owner.persistence.release_after_publication(")
        .expect("exact CM acknowledgement must release the retained WAL reserve");
    let bus_release = advance.find("release_publication_lease(").unwrap();
    assert!(durable < cm_commit && cm_commit < durable_commit
        && durable_commit < local && local < ack && ack < storage_release
        && storage_release < bus_release,
        "PREPARE→WAL barrier→CM COMMIT→marker→two anchors→PnP→ACK→release ordering");
    assert!(advance.contains("Phase::DurableCommit"),
        "uncertain marker or anchor must retain the exact publication owner for redrive");
}

#[test]
fn hosted_relation_v2_abort_keeps_wal_owner_through_acknowledged_cancel() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let abort = advance.find("cm_mutation_transport::abort(").unwrap();
    let wal_abort = advance.find("owner.persistence.abort_after_receipt(")
        .expect("exact CM abort receipt must authorize WAL prepare rollback");
    let ack_abort = advance.find("cm_mutation_transport::acknowledge_abort(").unwrap();
    let release = advance.find("owner.persistence.release_rolled_back(")
        .expect("confirmed CM abort acknowledgement must release the WAL reserve");
    let providers = advance.rfind("batch.abort(io_manager_mut())").unwrap();
    let bus = advance.rfind("release_publication_lease(").unwrap();
    assert!(abort < wal_abort && wal_abort < ack_abort && ack_abort < release
        && release < providers && providers < bus,
        "abort receipt, WAL rollback, ACK_ABORT, provider cleanup and bus release must be retained");
}

#[test]
fn hosted_relation_publishes_generation_only_after_wal_anchor() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let barrier = advance.find("owner.persistence.commit_durable(").unwrap();
    let generation = advance.find("LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.fetch_max(").unwrap();
    let wake = advance.find("config_manager_request_device_action_wake()").unwrap();
    let local = advance.find("commit_prospective_relation_with_lease(").unwrap();
    assert!(barrier < generation && barrier < wake && generation < local && wake < local,
        "CM generation and device wake must follow the marker and both WAL anchors");
}

#[test]
fn hosted_relation_zero_durable_journal_keeps_semantic_cm_commit() {
    let helper = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/hosted_relation_publication.rs"
    )).expect("retained relation publication helper must exist");
    let advance = source_block(&helper, "unsafe fn advance_hosted_relation_publication(");
    let admit = source_block(advance, "Phase::Admit => {");
    assert!(admit.contains("validate_storage(prepared)")
        && admit.contains("owner.persistence.admit(prepared, bytes)"),
        "a volatile-only mutation needs exact NoStorage admission and CM COMMIT");
    assert!(!admit.contains("prepared.durable_journal().is_empty()"),
        "empty durable bytes alone must not turn a semantic mutation into ABORT");
    assert!(advance.contains("Phase::Commit"),
        "semantic CM publication must continue after NoStorage admission");
}
