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
fn writable_hive_provider_refuses_v2_system_log_append_before_file_effect() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let guard = &source[source.find("fn require_legacy_file_mutation(").unwrap()
        ..source.find("\n    pub(crate) fn truncate_log_to(").unwrap()];
    assert!(guard.contains("CONFIG_SYSTEM_HIVE_PATH") && guard.contains("legacy_snapshot_writes_allowed()"),
        "the file mutation gate must distinguish SYSTEM v2 from unrelated hive logs");
    assert!(guard.contains("ensure_mounted()"),
        "a lazy restored v2 volume must be classified before its legacy provider writes");
    let provider = &source[source.find("impl nt_hive_core::HiveIoProvider for WritableHiveIoProvider {").unwrap()
        ..source.find("\n/// `NtFlushBuffersFile` on a writable-volume file object.").unwrap()];
    let append = &provider[provider.find("fn append_log_record(").unwrap()
        ..provider.find("\n    fn truncate_log(").unwrap()];
    let guard = append.find("require_legacy_file_mutation()")
        .expect("the ordinary SYSTEM.LOG provider must refuse mounted v2 before any append");
    let effect = append.find("append_file(").expect("legacy provider append effect");
    assert!(guard < effect, "v2 refusal must precede the file append");
}

#[test]
fn legacy_system_mutation_paths_refuse_v2_before_effects_and_abort_prepared_cm_work() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let legacy = &main[main.find("pub(crate) unsafe fn persist_and_publish_system_hive_mutation(").unwrap()
        ..main.find("\npub(crate) unsafe fn config_manager_prepare_system_hive_checkpoint(").unwrap()];
    let guard = legacy.find("legacy_snapshot_writes_allowed()")
        .expect("one-shot CM mutation must refuse mounted v2 before preparing CM or writing LOG");
    let prepare = legacy.find("config_manager_prepare_system_hive_mutation(").unwrap();
    assert!(guard < prepare);

    let worker = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let admit = &worker[worker.find("Phase::Admit => {").unwrap()..worker.find("Phase::Durable => {").unwrap()];
    assert!(admit.contains("ensure_mounted()") && admit.contains("legacy_snapshot_writes_allowed()"),
        "retained CM work must classify a lazy restored v2 volume before storage effects");
    assert!(admit.contains("work.phase = Phase::Abort"),
        "a refused v2 v1-storage admission must abort the still-prepared CM mutation");
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
