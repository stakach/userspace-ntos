//! The native boot path must settle snapshot format before importing SYSTEM into CM.

#[test]
fn boot_repairs_interrupted_wal_baseline_before_snapshot_decode() {
    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let restore = &source[source.find("unsafe fn restore_boot_snapshot_volume_once(").unwrap()
        ..source.find("unsafe fn snapshot_reserve_available()").unwrap()];
    let inspect = restore.find("boot_recovery_state(&mut dev)").unwrap();
    let repair = restore.find("repair_boot_snapshot_baseline").unwrap();
    let decode = restore.find("restore_volume_snapshot_with_metadata_from_store").unwrap();
    assert!(inspect < repair && repair < decode);

    let repair_owner = &source[source.find("fn repair_boot_snapshot_baseline(").unwrap()
        ..source.find("unsafe fn restore_boot_snapshot_volume_once(").unwrap()];
    assert!(repair_owner.contains("WalSnapshotBaselineRepair::admit"));
    assert!(repair_owner.contains("repair.repair()"));
    assert!(repair_owner.contains("core::mem::forget(repair)"));
    assert!(repair_owner.contains("WalSnapshotEpochRollover::resume"));
    assert!(repair_owner.contains("rollover.finish()"));
    assert!(repair_owner.contains("core::mem::forget(rollover)"));
}

#[test]
fn legacy_migration_folds_semantically_composed_system_before_v2_baseline() {
    let boot = include_str!("../../../components/ntos-executive/src/main.rs");
    let prepare = &boot[boot.find("unsafe fn prepare_boot_system_hive_image()").unwrap()
        ..boot.find("struct DriverServiceLaunchSpec").unwrap()];
    let compose = prepare.find("compose_boot_system_hive(").unwrap();
    let encode = prepare.find("try_encode_image(&composed.hive)").unwrap();
    let publish = prepare.find("restored.publish()").unwrap();
    assert!(compose < encode && encode < publish);

    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let owner = &source[source.find("impl RestoredBootSystem {").unwrap()
        ..source.find("impl Drop for RestoredBootSystem").unwrap()];
    let fold = owner.find("fold_boot_system_sidecar").unwrap();
    let migrate = owner.find("WalSnapshotBaselineRepair::admit").unwrap();
    let baseline = owner.find("migration.migrate(fs)").unwrap();
    let mount = owner.find("install_writable_fs(fs, true)").unwrap();
    assert!(fold < migrate && migrate < baseline && baseline < mount);
    assert!(owner.contains("SnapshotReadFormat::Legacy"));
    assert!(owner.contains("core::mem::forget(migration)"));
    assert!(owner.contains("_admission: BootWalCutoverAdmission"));
    let activation = prepare.find("migrate_composed_boot_system(&image").expect("restored legacy cutover");
    assert!(encode < activation && activation < publish,
        "compose and encode before legacy migration, then publish the v2 filesystem");
}

#[test]
fn empty_reserve_gets_paired_wal_baseline_before_cm_import() {
    let boot = include_str!("../../../components/ntos-executive/src/main.rs");
    let prepare = &boot[boot.find("unsafe fn prepare_boot_system_hive_image()").unwrap()
        ..boot.find("struct DriverServiceLaunchSpec").unwrap()];
    let encode = prepare.find("try_encode_image(&composed.hive)").unwrap();
    let initialize = prepare.find("initialize_empty_boot_system_wal(")
        .expect("first boot v2 baseline");
    let call = &prepare[initialize..(initialize + 180).min(prepare.len())];
    assert!(call.contains("&image"),
        "first boot must fold the semantically composed image");
    let image_publish = prepare.find("*core::ptr::addr_of_mut!(BOOT_SYSTEM_HIVE_IMAGE)").unwrap();
    assert!(encode < initialize && initialize < image_publish,
        "an empty reserve cannot publish CM authority before its durable v2 baseline");

    let writable = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let initialize = &writable[writable.find("fn initialize_empty_boot_system_wal(").unwrap()
        ..writable.find("impl RestoredBootSystem {").unwrap()];
    let provision = initialize.find("provision_missing_installed_sources(&mut fs)")
        .expect("parent directories, profile sources, config sources and boot status");
    let fold = initialize.find("fold_boot_system_sidecar(&mut fs, image)").unwrap();
    let baseline = initialize.find("initialization.initialize(&fs)").unwrap();
    assert!(provision < fold && fold < baseline,
        "first boot must include staged source tree and composed SYSTEM in both baseline slots");
    assert!(initialize.contains("WalSnapshotBaselineRepair::admit"));
    assert!(initialize.contains("initialization.initialize(&fs)"));
    assert!(initialize.contains("install_writable_fs(fs, true)"));
    assert!(initialize.contains("SnapshotReadFormat::Wal"));
}

#[test]
fn boot_publishes_verified_wal_suffix_anchor_after_semantic_composition() {
    let boot = include_str!("../../../components/ntos-executive/src/main.rs");
    let prepare = &boot[boot.find("unsafe fn prepare_boot_system_hive_image()").unwrap()
        ..boot.find("struct DriverServiceLaunchSpec").unwrap()];
    let compose = prepare.find("compose_boot_system_hive_with_wal_suffix").unwrap();
    let encode = prepare.find("try_encode_image(&composed.hive)").unwrap();
    let publish = prepare.find("restored.publish()").unwrap();
    assert!(compose < encode && encode < publish);

    let source = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let recovery = &source[source.find("fn verified_boot_log(").unwrap()
        ..source.find("unsafe fn restore_boot_system_persistence(").unwrap()];
    assert!(recovery.contains("wal.into_verified_device()"));
    assert!(recovery.contains("into_full_device()"));
    assert!(!recovery.contains("wal.into_device()"), "boot must retain the verified WAL prefix with its lease");

    let owner = &source[source.find("impl RestoredBootSystem {").unwrap()
        ..source.find("impl Drop for RestoredBootSystem").unwrap()];
    let admit = owner.find("WalSnapshotAnchorUpdate::admit_verified_wal").unwrap();
    let advance = owner.find("update.advance()").unwrap();
    let mount = owner.find("install_writable_fs(fs, true)").unwrap();
    assert!(admit < advance && advance < mount);
    assert!(owner.contains("core::mem::forget(update)"), "an uncertain header barrier must retain the reserve lease");
}
