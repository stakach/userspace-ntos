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
    assert!(!prepare.contains("migrate_composed_boot_system"), "live v1 CM writers still require v1 format");
}
