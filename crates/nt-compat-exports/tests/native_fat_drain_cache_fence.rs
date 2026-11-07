//! The Boot→Draining handoff retires cached FAT facts before native writes can begin.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");

#[test]
fn successful_boot_drain_invalidates_retained_fat_link_and_range_caches() {
    let drain = FAT.split_once("pub(crate) fn begin_exec_mount_drain()").unwrap().1
        .split_once("pub(crate) unsafe fn publish_exec_fs(").unwrap().0;
    let boot = drain.split_once("nt_fs::BlockSourceKind::Boot =>").unwrap().1
        .split_once("nt_fs::BlockSourceKind::Draining =>").unwrap().0;
    let transition = boot.find("route.begin_drain(mount.value())?;").unwrap();
    let link = boot.find("EXEC_FAT_SECTOR_CACHE").expect("retire cached FAT links");
    let range = boot.find("EXEC_FAT_RANGE_CURSORS").expect("retire cached FAT range cursors");
    assert!(transition < link && transition < range);
    assert!(boot.contains(".invalidate()"));
    assert!(drain.contains("nt_fs::BlockSourceKind::Draining => Ok(())"));
    assert!(drain.contains("nt_fs::BlockSourceKind::Native => Err(nt_fs::BlockRouteError::WrongPhase)"));
}
