//! The Executive Boot path alone may reuse copied Directory sectors.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");

#[test]
fn path_lookup_uses_a_generation_bound_boot_only_directory_cache() {
    let lookup = FAT.split_once("unsafe fn fat_lookup_metadata(").unwrap().1
        .split_once("/// Find one native FAT directory entry").unwrap().0;
    assert!(lookup.contains("FatPathRequestKind::Directory"));
    assert!(lookup.contains("EXEC_FAT_DIRECTORY_CACHE"));
    assert!(lookup.contains("BlockSourceKind::Boot"));
    assert!(lookup.contains("exec_fs_mount_identity()"));
    assert!(lookup.contains("route.mount() != mount.value()"));
    assert!(lookup.contains(".read_or_fetch("));
    let boot = lookup.find("Some(nt_fs::BlockSourceKind::Boot)").unwrap();
    let route = lookup.find("route.mount() != mount.value()").unwrap();
    let hit = lookup.find(".read_or_fetch(").unwrap();
    assert!(boot < route && route < hit, "drain and route mismatches cannot hit copied bytes");
    assert!(lookup.contains("fat_read_sector_checked(fs, sector, callsite)"));
    assert!(lookup.contains("lookup.feed(request, &bytes)"));
    assert!(lookup.contains("fat_read_sector_checked(fs, request.sector, callsite)"),
        "isolated host and post-drain paths remain physical");
}

#[test]
fn possible_write_mount_publish_and_successful_drain_invalidate_directory_copies() {
    let invalidate = FAT.split_once("unsafe fn fat_chain_cache_invalidate(").unwrap().1
        .split_once("/// Write one full FAT sector").unwrap().0;
    assert!(invalidate.contains("EXEC_FAT_DIRECTORY_CACHE"));
    for writer in ["pub(crate) unsafe fn fat_write_sector(", "pub(crate) unsafe fn fat_write_sectors("] {
        let body = FAT.split_once(writer).unwrap().1.split_once("fat_chain_cache_invalidate(fs);").unwrap().0;
        assert!(!body.contains("ahci_write_sectors("));
    }
    for boundary in ["pub(crate) fn begin_exec_mount_drain()", "pub(crate) unsafe fn publish_exec_fs("] {
        let body = FAT.split_once(boundary).unwrap().1.split_once("EXEC_FAT_RANGE_CURSORS").unwrap().0;
        assert!(body.contains("EXEC_FAT_DIRECTORY_CACHE"));
    }
}
