//! The Executive path walker reuses mounted FAT-link sectors.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");

#[test]
fn mounted_fat_path_links_share_generation_bound_cache() {
    let lookup = FAT.split_once("unsafe fn fat_lookup_metadata(").unwrap().1
        .split_once("/// Find one native FAT directory entry").unwrap().0;
    assert!(lookup.contains("FatPathRequestKind::Fat"));
    assert!(lookup.contains("EXEC_FAT_SECTOR_CACHE"));
    assert!(lookup.contains(".read_sector("));
    assert!(lookup.contains("exec_fs_mount_identity()"));
    assert!(lookup.contains("FatIoOwner::Executive"));
    assert!(lookup.contains("FatPathRequestKind::Directory"));
    assert!(lookup.contains("fat_read_sector_checked(fs, request.sector, callsite)"));
    assert!(lookup.contains("lookup.feed(request, &bytes)"));
    assert!(FAT.contains("fat_chain_cache_invalidate(fs);"));
}
