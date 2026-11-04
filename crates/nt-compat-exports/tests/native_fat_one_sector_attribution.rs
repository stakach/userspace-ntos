//! Verify native one-sector reads use an exact callsite and one shared census update.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");

#[test]
fn every_physical_fat_one_sector_read_has_a_callsite() {
    // One public wrapper, one declaration, and every internal one-sector caller.
    assert_eq!(FAT.matches("fat_read_sector_checked(").count(), 9);
    let sector = FAT.split_once("unsafe fn fat_read_sector_checked(").unwrap().1
        .split_once("unsafe fn fat_read_sectors_checked(").unwrap().0;
    let sectors = FAT.split_once("unsafe fn fat_read_sectors_checked(").unwrap().1
        .split_once("pub(crate) fn disk_census_record(").unwrap().0;
    assert!(sector.contains("FatOneSectorCallsite"));
    assert!(sector.contains("fat_direct_read_census_record("));
    assert!(sectors.contains("FatOneSectorCallsite::FilePayload"));
    assert!(sectors.contains("fat_direct_read_census_record("));
    assert!(FAT.contains("FatOneSectorCallsite::FatLink"));
    assert!(FAT.contains("FatOneSectorCallsite::Directory"));
    assert!(FAT.contains("FatOneSectorCallsite::Other"));
    assert!(FAT.contains("fat_one_sector_total()"));
    assert!(FAT.contains("reconciled="));
}
