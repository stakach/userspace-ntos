//! Native wiring for one-count-per-physical-read directory attribution.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");

#[test]
fn directory_callers_and_path_parent_observer_use_bounded_ready_census() {
    for (start, end, name) in [
        ("pub(crate) unsafe fn fat_visit_directory_checked(", "pub(crate) unsafe fn fat_visit_directory(", "CheckedDirectory"),
        ("pub(crate) unsafe fn fat_visit_directory(", "pub(crate) unsafe fn dir_find(", "LegacyDirectory"),
        ("pub(crate) unsafe fn dir_find(", "pub(crate) unsafe fn fat_read_file(", "ShortDirectory"),
        ("unsafe fn fat_lookup_metadata(", "/// Find one native FAT directory entry", "PathDirectory"),
    ] {
        let body = FAT.split_once(start).unwrap().1.split_once(end).unwrap().0;
        assert!(body.contains(name), "missing typed caller {name}");
    }
    assert!(FAT.contains("fat_directory_total()"));
    assert!(FAT.contains("FatPathLookupCensus"));
    assert!(FAT.contains(".directory_sector("));
    let lookup = FAT.split_once("unsafe fn fat_lookup_metadata(").unwrap().1
        .split_once("/// Find one native FAT directory entry").unwrap().0;
    assert!(lookup.find("fat_read_sector_checked(fs, request.sector, callsite)?;").unwrap()
        < lookup.find(".directory_sector(lookup.parent_cluster())").unwrap());
    assert!(FAT.contains(".found()"));
    assert!(FAT.contains(".not_found()"));
    assert!(FAT.contains("fat-directory-callsites"));
    assert!(FAT.contains("fat-path-parent"));
    assert!(FAT.contains("physical-directory-attempts="));
    assert!(FAT.contains("no-data-attempts="));
}
