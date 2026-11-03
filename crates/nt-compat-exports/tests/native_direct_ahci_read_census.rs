//! Native wiring for the pure Executive direct-read attribution counter.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");
const SNAPSHOT: &str =
    include_str!("../../../components/ntos-executive/src/writable_fs/snapshot_storage.rs");
const EXECUTIVE: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const HANDOFF: &str =
    include_str!("../../../components/ntos-executive/src/boot_storage_dma_handoff.rs");

fn body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let source = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing {start}"))
        .1;
    source
        .split_once(end)
        .unwrap_or_else(|| panic!("missing {end}"))
        .0
}

#[test]
fn executive_fat_and_snapshot_reads_are_attributed_only_after_returned_attempts() {
    let sector = body(
        FAT,
        "unsafe fn fat_read_sector_checked(",
        "unsafe fn fat_read_sectors_checked(",
    );
    let sectors = body(
        FAT,
        "unsafe fn fat_read_sectors_checked(",
        "pub(crate) fn disk_census_record(",
    );
    let snapshot = body(SNAPSHOT, "    fn read_sectors(", "    fn write_sector(");
    for (read, source) in [
        (sector, "DirectReadSource::Fat"),
        (sectors, "DirectReadSource::Fat"),
        (snapshot, "DirectReadSource::Snapshot"),
    ] {
        assert!(read.contains(".then(disk_census_ticks)"));
        assert!(read.contains("disk_census_record("));
        assert!(read.contains("direct_read_census_record("));
        assert!(read.contains(source));
        assert!(
            read.find("direct_read_census_record(").unwrap()
                > read
                    .find("let status =")
                    .unwrap_or_else(|| read.find("let tfd =").unwrap())
        );
    }
    assert!(FAT.contains("FatIoOwner::IsolatedStorageHost =>"));
    assert!(EXECUTIVE.contains("disk-read="));
    assert!(HANDOFF.contains("print_direct_read_census_once()"));
    assert!(FAT.contains("direct-read-source="));
}
