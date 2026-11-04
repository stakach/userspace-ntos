//! Native FAT readers must not publish DMA bytes from failed AHCI completions.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");

fn body_after(start: &str, end: &str) -> &'static str {
    FAT.split_once(start).unwrap().1.split_once(end).unwrap().0
}

#[test]
fn fat_payload_and_mount_readers_gate_dma_on_task_file_completion() {
    for body in [
        body_after("unsafe fn fat_read_sector_checked(", "unsafe fn fat_read_sectors_checked("),
        body_after("unsafe fn fat_read_sectors_checked(", "pub(crate) fn disk_census_record("),
        body_after("pub(crate) unsafe fn fat_volume_size(", "pub(crate) unsafe fn fat_next("),
        body_after("unsafe fn read_disk_sector_into(", "unsafe fn fat32_mount_for_owner("),
    ] {
        assert!(body.contains("nt_ahci::read_completion_ok(status)"), "reader lacks task-file failure gate");
    }
}

#[test]
fn fsinfo_read_reconciles_with_fat_direct_read_census_before_failure() {
    let body = body_after("pub(crate) unsafe fn fat_volume_size(", "pub(crate) unsafe fn fat_next(");
    let account = body.find("disk_census_record(").unwrap();
    let direct = body.find("fat_direct_read_census_record(census_started, 1, nt_ahci::FatOneSectorCallsite::Other)").unwrap();
    let reject = body.find("!nt_ahci::read_completion_ok(status)").unwrap();
    assert!(account < direct && direct < reject);
}
