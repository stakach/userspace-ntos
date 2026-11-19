//! The FAT sector cache is not HBA memory, and an unreleased AHCI command keeps its owner (#289).
//!
//! The isolated host's FAT cache lived at `[0xA00, 0xC08)` of the controller DMA page, inside the
//! data window at `0x800` that any read of three or more sectors legally overwrites. Transfer
//! outcomes and HBA retention are covered behaviorally in `nt_ahci::transfer`.

const FAT: &str = include_str!("../../../components/ntos-executive/src/fs_loader.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const TRANSFER: &str = include_str!("../../../components/ntos-executive/src/ahci_transfer.rs");
const PROBE: &str = include_str!("../../../components/ntos-executive/src/device_io.rs");

fn body_after(source: &'static str, start: &str, end: &str) -> &'static str {
    source.split_once(start).unwrap().1.split_once(end).unwrap().0
}

#[test]
fn no_fat_cache_is_derived_from_the_dma_run() {
    for retired in ["FatSectorCacheScratch", "FAT32_FAT_CACHE_OFFSET", "FAT32_SCRATCH_OFFSET"] {
        assert!(!FAT.contains(retired), "{retired} still places a cache in DMA memory");
    }
    assert!(!MAIN.contains("scratch_vaddr: u64"));
    let next = body_after(FAT, "unsafe fn fat_next_checked(", "/// Checked directory traversal");
    assert!(next.contains("(&mut *fs.sector_cache).read_entry("));
    assert!(!next.contains("dma_vaddr"));
}

#[test]
fn each_mount_owner_supplies_its_own_writable_cache() {
    let mount = body_after(FAT, "unsafe fn fat32_mount_for_owner(", "let mounted = Fat32 {");
    assert!(mount.contains("if sector_cache.is_null() {"));
    let executive = body_after(FAT, "pub(crate) unsafe fn fat32_mount(", "/// `sector_cache`");
    assert!(executive.contains("core::ptr::addr_of_mut!(EXEC_FAT_SECTOR_CACHE)"));
    let probe = body_after(PROBE, "pub(crate) unsafe fn storage_probe(", "macro_rules!");
    let cache = probe.find("let mut fat_sector_cache = nt_fs::FatSectorCache::new();").unwrap();
    let mount = probe.find("fat32_mount_isolated_storage_host(").unwrap();
    assert!(cache < mount);
}

#[test]
fn unreleased_commands_keep_their_boot_ticket_and_hide_their_payload() {
    assert!(TRANSFER.contains("finish_boot_io(admission, outcome.hba_released())"));
    assert!(TRANSFER.contains("nt_ahci::transfer(&mut port, dma_paddr, WINDOW_BYTES, request, POLL_BUDGET)"));
    // One transfer implementation: no hand-rolled command issue remains in main.rs.
    assert!(!MAIN.contains("pw(0x38, 1);"));
    let probe = body_after(PROBE, "pub(crate) unsafe fn storage_probe(", "print_str(b\"[storage-host] AHCI DET=\");");
    assert!(probe.contains("read.is_completed()"));
}
