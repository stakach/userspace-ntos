//! Hosted ntoskrnl `InitSafeBootMode` ULONG data export.

use super::*;

// This boot path has no safe-boot selection: the installed system is started in normal mode.
// Keep a real writable per-domain ULONG cell for PE data imports and pointer dereferences.
pub(super) const SAFE_BOOT_MODE_OFFSET: u64 = 0xA28;
pub(super) const SAFE_BOOT_MODE_VA: u64 = FSD_DATA_VADDR + SAFE_BOOT_MODE_OFFSET;

pub(super) unsafe fn initialize(exec_data_va: u64) {
    write_volatile((exec_data_va + SAFE_BOOT_MODE_OFFSET) as *mut u32, 0);
}
