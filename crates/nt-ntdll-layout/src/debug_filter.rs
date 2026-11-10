//! Root-owned debug-filter page shared read-only with hosted NT domains.
//!
//! The executive initializes the whole frame before publishing any mapping and
//! retains the original frame for its lifetime. Each guest mapping owns only a
//! copied cap. The mask words are atomic because privileged updates may happen
//! while an ntdll or hosted driver reader runs in another domain.

use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::AtomicU32;

use nt_compat_exports::debug_filter::COMPONENT_COUNT;

pub const PAGE_SIZE: usize = crate::kuser::PAGE_SIZE;
pub const MAGIC: u32 = u32::from_le_bytes(*b"NTDF");
pub const ABI_VERSION: u32 = 1;

/// Dedicated page in the hosted process environment's existing 2 MiB page table.
/// The executive must reserve this page in its guest VM policy before mapping it.
pub const HOSTED_USER_VA: u64 = 0x0000_0100_1605_0000;

/// Adjacent to, and disjoint from, the one-page kernel-mode KUSER alias.
/// Hosted driver domains map this page read-only; the executive has a separate
/// writable alias. PnP resource windows live in the low user canonical range.
pub const HOSTED_DRIVER_VA: u64 = crate::kuser::KERNEL_ALIAS_VA + PAGE_SIZE as u64;

const HEADER_SIZE: usize = 4 * size_of::<u32>();
const MASKS_SIZE: usize = COMPONENT_COUNT * size_of::<u32>();
const RESERVED_SIZE: usize = PAGE_SIZE - HEADER_SIZE - MASKS_SIZE;

/// Exact, zero-initialized 4 KiB frame layout. The header is immutable after
/// mapping; readers may use the masks only when `magic` and `abi_version` match.
#[repr(C, align(4096))]
pub struct DebugFilterPage {
    pub magic: u32,
    pub abi_version: u32,
    pub system_mask: AtomicU32,
    pub default_mask: AtomicU32,
    pub component_masks: [AtomicU32; COMPONENT_COUNT],
    _reserved: [u8; RESERVED_SIZE],
}

impl DebugFilterPage {
    pub const fn new() -> Self {
        Self {
            magic: MAGIC,
            abi_version: ABI_VERSION,
            system_mask: AtomicU32::new(1),
            default_mask: AtomicU32::new(0),
            component_masks: [const { AtomicU32::new(0) }; COMPONENT_COUNT],
            _reserved: [0; RESERVED_SIZE],
        }
    }

    pub const fn compatible(&self) -> bool {
        self.magic == MAGIC && self.abi_version == ABI_VERSION
    }
}

impl Default for DebugFilterPage {
    fn default() -> Self { Self::new() }
}

const _: () = assert!(size_of::<DebugFilterPage>() == PAGE_SIZE);
const _: () = assert!(align_of::<DebugFilterPage>() == PAGE_SIZE);
const _: () = assert!(offset_of!(DebugFilterPage, magic) == 0);
const _: () = assert!(offset_of!(DebugFilterPage, abi_version) == 4);
const _: () = assert!(offset_of!(DebugFilterPage, system_mask) == 8);
const _: () = assert!(offset_of!(DebugFilterPage, default_mask) == 12);
const _: () = assert!(offset_of!(DebugFilterPage, component_masks) == 16);
const _: () = assert!(HOSTED_USER_VA & (PAGE_SIZE as u64 - 1) == 0);
const _: () = assert!(HOSTED_DRIVER_VA & (PAGE_SIZE as u64 - 1) == 0);
const _: () = assert!(HOSTED_DRIVER_VA == crate::kuser::KERNEL_ALIAS_VA + PAGE_SIZE as u64);

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    #[test]
    fn initial_page_matches_reactos_masks_and_complete_frame_layout() {
        let page = DebugFilterPage::new();
        assert!(page.compatible());
        assert_eq!(page.system_mask.load(Ordering::Relaxed), 1);
        assert_eq!(page.default_mask.load(Ordering::Relaxed), 0);
        assert!(page.component_masks.iter().all(|mask| mask.load(Ordering::Relaxed) == 0));
        assert_eq!(size_of::<DebugFilterPage>(), PAGE_SIZE);
        assert_eq!(align_of::<DebugFilterPage>(), PAGE_SIZE);
        assert_eq!(offset_of!(DebugFilterPage, component_masks), 16);
        assert_eq!(HOSTED_USER_VA & 0xfff, 0);
        assert_eq!(HOSTED_DRIVER_VA & 0xfff, 0);
    }

    #[test]
    fn incompatible_header_is_rejected() {
        let mut page = DebugFilterPage::new();
        page.abi_version += 1;
        assert!(!page.compatible());
        page.abi_version = ABI_VERSION;
        page.magic = 0;
        assert!(!page.compatible());
    }
}
