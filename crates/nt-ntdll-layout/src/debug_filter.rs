//! Root-owned debug-filter page shared read-only with hosted NT domains.
//!
//! The executive initializes the whole frame before publishing any mapping and
//! retains the original frame for its lifetime. Each guest mapping owns only a
//! copied cap. The mask words are atomic because privileged updates may happen
//! while an ntdll or hosted driver reader runs in another domain.

use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicU32, Ordering};

use nt_compat_exports::debug_filter::{self, COMPONENT_COUNT, MaskSlot, SetFilterError};

pub const PAGE_SIZE: usize = crate::kuser::PAGE_SIZE;
pub const MAGIC: u32 = u32::from_le_bytes(*b"NTDF");
pub const ABI_VERSION: u32 = 1;

/// Dedicated page in the hosted process environment's existing 2 MiB page table.
/// The executive must reserve this page in its guest VM policy before mapping it.
pub const HOSTED_USER_VA: u64 = 0x0000_0100_1605_0000;

/// Reserved leaf in the hosted driver's existing auxiliary page table, beyond
/// its argument bank. Only the exact KUSER leaf is admitted in the upper
/// canonical half, so this shared page has its own lower-canonical address.
/// The executive retains a separate writable alias.
pub const HOSTED_DRIVER_VA: u64 = 0x0000_0100_0F3B_0000;

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

    fn selected_mask(&self, component: u32) -> &AtomicU32 {
        match debug_filter::mask_slot(component) {
            MaskSlot::System => &self.system_mask,
            MaskSlot::Default => &self.default_mask,
            MaskSlot::Component(index) => &self.component_masks[index],
        }
    }

    /// Read the same root-owned words used by the direct native query.
    pub fn query(&self, component: u32, level: u32) -> Option<bool> {
        if !self.compatible() { return None; }
        let system = self.system_mask.load(Ordering::Acquire);
        let selected = self.selected_mask(component).load(Ordering::Acquire);
        Some(debug_filter::enabled(system, selected, level))
    }

    /// Mutate a mask through the root's writable alias after a privilege check.
    /// Guest mappings of this frame are read-only.
    pub fn set(&self, component: u32, level: u32, state: bool,
        has_debug_privilege: bool) -> Result<(), SetFilterError> {
        if !has_debug_privilege { return Err(SetFilterError::AccessDenied); }
        if !self.compatible() { return Err(SetFilterError::IncompatiblePage); }
        let bits = debug_filter::level_mask(level);
        let mask = self.selected_mask(component);
        if state { mask.fetch_or(bits, Ordering::AcqRel); }
        else { mask.fetch_and(!bits, Ordering::AcqRel); }
        Ok(())
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
const _: () = assert!(HOSTED_DRIVER_VA + (PAGE_SIZE as u64) < (1u64 << 47));

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;
    use nt_compat_exports::debug_filter::SetFilterError;

    // ReactOS/LiberNT contract (ntoskrnl/kd64/kdapi.c NtQueryDebugFilterState /
    // NtSetDebugFilterState, kd64/kddata.c KdComponentTable, Kd_WIN2000_Mask = 1).
    const DPFLTR_DEFAULT_ID: u32 = 101;
    const DPFLTR_ENDOFTABLE_ID: u32 = 155;
    const DPFLTR_MASK: u32 = 0x8000_0000;
    const WIN2000: u32 = u32::MAX;

    #[test]
    fn contract_levels_below_32_are_bit_indexes_and_wider_levels_are_raw_masks() {
        let page = DebugFilterPage::new();
        page.set(7, 3, true, true).unwrap();
        assert_eq!(page.query(7, 3), Some(true));
        assert_eq!(page.query(7, DPFLTR_MASK | 0b1000), Some(true));
        assert_eq!(page.query(7, DPFLTR_MASK | 0b0100), Some(false));
        // Level 31 converts to 0x8000_0000, which the DPFLTR_MASK strip removes.
        page.set(7, 31, true, true).unwrap();
        assert_eq!(page.query(7, 31), Some(false));
        // A raw DPFLTR_MASK value of only the flag selects no level.
        assert_eq!(page.query(7, DPFLTR_MASK), Some(false));
    }

    #[test]
    fn contract_unknown_components_share_the_default_component_mask() {
        let page = DebugFilterPage::new();
        // Kd_DEFAULT_Mask is both KdComponentTable[DPFLTR_DEFAULT_ID] and the
        // Vista+ fallback for IDs outside the table.
        page.set(DPFLTR_DEFAULT_ID, 2, true, true).unwrap();
        assert_eq!(page.query(DPFLTR_ENDOFTABLE_ID + 1, 2), Some(true));
        assert_eq!(page.query(0x1234_5678, 2), Some(true));
        page.set(0x1234_5678, 2, false, true).unwrap();
        assert_eq!(page.query(DPFLTR_DEFAULT_ID, 2), Some(false));
        // The last table entry (DPFLTR_ENDOFTABLE_ID) is a real, distinct mask.
        page.set(DPFLTR_ENDOFTABLE_ID, 4, true, true).unwrap();
        assert_eq!(page.query(DPFLTR_ENDOFTABLE_ID + 1, 4), Some(false));
    }

    #[test]
    fn contract_win2000_mask_starts_at_error_and_enables_every_component() {
        let page = DebugFilterPage::new();
        for component in [0, DPFLTR_DEFAULT_ID, DPFLTR_ENDOFTABLE_ID, 4096, WIN2000] {
            assert_eq!(page.query(component, 0), Some(true), "component {component}");
            assert_eq!(page.query(component, 1), Some(false), "component {component}");
        }
        page.set(WIN2000, 1, true, true).unwrap();
        assert_eq!(page.query(42, 1), Some(true));
        page.set(WIN2000, 0, false, true).unwrap();
        assert_eq!(page.query(42, 0), Some(false));
        assert_eq!(page.query(WIN2000, 0), Some(false));
    }

    #[test]
    fn contract_set_requires_the_debug_privilege_and_changes_nothing_without_it() {
        let page = DebugFilterPage::new();
        for component in [3, DPFLTR_DEFAULT_ID, 9999, WIN2000] {
            assert_eq!(page.set(component, 2, true, false), Err(SetFilterError::AccessDenied));
            assert_eq!(page.query(component, 2), Some(false));
        }
        assert_eq!(page.set(WIN2000, 0, false, false), Err(SetFilterError::AccessDenied));
        assert_eq!(page.query(3, 0), Some(true));
    }

    #[test]
    fn contract_a_privileged_set_is_visible_through_every_mapped_view() {
        // The root's writable alias and each hosted process/driver read-only
        // mapping are views of one frame; model them as aliases of one page.
        let frame = DebugFilterPage::new();
        let root_alias: &DebugFilterPage = &frame;
        let process_a: &DebugFilterPage = unsafe { &*(&frame as *const DebugFilterPage) };
        let process_b: &DebugFilterPage = unsafe { &*(&frame as *const DebugFilterPage) };
        assert_eq!(process_a.query(12, 3), Some(false));
        root_alias.set(12, 3, true, true).unwrap();
        assert_eq!(process_a.query(12, 3), Some(true));
        assert_eq!(process_b.query(12, 3), Some(true));
        root_alias.set(12, 3, false, true).unwrap();
        assert_eq!(process_b.query(12, 3), Some(false));
    }

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
    fn driver_alias_is_admitted_by_the_microkernel_user_frame_boundary() {
        // rust-micro admits only the exact KUSER leaf in the upper canonical
        // half. Any other driver frame must fit wholly below USER_VADDR_END.
        assert!(HOSTED_DRIVER_VA
            .checked_add(PAGE_SIZE as u64)
            .is_some_and(|end| end < (1u64 << 47)));
    }

    #[test]
    fn incompatible_header_is_rejected() {
        let mut page = DebugFilterPage::new();
        page.abi_version += 1;
        assert!(!page.compatible());
        assert_eq!(page.query(0, 0), None);
        assert_eq!(page.set(0, 0, false, true),
            Err(nt_compat_exports::debug_filter::SetFilterError::IncompatiblePage));
        page.abi_version = ABI_VERSION;
        page.magic = 0;
        assert!(!page.compatible());
    }

    #[test]
    fn shared_page_query_and_privileged_update_use_the_same_mask_words() {
        let page = DebugFilterPage::new();
        assert_eq!(page.query(42, 0), Some(true));
        assert_eq!(page.query(42, 1), Some(false));
        assert_eq!(page.set(42, 1, true, false), Err(nt_compat_exports::debug_filter::SetFilterError::AccessDenied));
        assert_eq!(page.query(42, 1), Some(false));
        page.set(42, 1, true, true).unwrap();
        assert_eq!(page.query(42, 1), Some(true));
        assert_eq!(page.query(43, 1), Some(false));
        page.set(u32::MAX, 0, false, true).unwrap();
        assert_eq!(page.query(43, 0), Some(false));
        assert_eq!(page.query(42, 0), Some(false));
        page.set(200, 2, true, true).unwrap();
        assert_eq!(page.query(201, 2), Some(true));
        assert_eq!(page.query(155, 2), Some(false));
    }
}
