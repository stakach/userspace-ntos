//! Root-owned debug-filter frame and executive alias.
//!
//! The frame is retained for the root lifetime. Every guest receives only a
//! copied, read-only mapping cap, owned by that guest's exact lifetime record.

use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use nt_ntdll_layout::debug_filter::{DebugFilterPage, ABI_VERSION, HOSTED_DRIVER_VA, MAGIC};

const ROOT_ALIAS_VA: u64 = driver_launch::FSD_EXEC_LIMIT + 0x1000;
const _: () = assert!(ROOT_ALIAS_VA & 0xfff == 0);
// FSD instance windows end before FSD_EXEC_LIMIT; the KUSER scratch uses the
// first page at the limit. The next named scratch arena starts at 0x10151000000.
const _: () = assert!(ROOT_ALIAS_VA + 0x1000 <= 0x0000_0101_5100_0000);

static FRAME: AtomicU64 = AtomicU64::new(0);
static FAILED_FRAME_SLOT: AtomicU64 = AtomicU64::new(0);
static ROOT_ALIAS_CAP: AtomicU64 = AtomicU64::new(0);
// 0=not attempted, 1=entered, 2=copied. An entered or failed copy is
// retained and cannot be replayed against the same destination slot.
static ROOT_ALIAS_COPY_STATE: AtomicU32 = AtomicU32::new(0);
// A structural map refusal cannot be retried against the same VA/cap owner.
static ROOT_ALIAS_MAP_TERMINAL: AtomicU32 = AtomicU32::new(0);
static READY: AtomicBool = AtomicBool::new(false);

/// Whether a native root-page effect has an entered, unresolved owner.
/// A known resource refusal can be retried; this state cannot.
pub(crate) fn root_init_uncertain() -> bool {
    FAILED_FRAME_SLOT.load(Ordering::Acquire) != 0
        || ROOT_ALIAS_COPY_STATE.load(Ordering::Acquire) == 1
        || ROOT_ALIAS_MAP_TERMINAL.load(Ordering::Acquire) != 0
}

/// Return the one root-writable page. Synchronous native errors retain the
/// allocated frame/cap so a later attempt cannot reuse an uncertain owner.
///
/// # Safety
/// Called in the executive's serialized root context, with its VSpace active.
pub(crate) unsafe fn root_page() -> Result<&'static DebugFilterPage, nt_status::NtStatus> {
    if !READY.load(Ordering::Acquire) {
        let map_terminal = ROOT_ALIAS_MAP_TERMINAL.load(Ordering::Acquire);
        if map_terminal != 0 {
            return Err(if map_terminal == 8 {
                nt_status::NtStatus::CONFLICTING_ADDRESSES
            } else {
                nt_status::NtStatus::DEVICE_BUSY
            });
        }
        if FAILED_FRAME_SLOT.load(Ordering::Acquire) != 0 {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        if !ensure_executive_paging(ROOT_ALIAS_VA) {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        let mut frame = FRAME.load(Ordering::Acquire);
        if frame == 0 {
            let (allocated, error) = alloc_frame_r();
            if error != 0 || allocated == 0 {
                // Retain an attempted native retype slot. Its effect is not
                // replayed and the slot is never offered to another owner.
                if allocated != 0 { FAILED_FRAME_SLOT.store(allocated, Ordering::Release); }
                return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            }
            FRAME.store(allocated, Ordering::Release);
            frame = allocated;
        }
        let mut alias = ROOT_ALIAS_CAP.load(Ordering::Acquire);
        if alias == 0 {
            let Some(slot) = try_alloc_slot() else {
                return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            };
            ROOT_ALIAS_CAP.store(slot, Ordering::Release);
            ROOT_ALIAS_COPY_STATE.store(1, Ordering::Release);
            if copy_cap_into_r(frame, slot) != 0 {
                // Keep the attempted slot; no other cap may acquire it.
                return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            }
            ROOT_ALIAS_COPY_STATE.store(2, Ordering::Release);
            alias = slot;
        }
        if ROOT_ALIAS_COPY_STATE.load(Ordering::Acquire) != 2 {
            return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
        }
        let map_error = page_map_r(alias, ROOT_ALIAS_VA, RW_NX, CAP_INIT_THREAD_VSPACE);
        if map_error != 0 {
            // A failed Call did not establish a mapping. Only exhaustion can
            // retry against the same exact cap and destination.
            if map_error != 10 {
                ROOT_ALIAS_MAP_TERMINAL.store(
                    u32::try_from(map_error).unwrap_or(u32::MAX),
                    Ordering::Release,
                );
            }
            print_str(b"[debug-filter-page] root alias map failed label=");
            print_u64(map_error);
            print_str(b"\n");
            return Err(match map_error {
                10 => nt_status::NtStatus::INSUFFICIENT_RESOURCES,
                8 => nt_status::NtStatus::CONFLICTING_ADDRESSES,
                _ => nt_status::NtStatus::DEVICE_BUSY,
            });
        }
        let page = ROOT_ALIAS_VA as *mut DebugFilterPage;
        // Retype zeroes the frame. Publish the small header and initial system
        // mask without materializing a 4 KiB temporary on the root stack.
        core::ptr::write(core::ptr::addr_of_mut!((*page).magic), MAGIC);
        core::ptr::write(core::ptr::addr_of_mut!((*page).abi_version), ABI_VERSION);
        (*page).system_mask.store(1, Ordering::Release);
        READY.store(true, Ordering::Release);
    }
    Ok(&*(ROOT_ALIAS_VA as *const DebugFilterPage))
}

/// Root-owned source cap for a copied guest mapping.
///
/// # Safety
/// Called in serialized executive context.
pub(crate) unsafe fn frame() -> Result<u64, nt_status::NtStatus> {
    let _ = root_page()?;
    Ok(FRAME.load(Ordering::Acquire))
}

/// The already-installed read-only view in a hosted driver domain.
///
/// # Safety
/// The caller must be executing in a driver VSpace whose exact instance owner
/// retains a successful mapping at `HOSTED_DRIVER_VA`.
pub(crate) unsafe fn hosted_driver_page() -> &'static DebugFilterPage {
    &*(HOSTED_DRIVER_VA as *const DebugFilterPage)
}
