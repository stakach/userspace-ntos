//! win32k-domain entry points for the WDDM bridge interface (see
//! `nt_io_manager::wddm_bridge_interface`). The root writes these addresses over the provider's
//! function pointers before the interface reaches win32k; provider code cannot execute here.
//!
//! A routed entry asks the root to call the provider through the exact binding it recorded for
//! win32k (`driver_launch::hosted_dxg_registration::wddm_bridge`). Every other entry stops win32k
//! with the slot index.

use super::*;
use nt_io_manager::wddm_bridge_interface::{
    BridgeSlotRoute, WDDM_BRIDGE_SEND_IOCTL_SLOT, WDDM_BRIDGE_SLOT_COUNT,
};

/// `provider_bugcheck` parameter 0 for a bridge entry that cannot complete ("WDDM").
const BRIDGE_BUGCHECK_TAG: u64 = 0x5744_444d;

// Entry from win32k's indirect call, with the Win64 arguments in rcx/rdx/r8/r9 and on the stack.
// The four register arguments are spilled into the caller's home space, which belongs to the
// callee, so the root reads every argument from the caller frame at `rsp + 8`.
core::arch::global_asm!(
    ".text",
    ".globl win32k_wddm_bridge_send_ioctl_entry",
    "win32k_wddm_bridge_send_ioctl_entry:",
    "mov [rsp + 0x08], rcx",
    "mov [rsp + 0x10], rdx",
    "mov [rsp + 0x18], r8",
    "mov [rsp + 0x20], r9",
    "mov ecx, {slot}",
    "mov rdx, rsp",
    "sub rsp, 0x28",
    "call win32k_wddm_bridge_routed_call",
    "add rsp, 0x28",
    "ret",
    slot = const WDDM_BRIDGE_SEND_IOCTL_SLOT,
);

extern "win64" {
    fn win32k_wddm_bridge_send_ioctl_entry();
}

/// The root replies `(status, provider result)`. A refused or uncertain call has no result to
/// return: win32k stops with the slot and status instead of observing a fabricated value.
#[no_mangle]
unsafe extern "win64" fn win32k_wddm_bridge_routed_call(slot: u64, entry_rsp: u64) -> u64 {
    let (words, raw, result, spare0, spare1) = crate::driver_launch::call_on4_raw(
        (W32_WDDM_BRIDGE_LABEL << 12) | 4, slot, entry_rsp, 0, 0);
    if words != 4 || raw != 0 || spare0 != 0 || spare1 != 0 {
        crate::provider_bugcheck::report(0xc4, [BRIDGE_BUGCHECK_TAG, slot, raw, words]);
    }
    result
}

/// A bridge entry point that has no cross-domain route. Calling it stops win32k with the slot
/// index rather than jumping into another domain's code.
extern "win64" fn unrouted_slot<const SLOT: usize>() -> u64 {
    unsafe { crate::provider_bugcheck::report(0xc4, [BRIDGE_BUGCHECK_TAG, SLOT as u64, 0, 0]) }
}

macro_rules! slot_table {
    ($($slot:literal),* $(,)?) => {
        [$(unrouted_slot::<$slot> as *const () as u64),*]
    };
}

/// The win32k-domain address the root publishes for a present slot.
pub(crate) fn entry(slot: usize, route: BridgeSlotRoute) -> u64 {
    if route == BridgeSlotRoute::Routed && slot == WDDM_BRIDGE_SEND_IOCTL_SLOT {
        return win32k_wddm_bridge_send_ioctl_entry as *const () as u64;
    }
    let table: [u64; WDDM_BRIDGE_SLOT_COUNT] = slot_table!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        69, 70, 71, 72, 73, 74, 75, 76,
    );
    table[slot]
}
