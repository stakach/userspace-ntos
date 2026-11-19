//! win32k-domain targets for the WDDM bridge interface (see
//! `nt_io_manager::wddm_bridge_interface`). The provider's function pointers cannot execute here.

use super::*;

/// `BOOLEAN SendIoctl(ULONG Code, PVOID In, ULONG InLength, PVOID Out, ULONG OutLength,
/// NTSTATUS *Status, ULONG_PTR *Information)`. Declining (FALSE) makes WddmBridgeSendIoctl send
/// the same IOCTL to the bridge device through IoBuildDeviceIoControlRequest/IofCallDriver, which
/// the I/O manager routes into the provider's own domain.
extern "win64" fn decline_send_ioctl(
    _code: u32,
    _input: u64,
    _input_length: u32,
    _output: u64,
) -> u8 {
    0
}

/// A bridge entry point that has no cross-domain route yet. Calling it stops the provider with
/// the slot index rather than jumping into another domain's code.
extern "win64" fn unrouted_slot<const SLOT: usize>() -> u64 {
    unsafe { crate::provider_bugcheck::report(0xc4, [0x5744_444d, SLOT as u64, 0, 0]) }
}

macro_rules! slot_table {
    ($($slot:literal),* $(,)?) => {
        [$(unrouted_slot::<$slot> as *const () as u64),*]
    };
}

fn unrouted_slot_target(slot: usize) -> u64 {
    let table: [u64; nt_io_manager::wddm_bridge_interface::WDDM_BRIDGE_SLOT_COUNT] = slot_table!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
        69, 70, 71, 72, 73, 74, 75, 76,
    );
    table[slot]
}

/// Project a successful bridge interface in place before it is published to win32k.
pub(super) fn project(output: &mut [u8]) -> bool {
    match nt_io_manager::wddm_bridge_interface::project_bridge_interface(
        output,
        decline_send_ioctl as *const () as u64,
        unrouted_slot_target,
    ) {
        Ok(projected) => {
            print_str(b"[wddm-bridge] projected slots=");
            print_u64(projected as u64);
            print_str(b"\n");
            true
        }
        Err(_) => false,
    }
}
