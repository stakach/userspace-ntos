//! The provider's requests for reserve-only session views (`SEC_RESERVE` Section views).
//!
//! The root owns the band ledger and every page effect (`crate::win32k_session_views`). A view
//! reserves addresses only; a page exists once it is committed, and a reserved page that was never
//! committed faults as an access violation. The provider keeps no copy of the ledger.

use super::*;
use nt_memory_manager::session_view_band::wire;

pub(crate) const BASE: u64 = nt_executive_layout::root::WIN32K_SESSION_VIEWS.base;
pub(crate) const BYTES: u64 = nt_executive_layout::root::WIN32K_SESSION_VIEWS.len;

pub(crate) fn contains(address: u64) -> bool {
    address >= BASE && address - BASE < BYTES
}

unsafe fn call(op: u64, first: u64, second: u64) -> (i32, u64, u64) {
    let (words, raw, out1, out2, spare) = crate::driver_launch::call_on4_raw(
        (W32_SESSION_VIEW_LABEL << 12) | 4, op, first, second, 0);
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4 || !canonical || spare != 0
        || ((raw as u32 as i32) < 0 && (out1 != 0 || out2 != 0))
    {
        crate::provider_bugcheck::report(0xc4, [W32_SESSION_VIEW_LABEL, op, words, raw]);
    }
    (raw as u32 as i32, out1, out2)
}

/// Reserve a view of `bytes`: `(base, generation)`.
pub(super) unsafe fn reserve(bytes: u64) -> Option<(u64, u64)> {
    let (status, base, generation) = call(wire::OP_RESERVE, bytes, 0);
    if status != 0 {
        print_str(b"[win32k-host] session view reserve refused bytes=0x");
        crate::print_hex_u64(bytes);
        print_str(b" status=0x");
        print_hex(status as u32);
        print_str(b"\n");
        return None;
    }
    if !contains(base) || generation == 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SESSION_VIEW_LABEL, wire::OP_RESERVE, base, generation]);
    }
    Some((base, generation))
}

/// `MEM_COMMIT` the Section pages covering `[address, address + bytes)` of one view:
/// the page-rounded `(base, bytes)` actually committed.
pub(super) unsafe fn commit(address: u64, bytes: u64) -> Result<(u64, u64), i32> {
    let (status, base, committed) = call(wire::OP_COMMIT, address, bytes);
    if status != 0 {
        return Err(status);
    }
    if base > address || base.checked_add(committed).is_none_or(|end| end < address + bytes) {
        crate::provider_bugcheck::report(0xc4, [W32_SESSION_VIEW_LABEL, wire::OP_COMMIT, base, committed]);
    }
    Ok((base, committed))
}

/// Delete a Section's pages and free its view.
pub(super) unsafe fn release(base: u64, generation: u64) -> i32 {
    call(wire::OP_RELEASE, base, generation).0
}
