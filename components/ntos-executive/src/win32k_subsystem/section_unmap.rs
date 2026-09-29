//! Exact-process native Section unmap request from win32k.

use super::*;

const LABEL: u64 = W32_SECTION_UNMAP_LABEL;
const UNMAP: u64 = 1;
const ACK: u64 = 2;

unsafe fn call(op: u64, first: u64, second: u64) -> (i32, u64) {
    let (words, raw, token, out2, out3) =
        crate::driver_launch::call_on4_raw((LABEL << 12) | 4, op, first, second, 0);
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4 || !canonical || out2 != 0 || out3 != 0 {
        crate::provider_bugcheck::report(0xc4, [LABEL, op, words, raw]);
    }
    (raw as u32 as i32, token)
}

#[allow(dead_code)] // Bound with the complete Section import lifecycle.
pub(super) extern "win64" fn unmap(process_handle: u64, base_address: u64) -> i32 {
    unsafe {
        let (status, token) = call(UNMAP, process_handle, base_address);
        if token == 0 {
            if status >= 0 {
                crate::provider_bugcheck::report(0xc4, [LABEL, UNMAP, process_handle, base_address]);
            }
            return status;
        }
        let (ack_status, ack_token) = call(ACK, token, base_address);
        if ack_status != 0 || ack_token != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, ACK, token, ack_status as u32 as u64]);
        }
        status
    }
}
