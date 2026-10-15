//! Capture hosted NT debug messages before the non-IPC serial record boundary.

use super::*;
use nt_printf::record::RecordBuffer;

const NT_DEBUG_BYTES: usize = 512;

unsafe fn capture_prefix(prefix: u64, output: &mut RecordBuffer<NT_DEBUG_BYTES>) {
    if prefix == 0 {
        return;
    }
    for offset in 0..NT_DEBUG_BYTES {
        let byte = read_volatile((prefix + offset as u64) as *const u8);
        if byte == 0 || !output.push_bytes(&[byte]) {
            return;
        }
    }
    let _ = output.push_bytes(b"?");
}

unsafe fn format_debug_driver<A: nt_printf::Arguments>(prefix: u64, fmt: u64, args: &mut A) -> i32 {
    if fmt == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut output = RecordBuffer::<NT_DEBUG_BYTES>::new();
    capture_prefix(prefix, &mut output);
    let formatted = nt_printf::format_narrow(fmt as *const u8, args, &mut output);
    if formatted.is_err() && !output.overflowed() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut bytes = [0u8; NT_DEBUG_BYTES];
    let length = output.len();
    bytes[..length].copy_from_slice(output.bytes());
    if output.overflowed() {
        let marker = b"[record-truncated]\n";
        bytes[length - marker.len()..length].copy_from_slice(marker);
    }
    sel4_rt::print_record(&bytes[..length]);
    STATUS_SUCCESS
}

#[no_mangle]
extern "win64" fn s_dbg_print_body(fmt: u64, a0: u64, a1: u64, a2: u64, caller_rsp: u64) -> i32 {
    let mut args = Win64PrintfArguments::new([a0, a1, a2], 3, caller_rsp);
    unsafe { format_debug_driver(0, fmt, &mut args) }
}

#[no_mangle]
extern "win64" fn s_dbg_print_ex_body(
    _component_id: u64,
    _level: u64,
    fmt: u64,
    a0: u64,
    caller_rsp: u64,
) -> i32 {
    let mut args = Win64PrintfArguments::new([a0, 0, 0], 1, caller_rsp);
    unsafe { format_debug_driver(0, fmt, &mut args) }
}

#[no_mangle]
extern "win64" fn s_video_port_debug_print_body(
    _level: u64,
    fmt: u64,
    a0: u64,
    a1: u64,
    caller_rsp: u64,
) -> i32 {
    let mut args = Win64PrintfArguments::new([a0, a1, 0], 2, caller_rsp);
    unsafe { format_debug_driver(0, fmt, &mut args) }
}

pub(super) extern "win64" fn s_vdbg_print_ex(
    _component_id: u32,
    _level: u32,
    fmt: u64,
    va_list: u64,
) -> i32 {
    let mut args = VaListPrintfArguments { cursor: va_list };
    unsafe { format_debug_driver(0, fmt, &mut args) }
}

pub(super) extern "win64" fn s_vdbg_print_ex_with_prefix(
    prefix: u64,
    _component_id: u32,
    _level: u32,
    fmt: u64,
    va_list: u64,
) -> i32 {
    let mut args = VaListPrintfArguments { cursor: va_list };
    unsafe { format_debug_driver(prefix, fmt, &mut args) }
}
