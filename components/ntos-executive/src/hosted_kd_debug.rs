//! Driver-visible kernel debugger control import.
//!
//! Import admission must not imply an available debugger. This seven-argument
//! adapter rejects unsupported operations without reading or writing guest
//! buffers, registering callbacks, or reporting synthetic success.

use core::sync::atomic::{AtomicBool, Ordering};

static FIRST_INVOCATION_TRACED: AtomicBool = AtomicBool::new(false);

/// No kernel-debugger transport is registered by this host. Process debug
/// ports are a different NT facility and do not change the KD presence byte.
pub(super) const fn kernel_debugger_connected() -> bool { false }

/// `NTSTATUS KdDisableDebugger(void)` when no kernel-debug transport is registered.
pub(super) extern "win64" fn s_kd_disable_debugger() -> i32 {
    if kernel_debugger_connected() {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x4b44_4449, 0, 0, 0]); }
    }
    nt_compat_exports::kd_debug_control::status_without_transport()
}

/// `NTSTATUS KdEnableDebugger(void)` when no kernel-debug transport is registered.
pub(super) extern "win64" fn s_kd_enable_debugger() -> i32 {
    if kernel_debugger_connected() {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x4b44_454e, 0, 0, 0]); }
    }
    nt_compat_exports::kd_debug_control::status_without_transport()
}

pub(super) extern "win64" fn s_kd_system_debug_control(
    command: u32,
    _input_buffer: u64,
    _input_buffer_length: u32,
    _output_buffer: u64,
    _output_buffer_length: u32,
    _return_length: u64,
    _previous_mode: u8,
) -> i32 {
    let status = nt_compat_exports::kd_debug_control::classify_command(command);
    if !FIRST_INVOCATION_TRACED.swap(true, Ordering::Relaxed) {
        super::print_str(b"[kd-debug-control] first invocation command=0x");
        super::print_hex(command);
        super::print_str(b" status=0x");
        super::print_hex(status as u32);
        super::print_str(b"\n");
    }
    status
}
