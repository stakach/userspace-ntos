//! Source-backed NT kernel imports required by the released PCI bus driver.

use super::*;
use nt_kernel_exec::ipi_broadcast::{admit, IpiAdmission};

pub(crate) const IPI_PREFLIGHT_LABEL: u64 = 0x7D8;
const IPI_LEVEL: u8 = 14; // x64 WDK IPI_LEVEL

/// Authenticate a worker against the exact live image publication before raising IRQL.
/// The reply carries the image bounds and boot topology; neither is trusted from the
/// component's mutable shared page. A lost reply has no native effect and is not replayed.
pub(crate) fn ipi_preflight(
    channel: &crate::spawn_hosts::PumpChannel,
    callback: u64,
    badge: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let Some(image) = (unsafe {
        hosted_driver_process_notify::published_image_for_callback(index, inst, callback)
    }) else {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    };
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire);
    if admit(count, callback, image.run_base, image.image_len) == IpiAdmission::InvalidTopology {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    (STATUS_SUCCESS, image.run_base, image.image_len, count)
}

/// `ULONG_PTR KeIpiGenericCall(PKIPI_BROADCAST_WORKER, ULONG_PTR)`.
pub(super) extern "win64" fn ke_ipi_generic_call(callback: u64, argument: u64) -> u64 {
    let (words, raw, base, len, count) = unsafe {
        call_on4_raw((IPI_PREFLIGHT_LABEL << 12) | 4, callback, 0, 0, 0)
    };
    let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if words != 4 || !canonical || raw as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [IPI_PREFLIGHT_LABEL, callback, words, raw]); }
    }
    match admit(count, callback, base, len) {
        IpiAdmission::Local => {},
        IpiAdmission::NeedsBroadcast => unsafe {
            // A local invocation on SMP would allow PCI's barrier worker to return
            // before all processors have observed its critical hardware operation.
            crate::provider_bugcheck::report(0xc4, [IPI_PREFLIGHT_LABEL, callback, count, 2]);
        },
        IpiAdmission::InvalidCallback | IpiAdmission::InvalidTopology => unsafe {
            crate::provider_bugcheck::report(0xc4, [IPI_PREFLIGHT_LABEL, callback, count, 3]);
        },
    }
    let old_irql = unsafe { hosted_current_irql() };
    if old_irql >= IPI_LEVEL {
        unsafe { crate::provider_bugcheck::report(0xc4, [IPI_PREFLIGHT_LABEL, callback, old_irql as u64, 4]); }
    }
    unsafe {
        hosted_raise_irql(IPI_LEVEL);
        let result = call_hosted_pe(callback, &[argument]);
        hosted_lower_irql(old_irql);
        result
    }
}

pub(crate) fn bind_pci_kernel_exports(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("KdDisableDebugger", hosted_kd_debug::s_kd_disable_debugger as usize as u64);
    reg.bind("KdEnableDebugger", hosted_kd_debug::s_kd_enable_debugger as usize as u64);
    reg.bind("KeQueryActiveProcessorCountEx", hosted_driver_processor_mask::query_active_processor_count_ex as usize as u64);
    reg.bind("KeIpiGenericCall", ke_ipi_generic_call as usize as u64);
}
