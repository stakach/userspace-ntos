//! Native `IoInitializeIrp` and `IoReuseIrp` entry points.
//!
//! The root service owns the packet write under its source-ledger and pool locks. A
//! component-side check followed by a local write could race a forwarded IRP owner.

use super::*;

const INITIALIZE: u64 = 12;
const REUSE: u64 = 13;

fn current_apc_environment() -> u8 {
    let thread = s_current_thread();
    if thread == 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_SOURCE_IRP_LABEL, 0, 0, 0]); }
    }
    let index = unsafe {
        read_volatile((thread + nt_kernel_abi::ps_hosted_x64::KTHREAD_APC_STATE_INDEX as u64) as *const u8)
    };
    if index > 1 {
        unsafe { crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_SOURCE_IRP_LABEL, 0, thread, index as u64]); }
    }
    index
}

fn commit(operation: u64, irp: u64, third: u64, fourth: u64) {
    let (label, status, _, _, _) = unsafe {
        call_on4((FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4,
            operation, irp, third, fourth)
    };
    if label != 0 || status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4,
            [FSD_SERVICE_SOURCE_IRP_LABEL, operation, irp, status]); }
    }
}

/// `VOID IoInitializeIrp(PIRP Irp, USHORT PacketSize, CCHAR StackSize)`.
pub(super) extern "win64" fn io_initialize_irp(irp: u64, packet_size: u16, stack_size: i8) {
    let apc = current_apc_environment();
    commit(INITIALIZE, irp, u64::from(packet_size),
        (stack_size as u8 as u64) | (u64::from(apc) << 8));
}

/// `VOID IoReuseIrp(PIRP Irp, NTSTATUS Status)`.
pub(super) extern "win64" fn io_reuse_irp(irp: u64, status: i32) {
    let apc = current_apc_environment();
    commit(REUSE, irp, status as u32 as u64, u64::from(apc));
}

pub(super) fn bind(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("IoInitializeIrp", io_initialize_irp as usize as u64);
    reg.bind("IoReuseIrp", io_reuse_irp as usize as u64);
}
