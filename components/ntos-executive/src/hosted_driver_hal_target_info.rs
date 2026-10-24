//! HAL interrupt target descriptor for the released ACPI one-argument Win64 ABI.

use super::*;

const HAL_INTERRUPT_TARGET_INFORMATION_VERSION: u32 = 1;

#[allow(non_snake_case)]
#[repr(C)]
struct HalInterruptTargetInformation {
    Version: u32,
    TargetProcessors: u64,
    ProcessorNumber: u32,
    DestinationId: u32,
}

const _: () = assert!(core::mem::size_of::<HalInterruptTargetInformation>() == 24);
const _: () = assert!(core::mem::offset_of!(HalInterruptTargetInformation, TargetProcessors) == 8);
const _: () = assert!(core::mem::offset_of!(HalInterruptTargetInformation, ProcessorNumber) == 16);
const _: () = assert!(core::mem::offset_of!(HalInterruptTargetInformation, DestinationId) == 20);

/// `NTSTATUS HalGetInterruptTargetInformation(PHAL_INTERRUPT_TARGET_INFORMATION)`.
pub(super) extern "win64" fn hal_get_interrupt_target_information(info: u64) -> i32 {
    if info == 0 || info.checked_add(core::mem::size_of::<HalInterruptTargetInformation>() as u64).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    let requested_version = unsafe { read_unaligned(info as *const u32) };
    let requested_mask = unsafe { read_unaligned((info + 8) as *const u64) };
    let active = hosted_driver_processor_mask::active_processor_mask(
        crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire),
    );
    if requested_version != HAL_INTERRUPT_TARGET_INFORMATION_VERSION
        || requested_mask == 0 || requested_mask & !active != 0
    {
        return STATUS_INVALID_PARAMETER;
    }
    // The hosted processor model currently publishes one logical CPU. For multiple targets,
    // this component has no per-CPU APIC destination authority and must refuse the request.
    if active != 1 || requested_mask != 1 {
        return STATUS_NOT_SUPPORTED;
    }
    let apic_id = unsafe { (core::arch::x86_64::__cpuid(1).ebx >> 24) & 0xff };
    unsafe {
        write_unaligned((info + 8) as *mut u64, 1);
        write_unaligned((info + 16) as *mut u32, 0);
        write_unaligned((info + 20) as *mut u32, apic_id);
    }
    STATUS_SUCCESS
}
