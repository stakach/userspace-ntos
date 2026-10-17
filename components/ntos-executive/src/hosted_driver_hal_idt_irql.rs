//! HAL IDT conversion against the PnP interrupt resource admitted to this driver.

use super::*;

/// `KIRQL HalConvertDeviceIdtToIrql(ULONG IdtEntry)`.
pub(super) extern "win64" fn hal_convert_device_idt_to_irql(idt_entry: u32) -> u8 {
    let (vector, policy) = unsafe {
        (
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32),
            read_volatile((FSD_SHARED_VADDR + SH_RESOURCE_INTERRUPT_POLICY) as *const u64),
        )
    };
    let irql = policy as u8;
    if !unsafe { hosted_resource_identity_active() } || vector == 0 || idt_entry != vector || irql == 0 {
        // KIRQL has no failure status. An ungranted vector must not gain a fabricated IRQL.
        unsafe { crate::provider_bugcheck::report(0xc4, [0x4849_4454, idt_entry as u64, vector as u64, policy]); }
    }
    irql
}
