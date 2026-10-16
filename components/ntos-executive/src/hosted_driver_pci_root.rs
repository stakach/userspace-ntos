//! HAL PCI root bridge configuration across the isolated driver boundary.

use super::*;
use nt_pnp::acpi_hal_pci_root::{
    PciRootDescriptor, PciRootLedger, PciRootOwner, HAL_ACPI_PCI_ROOT_INFO_BYTES,
};

pub(crate) const LABEL: u64 = 0x7CA;
static mut ROOTS: Option<PciRootLedger> = None;

fn owner(inst: DriverInstance) -> PciRootOwner {
    PciRootOwner {
        domain_id: inst.hosted_domain_id,
        domain_cookie: inst.hosted_domain_cookie,
        vspace: inst.pml4,
    }
}

/// `VOID HalpConfigurePciRootBridge(const HAL_ACPI_PCI_ROOT_INFO *Info)`.
/// The pinned structure contains BusRangePresent and MemoryWindow among its
/// windows. A VOID call cannot report a rejected publication to ACPI, so a
/// failed or uncertain transfer is terminal for this driver domain.
pub(super) extern "win64" fn halp_configure_pci_root_bridge(info: *const u8) {
    if info.is_null() {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, 0, 0, 0]); }
    }
    unsafe {
        let _guard = component_device_reply_lock();
        core::ptr::copy_nonoverlapping(
            info,
            FSD_ARG_VADDR as *mut u8,
            HAL_ACPI_PCI_ROOT_INFO_BYTES,
        );
        let (words, raw, out1, out2, out3) = call_on4_raw((LABEL << 12) | 4, 0, 0, 0, 0);
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || out1 != 0 || out2 != 0 || out3 != 0
            || raw as u32 as i32 != STATUS_SUCCESS
        {
            crate::provider_bugcheck::report(0xc4, [LABEL, words, raw, 0]);
        }
    }
}

pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    badge: u64,
    reply_cap: u64,
) -> i32 {
    let Some((index, inst)) = instance_for_pump_channel(channel, reply_cap) else {
        return STATUS_INVALID_HANDLE;
    };
    if hosted_driver_caller(index, inst, badge).is_none() || inst.exec_arg_va == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let mut bytes = [0u8; HAL_ACPI_PCI_ROOT_INFO_BYTES];
    unsafe {
        core::ptr::copy_nonoverlapping(
            inst.exec_arg_va as *const u8,
            bytes.as_mut_ptr(),
            HAL_ACPI_PCI_ROOT_INFO_BYTES,
        );
    }
    let Ok(root) = PciRootDescriptor::decode(&bytes) else {
        return STATUS_INVALID_PARAMETER;
    };
    unsafe {
        let ledger = (&mut *core::ptr::addr_of_mut!(ROOTS)).get_or_insert_with(PciRootLedger::new);
        match ledger.publish(owner(inst), root) {
            Ok(()) => STATUS_SUCCESS,
            Err(nt_pnp::acpi_hal_pci_root::PciRootError::NoMemory) => STATUS_INSUFFICIENT_RESOURCES,
            Err(_) => STATUS_INVALID_PARAMETER,
        }
    }
}

/// Called only after all domain ingress has stopped and before VSpace release.
pub(crate) unsafe fn retire(inst: DriverInstance) {
    if let Some(ledger) = (&mut *core::ptr::addr_of_mut!(ROOTS)).as_mut() {
        ledger.retire(owner(inst));
    }
}
