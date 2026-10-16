//! HAL ACPI PCI route callback registration with exact image ownership.

use super::*;
use nt_pnp::acpi_hal_route_callback::{PciRouteCallback, PciRouteCallbackLedger};

pub(crate) const LABEL: u64 = 0x7CB;
static mut CALLBACKS: Option<PciRouteCallbackLedger> = None;

/// `VOID HalpRegisterPciRouteQuery(PHAL_ACPI_PCI_ROUTE_QUERY Provider)`.
/// The callback is an ACPI image pointer; the root binds it to that image's
/// publication generation before accepting the registration.
pub(super) extern "win64" fn halp_register_pci_route_query(callback: u64) {
    unsafe {
        if hosted_current_irql() != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, callback, 1, 0]);
        }
        let (words, raw, out1, out2, out3) =
            call_on4_raw((LABEL << 12) | 4, callback, 0, 0, 0);
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || out1 != 0 || out2 != 0 || out3 != 0
            || raw as u32 as i32 != STATUS_SUCCESS
        {
            // A lost reply may follow a committed registration. Do not replay
            // the VOID call or reuse its image owner.
            crate::provider_bugcheck::report(0xc4, [LABEL, callback, words, raw]);
        }
    }
}

pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    callback: u64,
    badge: u64,
    active_reply_cap: u64,
) -> i32 {
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return STATUS_INVALID_HANDLE;
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    unsafe {
        let ledger = (&mut *core::ptr::addr_of_mut!(CALLBACKS))
            .get_or_insert_with(PciRouteCallbackLedger::new);
        let result = if callback == 0 {
            ledger.unregister(inst.hosted_domain_id, inst.hosted_domain_cookie, inst.pml4)
        } else {
            let Some(image) = hosted_driver_process_notify::published_image_for_callback(index, inst, callback)
            else { return STATUS_INVALID_PARAMETER; };
            ledger.register(PciRouteCallback {
                domain_id: inst.hosted_domain_id,
                domain_cookie: inst.hosted_domain_cookie,
                vspace: inst.pml4,
                image_base: image.run_base,
                image_len: image.image_len,
                image_generation: image.publication_generation,
                callback,
            })
        };
        match result {
            Ok(()) => STATUS_SUCCESS,
            Err(_) => STATUS_INVALID_PARAMETER,
        }
    }
}

/// A registered callback keeps its exact image and domain alive until ACPI
/// explicitly unregisters it. This runs before source image retirement.
pub(crate) unsafe fn blocks_instance_retirement(inst: DriverInstance) -> bool {
    (&*core::ptr::addr_of!(CALLBACKS)).as_ref().is_some_and(|ledger|
        ledger.blocks_retirement(inst.hosted_domain_id, inst.hosted_domain_cookie, inst.pml4))
}
