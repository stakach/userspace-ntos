//! PCI HAL exports backed by the accepted ACPI route owner.
//!
//! LiberNT's PCI driver queries a supplied INTx pin, including a bridge-swizzled
//! pin, instead of always using the device's config-space InterruptPin. The
//! query crosses to the root-owned PCI topology; an unaccepted or stale route
//! can never become a fabricated GSI.

use super::*;

pub(crate) const ROUTED_INTERRUPT_LABEL: u64 = 0x7D7;

/// `BOOLEAN HalQueryPciRoutedInterrupt(ULONG Segment, ULONG Bus, ULONG Device,
/// ULONG Function, ULONG Pin, PULONG Gsi)`.
extern "win64" fn hal_query_pci_routed_interrupt(
    segment: u32,
    bus: u32,
    device: u32,
    function: u32,
    pin: u32,
    gsi_out: u64,
) -> u8 {
    if gsi_out == 0 || segment > u16::MAX as u32 || bus > u8::MAX as u32
        || device >= 32 || function >= 8 || !(1..=4).contains(&pin)
    {
        return 0;
    }
    let address = (device as u64) | ((function as u64) << 32);
    let (words, found, gsi, unused2, unused3) = unsafe {
        call_on4_raw(
            (ROUTED_INTERRUPT_LABEL << 12) | 4,
            segment as u64,
            bus as u64,
            address,
            pin as u64,
        )
    };
    if words != 4 || found != 1 || gsi > u32::MAX as u64 || unused2 != 0 || unused3 != 0 {
        return 0;
    }
    unsafe { write_unaligned(gsi_out as *mut u32, gsi as u32); }
    1
}

/// Pinned LiberNT `HAL_MESSAGE_ROUTING_INFO` v1, x64.
#[repr(C)]
struct HalMessageRoutingInfo {
    version: u32,
    flags: u32,
    desired_irql: u8,
    _pad0: [u8; 3],
    message_count: u32,
    vector: u32,
    irql: u8,
    _pad1: [u8; 3],
    target_processors: u64,
    destination_id: u32,
    _pad2: [u8; 4],
    message_address: u64,
    message_data: u16,
    reserved: u16,
    _pad3: [u8; 4],
}

const _: () = {
    assert!(core::mem::size_of::<HalMessageRoutingInfo>() == 56);
    assert!(core::mem::offset_of!(HalMessageRoutingInfo, vector) == 16);
    assert!(core::mem::offset_of!(HalMessageRoutingInfo, target_processors) == 24);
    assert!(core::mem::offset_of!(HalMessageRoutingInfo, message_address) == 40);
    assert!(core::mem::offset_of!(HalMessageRoutingInfo, message_data) == 48);
};

/// `NTSTATUS HalpGetMessageRoutingInfo(PHAL_MESSAGE_ROUTING_INFO)`.
/// rust-micro's X86IRQIssueIRQHandlerMSI rejects all MSI handler issuance until
/// MSI programming/remapping has a real owner. Returning an address or vector
/// here would cause a driver to program undeliverable device interrupts.
extern "win64" fn halp_get_message_routing_info(info: u64) -> i32 {
    if info == 0 || info.checked_add(core::mem::size_of::<HalMessageRoutingInfo>() as u64).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    let version = unsafe { read_unaligned(info as *const u32) };
    let flags = unsafe { read_unaligned((info + 4) as *const u32) };
    let message_count = unsafe { read_unaligned((info + 12) as *const u32) };
    let vector = unsafe { read_unaligned((info + 16) as *const u32) };
    if version != 1 || flags & !3 != 0 || flags == 3
        || (flags == 2 && (message_count != 1 || vector > u8::MAX as u32))
        || (flags == 0 && vector == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_NOT_SUPPORTED
}

pub(crate) fn bind_pci_hal_exports(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("HalQueryPciRoutedInterrupt", hal_query_pci_routed_interrupt as *const () as usize as u64);
    reg.bind("HalpGetInterruptTargetInformation",
        hosted_driver_hal_target_info::hal_get_interrupt_target_information as *const () as usize as u64);
    reg.bind("HalpGetMessageRoutingInfo", halp_get_message_routing_info as *const () as usize as u64);
}

/// Authenticate the hosted caller before observing the current root-owned route.
pub(crate) fn service_routed_interrupt(
    ch: &crate::spawn_hosts::PumpChannel,
    segment: u64,
    bus: u64,
    address: u64,
    pin: u64,
    badge: u64,
    active_reply_cap: u64,
) -> (u64, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return (0, 0);
    };
    if hosted_driver_caller(index, inst, badge).is_none()
        || segment > u16::MAX as u64 || bus > u8::MAX as u64
        || (address as u32) >= 32 || (address >> 32) >= 8
        || !(1..=4).contains(&pin)
    {
        return (0, 0);
    }
    let location = nt_pnp::PciLocation {
        bus: bus as u8,
        device: address as u8,
        function: (address >> 32) as u8,
    };
    match unsafe { hosted_pci_topology::query_hosted_pci_routed_interrupt(segment as u16, location, pin as u8) } {
        Some(gsi) => (1, gsi as u64),
        None => (0, 0),
    }
}
