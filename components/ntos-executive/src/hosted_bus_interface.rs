//! Executive-owned PCI BUS_INTERFACE_STANDARD for an exact accepted PDO.
//!
//! A consumer receives only a monotonically allocated lease as opaque Context and callbacks
//! compiled into its own host. Every hardware operation revalidates the accepted provider,
//! consumer projection, PnP context generation, and assigned PCI BDF in root. No provider-domain
//! pointer or callback is serialized into the consumer.

use super::*;
use nt_io_manager::bus_interface::BusInterfaceCatalog;
use nt_pnp_abi::{BusInterfaceQueryRequest, BUS_INTERFACE_STANDARD_X64_SIZE, GUID_BUS_INTERFACE_STANDARD};
use nt_pnp_manager::AcceptedPdoProviderAuthority;

pub(super) const LABEL: u64 = 0x7EE;
const QUERY: u64 = 1;
const REFERENCE: u64 = 2;
const DEREFERENCE: u64 = 3;
const VALIDATE: u64 = 4;
const READ_CONFIG: u64 = 5;
const WRITE_CONFIG: u64 = 6;
const PCI_WHICHSPACE_CONFIG: u32 = 0;
const PCI_SLOT_DEVICE_MASK: u32 = 0x1f;
const INTERFACE_TYPE_OFFSET: u64 = 0x08;
const INTERFACE_SIZE_OFFSET: u64 = 0x10;
const INTERFACE_VERSION_OFFSET: u64 = 0x12;
const INTERFACE_POINTER_OFFSET: u64 = 0x18;

#[derive(Clone, Copy)]
struct Row {
    lease_id: u64,
    consumer_instance: usize,
    binding: HostedDeviceBinding,
    provider: AcceptedPdoProviderAuthority,
    bus_number: u32,
    slot_number: u32,
    pci_vendor_device: u32,
    pnp_context_lease: nt_pnp_context::ContextLeaseIdentity,
}

static mut CATALOG: Option<BusInterfaceCatalog> = None;
static mut ROWS: Vec<Row> = Vec::new();

unsafe fn catalog() -> &'static mut BusInterfaceCatalog {
    let slot = &mut *core::ptr::addr_of_mut!(CATALOG);
    if slot.is_none() { *slot = Some(BusInterfaceCatalog::new()); }
    slot.as_mut().unwrap()
}

fn slot_number(address: u32) -> Option<u32> {
    let device = address >> 16;
    let function = address & 7;
    if device > PCI_SLOT_DEVICE_MASK || address & 0xffe0_fff8 != 0 { return None; }
    Some(device | (function << 5))
}

unsafe fn consumer_binding(
    instance: usize, domain: HostedDomainIdentity, pdo_object: u64, pdo_id: u64,
) -> Option<HostedDeviceBinding> {
    hosted_device_bindings()?.iter().copied().find(|binding| {
        binding.used
            && binding.projection_instance == instance
            && binding.projection_domain == domain
            && binding.pdo_object == pdo_object
            && binding.pdo_device_id == pdo_id
    })
}

unsafe fn current_row(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    consumer: HostedDomainIdentity,
    lease_id: u64,
) -> Result<Row, nt_status::NtStatus> {
    let row = (*core::ptr::addr_of!(ROWS)).iter().copied()
        .find(|row| row.lease_id == lease_id)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let (instance_index, inst, pdo) = authenticated_hosted_pdo(
        ch, row.binding.pdo_object, reply_cap,
    )?;
    if instance_index != row.consumer_instance
        || instance_domain_identity(inst) != Some(consumer)
        || pdo.raw() != row.binding.pdo_device_id
        || consumer_binding(instance_index, consumer, row.binding.pdo_object, pdo.raw())
            != Some(row.binding)
        || catalog().provider(io_manager_mut(), consumer, lease_id)? != row.provider.provider()
        || hosted_accepted_pdo_provider_catalog().resolve(
            hosted_pnp_manager_mut(), hosted_bus_relations(), io_manager_mut(), pdo.raw(),
        ).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)? != row.provider
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let state = hosted_device_resource_state_by_device_id(row.binding.device_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if state.instance != row.binding.instance
        || state.projection_domain != consumer
        || state.pdo_object != row.binding.pdo_object
        || state.interface_type != HOSTED_INTERFACE_TYPE_PCIBUS
        || state.bus_number != row.bus_number
        || slot_number(state.address) != Some(row.slot_number)
        || state.pci_vendor_device != row.pci_vendor_device
        || state.pnp_context_lease != Some(row.pnp_context_lease)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(row)
}

unsafe fn issue(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    pdo_object: u64,
    request: BusInterfaceQueryRequest,
) -> Result<u64, nt_status::NtStatus> {
    let (consumer_instance, inst, pdo) = authenticated_hosted_pdo(ch, pdo_object, reply_cap)?;
    let consumer = instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
    let binding = consumer_binding(consumer_instance, consumer, pdo_object, pdo.raw())
        .ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
    let provider = hosted_accepted_pdo_provider_catalog().resolve(
        hosted_pnp_manager_mut(), hosted_bus_relations(), io_manager_mut(), pdo.raw(),
    ).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let state = hosted_device_resource_state_by_device_id(binding.device_id)
        .filter(|state| state.instance == binding.instance
            && state.projection_domain == consumer
            && state.pdo_object == pdo_object
            && state.interface_type == HOSTED_INTERFACE_TYPE_PCIBUS)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let slot_number = slot_number(state.address)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let pnp_context_lease = state.pnp_context_lease
        .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    (*core::ptr::addr_of_mut!(ROWS)).try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let reply = catalog().issue_executive_pci(
        io_manager_mut(), consumer, provider.provider(), request,
    )?;
    (*core::ptr::addr_of_mut!(ROWS)).push(Row {
        lease_id: reply.lease_id,
        consumer_instance,
        binding,
        provider,
        bus_number: state.bus_number,
        slot_number,
        pci_vendor_device: state.pci_vendor_device,
        pnp_context_lease,
    });
    Ok(reply.lease_id)
}

fn callback(op: u64, value1: u64, value2: u64, value3: u64) -> (i32, u64, u64) {
    let (label, status, result1, result2, _) = unsafe {
        call_on4((LABEL << 12) | 4, op, value1, value2, value3)
    };
    if label != 0 { return (STATUS_INVALID_DEVICE_REQUEST, 0, 0); }
    (status as u32 as i32, result1, result2)
}

fn callback_valid(lease_id: u64) -> Option<(u64, u32)> {
    let (status, pdo, bus) = callback(VALIDATE, lease_id, 0, 0);
    (status == STATUS_SUCCESS && pdo != 0 && bus <= u8::MAX as u64)
        .then_some((pdo, bus as u32))
}

extern "win64" fn interface_reference(context: u64) {
    let (status, _, _) = callback(REFERENCE, context, 0, 0);
    if status != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, REFERENCE, context, status as u32 as u64]); }
    }
}

extern "win64" fn interface_dereference(context: u64) {
    let (status, _, _) = callback(DEREFERENCE, context, 0, 0);
    if status != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, DEREFERENCE, context, status as u32 as u64]); }
    }
}

extern "win64" fn translate_bus_address(
    context: u64, address: u64, _length: u32, address_space: u64, translated: u64,
) -> u8 {
    if address_space == 0 || translated == 0 { return 0; }
    let Some((_, bus)) = callback_valid(context) else { return 0; };
    s_hal_translate_bus_address(HOSTED_INTERFACE_TYPE_PCIBUS, bus, address, address_space, translated)
}

extern "win64" fn get_dma_adapter(context: u64, description: u64, registers: *mut u32) -> u64 {
    let Some((pdo, _)) = callback_valid(context) else { return 0; };
    project_hosted_dma_adapter(pdo, description, registers)
}

fn config_data(context: u64, data_type: u32, buffer: u64, offset: u32, length: u32, op: u64) -> u32 {
    if context == 0 || buffer == 0 || length == 0 || length > 0x100
        || offset > 0xff || data_type != PCI_WHICHSPACE_CONFIG
            && data_type != BUS_DATA_TYPE_PCI_CONFIGURATION
    {
        return 0;
    }
    let range = data_type as u64 | ((offset as u64) << 16) | ((length as u64) << 32);
    let (status, transferred, _) = callback(op, context, buffer, range);
    if status == STATUS_SUCCESS && transferred <= length as u64 { transferred as u32 } else { 0 }
}

extern "win64" fn set_bus_data(context: u64, data_type: u32, buffer: u64, offset: u32, length: u32) -> u32 {
    config_data(context, data_type, buffer, offset, length, WRITE_CONFIG)
}

extern "win64" fn get_bus_data(context: u64, data_type: u32, buffer: u64, offset: u32, length: u32) -> u32 {
    config_data(context, data_type, buffer, offset, length, READ_CONFIG)
}

/// Handles only GUID_BUS_INTERFACE_STANDARD. Other interface GUIDs keep their existing path.
pub(super) unsafe fn try_query_interface(device: u64, irp: u64, next: u64, previous_location: u8)
    -> Option<i32>
{
    let guid_ptr = read_unaligned((next + INTERFACE_TYPE_OFFSET) as *const u64);
    if guid_ptr == 0 || guid_ptr.checked_add(15).is_none()
        || s_mm_is_address_valid(guid_ptr) == 0
        || s_mm_is_address_valid(guid_ptr + 15) == 0
    {
        return Some(complete_query(device, irp, next, previous_location, STATUS_INVALID_PARAMETER));
    }
    let mut guid = [0u8; 16];
    core::ptr::copy_nonoverlapping(guid_ptr as *const u8, guid.as_mut_ptr(), 16);
    if guid != GUID_BUS_INTERFACE_STANDARD { return None; }
    let size = read_unaligned((next + INTERFACE_SIZE_OFFSET) as *const u16);
    let version = read_unaligned((next + INTERFACE_VERSION_OFFSET) as *const u16);
    let interface = read_unaligned((next + INTERFACE_POINTER_OFFSET) as *const u64);
    let status = if version < 1 {
        nt_status::NtStatus::NOT_SUPPORTED.raw()
    } else if size < BUS_INTERFACE_STANDARD_X64_SIZE {
        nt_status::NtStatus::BUFFER_TOO_SMALL.raw()
    } else if interface == 0
        || interface.checked_add(BUS_INTERFACE_STANDARD_X64_SIZE as u64 - 1).is_none()
        || s_mm_is_address_valid(interface) == 0
        || s_mm_is_address_valid(interface + BUS_INTERFACE_STANDARD_X64_SIZE as u64 - 1) == 0
    {
        STATUS_INVALID_PARAMETER
    } else {
        let (status, lease, _) = callback(QUERY, device, irp,
            size as u64 | ((version as u64) << 16));
        if status == STATUS_SUCCESS && lease != 0 {
            core::ptr::write_bytes(interface as *mut u8, 0, BUS_INTERFACE_STANDARD_X64_SIZE as usize);
            write_unaligned(interface as *mut u16, BUS_INTERFACE_STANDARD_X64_SIZE);
            write_unaligned((interface + 2) as *mut u16, 1);
            write_unaligned((interface + 8) as *mut u64, lease);
            write_unaligned((interface + 0x10) as *mut u64, interface_reference as *const () as u64);
            write_unaligned((interface + 0x18) as *mut u64, interface_dereference as *const () as u64);
            write_unaligned((interface + 0x20) as *mut u64, translate_bus_address as *const () as u64);
            write_unaligned((interface + 0x28) as *mut u64, get_dma_adapter as *const () as u64);
            write_unaligned((interface + 0x30) as *mut u64, set_bus_data as *const () as u64);
            write_unaligned((interface + 0x38) as *mut u64, get_bus_data as *const () as u64);
            STATUS_SUCCESS
        } else if status == STATUS_SUCCESS { STATUS_INVALID_DEVICE_REQUEST } else { status }
    };
    Some(complete_query(device, irp, next, previous_location, status))
}

unsafe fn complete_query(device: u64, irp: u64, next: u64, previous_location: u8, status: i32) -> i32 {
    write_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8, previous_location - 1);
    write_unaligned((irp + 0xb8) as *mut u64, next);
    write_unaligned((next + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *mut u64, device);
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32, status);
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64, 0);
    s_io_complete_request(irp, 0);
    status
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    op: u64,
    value1: u64,
    value2: u64,
    value3: u64,
) -> (i32, u64, u64) {
    let Some((instance_index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0, 0);
    };
    let Some(caller) = hosted_driver_caller(instance_index, inst, caller_badge) else {
        return (STATUS_ACCESS_DENIED, 0, 0);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return (STATUS_ACCESS_DENIED, 0, 0);
    }
    let Some(consumer) = instance_domain_identity(inst) else { return (STATUS_ACCESS_DENIED, 0, 0); };
    unsafe {
        match op {
            QUERY => {
                let size = value3 as u16;
                let version = (value3 >> 16) as u16;
                if value3 >> 32 != 0 || value2 == 0 || size < BUS_INTERFACE_STANDARD_X64_SIZE
                    || version < 1
                {
                    return (STATUS_INVALID_PARAMETER, 0, 0);
                }
                let Some((source_ticket, _)) = hosted_source_irp_ledger::pin(
                    instance_index, consumer, value2,
                ) else { return (STATUS_INVALID_DEVICE_REQUEST, 0, 0); };
                let request = BusInterfaceQueryRequest { size, version,
                    interface_type: GUID_BUS_INTERFACE_STANDARD };
                let issued = issue(ch, reply_cap, value1, request);
                if !hosted_source_irp_ledger::unpin(source_ticket) {
                    // The exact source pin and any committed interface remain retained. A lost
                    // unpin cannot justify replay or reusing the lease ID.
                    return (nt_status::NtStatus::DEVICE_BUSY.raw(), 0, 0);
                }
                match issued {
                    Ok(lease) => (STATUS_SUCCESS, lease, 0),
                    Err(status) => (status.raw(), 0, 0),
                }
            }
            REFERENCE => {
                if let Err(status) = current_row(ch, reply_cap, consumer, value1) {
                    return (status.raw(), 0, 0);
                }
                match catalog().reference_executive_pci(io_manager_mut(), consumer, value1) {
                    Ok(()) => (STATUS_SUCCESS, 0, 0), Err(status) => (status.raw(), 0, 0),
                }
            }
            DEREFERENCE => {
                let result = catalog().dereference_executive_pci(io_manager_mut(), consumer, value1);
                if result.is_ok() && catalog().provider(io_manager_mut(), consumer, value1)
                    == Err(nt_status::NtStatus::INVALID_PARAMETER)
                {
                    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
                    if let Some(index) = rows.iter().position(|row| row.lease_id == value1) {
                        rows.swap_remove(index);
                    }
                }
                match result { Ok(()) => (STATUS_SUCCESS, 0, 0), Err(status) => (status.raw(), 0, 0) }
            }
            VALIDATE | READ_CONFIG | WRITE_CONFIG => {
                let row = match current_row(ch, reply_cap, consumer, value1) {
                    Ok(row) => row, Err(status) => return (status.raw(), 0, 0),
                };
                if op == VALIDATE {
                    return (STATUS_SUCCESS, row.binding.pdo_object, row.bus_number as u64);
                }
                let data_type = value3 as u16 as u32;
                let offset = (value3 >> 16) as u16 as u32;
                let length = (value3 >> 32) as u32;
                if data_type != PCI_WHICHSPACE_CONFIG
                    && data_type != BUS_DATA_TYPE_PCI_CONFIGURATION
                {
                    return (STATUS_INVALID_PARAMETER, 0, 0);
                }
                let access = match nt_pnp::validate_pci_config_access(
                    row.bus_number, row.slot_number, offset, length,
                ) { Ok(access) if access.length != 0 => access,
                    _ => return (STATUS_INVALID_PARAMETER, 0, 0), };
                let exec_buffer = component_to_exec_va_for_instance(
                    instance_index, inst, value2, access.length as u64,
                ).or_else(|| caller.runtime.and_then(|worker| hosted_worker_component_to_exec_va(
                    worker, value2, access.length as u64,
                )));
                let Some(exec_buffer) = exec_buffer else { return (STATUS_INVALID_PARAMETER, 0, 0); };
                let result = if op == READ_CONFIG {
                    crate::pnp::read_pci_config(access, core::slice::from_raw_parts_mut(
                        exec_buffer as *mut u8, access.length as usize,
                    ))
                } else {
                    crate::pnp::write_pci_config(access, core::slice::from_raw_parts(
                        exec_buffer as *const u8, access.length as usize,
                    ))
                };
                match result {
                    Ok(()) => (STATUS_SUCCESS, access.length as u64, 0),
                    Err(status) => (status.raw(), 0, 0),
                }
            }
            _ => (STATUS_INVALID_PARAMETER, 0, 0),
        }
    }
}
