//! Win32k-owned IRP storage. Catalog pins and the ledger live in this component;
//! the executive cannot infer them from the shared pool header.

use super::*;
use nt_io_manager::kernel_irp_builder::{
    plan_device_io_control_request, validate_kernel_irp_dispatch_cursor,
    validate_new_kernel_irp_packet, KernelIrpDispatchCursor, KernelIrpDispatchHeader,
};
use nt_io_manager::provider_source_irp::{
    ProviderSourceIrpAllocation, ProviderSourceIrpLedger, ProviderSourceIrpTicket,
};
use nt_io_manager::{
    initialize_wdm_irp_thread_list, write_wdm_io_stack_location, write_wdm_irp, WdmIrpInit,
    WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IRP_SIZE,
};
use nt_provider_wait::{ProviderAllocationPin, ProviderAllocationSnapshot};

unsafe fn ledger() -> Option<&'static mut ProviderSourceIrpLedger> {
    (&mut *core::ptr::addr_of_mut!(WIN32K_SOURCE_IRPS)).as_mut()
}

fn packet_bytes(stack_count: u8) -> Option<u64> {
    if stack_count == 0 || stack_count == u8::MAX {
        return None;
    }
    let bytes = WDM_X64_IRP_SIZE + stack_count as usize * WDM_X64_IO_STACK_LOCATION_SIZE;
    (bytes <= u16::MAX as usize).then_some(bytes as u64)
}

/// Undo an unpublished allocation while both metadata and pool locks remain held.
unsafe fn rollback(
    catalog: &mut nt_provider_wait::ProviderAllocationCatalog,
    memory: &mut ProviderPoolMemory,
    native_offset: u64,
    snapshot: Option<ProviderAllocationSnapshot>,
    pin: Option<ProviderAllocationPin>,
) {
    if let Some(snapshot) = snapshot {
        let reserved = if let Some(pin) = pin {
            catalog.begin_retirement_from_pin(pin)
        } else {
            catalog.begin_retirement(snapshot.identity)
        };
        if reserved != Ok(snapshot) {
            print_str(b"[win32k-irp] fatal unpublished catalog rollback failure\n");
            park();
        }
    }
    if shared_pool::free(memory, native_offset).is_err()
        || snapshot.is_some_and(|snapshot| catalog.retire(snapshot.identity) != Ok(snapshot))
    {
        print_str(b"[win32k-irp] fatal unpublished native rollback failure\n");
        park();
    }
}

/// Publish a zeroed WDM packet only after native generation, catalog generation,
/// and the lifetime pin have been registered in one metadata -> pool lock scope.
pub(super) unsafe fn allocate(stack_count: u8) -> Option<(u64, ProviderSourceIrpTicket)> {
    let bytes = packet_bytes(stack_count)?;
    let provider = registered_provider_wait_domain()?;
    let arena = fixed_provider_arena_identity(PROVIDER_ARENA_SHARED_POOL_ID)?;
    let (mut metadata, _pool) = provider_metadata_pool_lock()?;
    let mut memory = ProviderPoolMemory;
    let native = shared_pool::allocate(&mut memory, bytes, true).ok()?;
    let address = WIN32K_POOL_VADDR + native.payload_offset;
    let packet = core::slice::from_raw_parts_mut(address as *mut u8, bytes as usize);
    let initialized = write_wdm_irp(
        packet,
        WdmIrpInit {
            packet_size: bytes as u16,
            stack_count,
            current_location: stack_count + 1,
            current_stack_location: address + bytes,
            ..Default::default()
        },
    )
    .and_then(|_| initialize_wdm_irp_thread_list(packet, address))
    .is_ok()
        && validate_new_kernel_irp_packet(address, packet, stack_count).is_ok();
    let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
        rollback_unpublished_native(&mut memory, native.payload_offset);
        return None;
    };
    if !initialized {
        rollback(catalog, &mut memory, native.payload_offset, None, None);
        return None;
    }
    let Ok(snapshot) = catalog.register(arena, address, native.capacity) else {
        rollback(catalog, &mut memory, native.payload_offset, None, None);
        return None;
    };
    let Ok((pinned, pin)) = catalog.pin_containing(address, bytes) else {
        rollback(
            catalog,
            &mut memory,
            native.payload_offset,
            Some(snapshot),
            None,
        );
        return None;
    };
    if pinned != snapshot {
        rollback(
            catalog,
            &mut memory,
            native.payload_offset,
            Some(snapshot),
            Some(pin),
        );
        return None;
    }
    let allocation = ProviderSourceIrpAllocation {
        provider,
        catalog: snapshot,
        catalog_pin: pin,
        pool_base: WIN32K_POOL_VADDR,
        native: native.identity,
        native_capacity: native.capacity,
        bytes,
        stack_count,
    };
    let Some(ledger) = ledger() else {
        rollback(
            catalog,
            &mut memory,
            native.payload_offset,
            Some(snapshot),
            Some(pin),
        );
        return None;
    };
    match ledger.register(allocation) {
        Ok(ticket) => Some((address, ticket)),
        Err(_) => {
            rollback(
                catalog,
                &mut memory,
                native.payload_offset,
                Some(snapshot),
                Some(pin),
            );
            None
        }
    }
}

/// Construct a win32k-owned, file-less METHOD_BUFFERED request. This publishes
/// no device request; dispatch must retain the source, SystemBuffer, Event, and
/// IOSB before entry. Every failed construction retires its exact allocations.
pub(super) extern "win64" fn build_device_io_control_request(
    code: u32,
    device: u64,
    input: u64,
    input_length: u32,
    output: u64,
    output_length: u32,
    internal: u8,
    event: u64,
    iosb: u64,
) -> u64 {
    unsafe {
        use nt_io_abi::ioctl;
        const MAX_BUFFER: u32 = nt_io_manager::win32k_source_irp_ioctl_wire::MAX_BUFFER_BYTES;
        if ioctl::method(code) != ioctl::METHOD_BUFFERED
            || input_length > MAX_BUFFER
            || output_length > MAX_BUFFER
            || (input_length != 0 && input == 0)
            || (output_length != 0 && output == 0)
            || iosb == 0
            || !provider_pool_contains(device)
            || device
                .checked_add(0x50)
                .is_none_or(|end| end > WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000)
        {
            return 0;
        }
        if crate::driver_launch::win32k_device_pointers::reference(device).is_err() {
            return 0;
        }
        let stack_count = read_unaligned((device + 0x4c) as *const u8);
        if crate::driver_launch::win32k_device_pointers::dereference(device).is_err() {
            crate::provider_bugcheck::report(0xc4, [0x57495250, device, 4, 0]);
        }
        let Ok(plan) = plan_device_io_control_request(
            code,
            internal != 0,
            stack_count,
            device,
            input,
            input_length,
            output,
            output_length,
        ) else {
            return 0;
        };
        let Some((irp, ticket)) = allocate(stack_count) else {
            return 0;
        };
        let system_buffer = if plan.system_buffer_len == 0 {
            0
        } else {
            pool_alloc(u64::from(plan.system_buffer_len))
        };
        if plan.system_buffer_len != 0 && system_buffer == 0 {
            if !retire(irp, ticket) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, irp, 1, 0]);
            }
            return 0;
        }
        if plan.system_buffer_input_len != 0 {
            core::ptr::copy_nonoverlapping(
                input as *const u8,
                system_buffer as *mut u8,
                input_length as usize,
            );
        }
        let stack = irp + plan.next_stack_offset as u64;
        let stack_bytes =
            core::slice::from_raw_parts_mut(stack as *mut u8, WDM_X64_IO_STACK_LOCATION_SIZE);
        if write_wdm_io_stack_location(stack_bytes, plan.stack).is_err() {
            if system_buffer != 0 && !provider_pool_free(system_buffer) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, system_buffer, 2, 0]);
            }
            if !retire(irp, ticket) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, irp, 3, 0]);
            }
            return 0;
        }
        write_unaligned((irp + 0x10) as *mut u32, plan.irp_flags);
        write_unaligned((irp + 0x18) as *mut u64, system_buffer);
        write_unaligned((irp + 0x48) as *mut u64, iosb);
        write_unaligned((irp + 0x50) as *mut u64, event);
        write_unaligned((irp + 0x70) as *mut u64, plan.user_buffer);
        write_unaligned((irp + 0x98) as *mut u64, s_current_thread());
        irp
    }
}

unsafe fn rollback_unpublished_native(memory: &mut ProviderPoolMemory, native_offset: u64) {
    if shared_pool::free(memory, native_offset).is_err() {
        print_str(b"[win32k-irp] fatal unpublished native rollback failure\n");
        park();
    }
}

pub(super) unsafe fn is_source_irp(address: u64) -> bool {
    let _metadata = ProviderMetadataGuard::acquire();
    ledger().is_some_and(|ledger| ledger.allocation_at(WIN32K_POOL_VADDR, address).is_some())
}

#[must_use]
pub(super) struct SourceIrpDispatchLease {
    pub ticket: ProviderSourceIrpTicket,
    pub allocation: ProviderSourceIrpAllocation,
    pub cursor: KernelIrpDispatchCursor,
}

/// Retain the source across a reentrant or pending canonical device dispatch.
/// The provider catalog and native pool identities must still describe this packet.
pub(super) unsafe fn retain_dispatch(address: u64) -> Option<SourceIrpDispatchLease> {
    if !provider_pool_contains(address) {
        return None;
    }
    let (mut metadata, _pool) = provider_metadata_pool_lock()?;
    let (ticket, allocation) = ledger()?.allocation_at(WIN32K_POOL_VADDR, address)?;
    if registered_provider_wait_domain() != Some(allocation.provider)
        || provider_allocations_unlocked(&mut metadata)?
            .snapshot_active(allocation.catalog.identity)
            .ok()?
            != allocation.catalog
    {
        return None;
    }
    let memory = ProviderPoolMemory;
    let offset = address - WIN32K_POOL_VADDR;
    if shared_pool::allocation_identity(&memory, offset) != Ok(allocation.native)
        || shared_pool::allocation_capacity(&memory, offset) != Ok(allocation.native_capacity)
    {
        return None;
    }
    let header = KernelIrpDispatchHeader {
        irp_type: read_volatile(address as *const u16),
        packet_size: read_volatile((address + 2) as *const u16),
        stack_count: read_volatile((address + 0x42) as *const u8),
        current_location: read_volatile((address + 0x43) as *const u8),
        current_stack_location: read_volatile((address + 0xb8) as *const u64),
    };
    let cursor = validate_kernel_irp_dispatch_cursor(
        address,
        allocation.bytes,
        allocation.stack_count,
        header,
    )
    .ok()?;
    ledger()?.pin(ticket, allocation).ok()?;
    Some(SourceIrpDispatchLease {
        ticket,
        allocation,
        cursor,
    })
}

/// Release only the exact source captured at dispatch admission. A stale lease
/// remains pinned rather than authorizing retirement of a reused address.
pub(super) unsafe fn release_dispatch(lease: SourceIrpDispatchLease) -> bool {
    let address = lease.allocation.catalog.base;
    if !provider_pool_contains(address) {
        return false;
    }
    let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
        return false;
    };
    let offset = address - WIN32K_POOL_VADDR;
    let memory = ProviderPoolMemory;
    if registered_provider_wait_domain() != Some(lease.allocation.provider)
        || provider_allocations_unlocked(&mut metadata).is_none_or(|catalog| {
            catalog.snapshot_active(lease.allocation.catalog.identity)
                != Ok(lease.allocation.catalog)
        })
        || shared_pool::allocation_identity(&memory, offset) != Ok(lease.allocation.native)
        || shared_pool::allocation_capacity(&memory, offset) != Ok(lease.allocation.native_capacity)
    {
        return false;
    }
    ledger().is_some_and(|ledger| ledger.unpin(lease.ticket, lease.allocation).is_ok())
}

/// A failed commit remains reserved. Callers must never retry the free by address.
pub(super) unsafe fn retire(address: u64, ticket: ProviderSourceIrpTicket) -> bool {
    let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
        return false;
    };
    let Some(ledger) = ledger() else { return false };
    let Some((found, allocation)) = ledger.allocation_at(WIN32K_POOL_VADDR, address) else {
        return false;
    };
    if found != ticket || ledger.preflight_free(ticket, allocation).is_err() {
        return false;
    }
    let mut memory = ProviderPoolMemory;
    let offset = address - WIN32K_POOL_VADDR;
    if shared_pool::allocation_identity(&memory, offset) != Ok(allocation.native)
        || shared_pool::allocation_capacity(&memory, offset) != Ok(allocation.native_capacity)
    {
        return false;
    }
    let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
        return false;
    };
    if catalog.begin_retirement_from_pin(allocation.catalog_pin) != Ok(allocation.catalog) {
        return false;
    }
    if ledger.begin_free(ticket, allocation).is_err()
        || shared_pool::free(&mut memory, offset).is_err()
        || catalog.retire(allocation.catalog.identity) != Ok(allocation.catalog)
        || ledger.finish_free(ticket, allocation).is_err()
    {
        print_str(b"[win32k-irp] fatal source IRP retirement commit failure\n");
        park();
    }
    true
}
