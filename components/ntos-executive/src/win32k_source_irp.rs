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
use nt_io_manager::win32k_source_irp_ioctl_wire::{self as wire, EventIdentity};

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

/// Construct a win32k-owned, file-less kernel IOCTL request. Child allocations
/// and direct/neither targets are pinned in an exact auxiliary row before the
/// IRP becomes visible to its caller. Dispatch remains a separate authority.
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
        if input_length > MAX_BUFFER
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
        let Some(activation) = active_provider_stack_event_activation() else {
            return 0;
        };
        let mut input_copy = Vec::new();
        if plan.system_buffer_input_len != 0 {
            if input_copy.try_reserve_exact(input_length as usize).is_err() {
                return 0;
            }
            input_copy.resize(input_length as usize, 0);
            if provider_input::copy_validated_input(
                activation,
                input,
                input_length,
                &mut input_copy,
                0x57495250,
            )
            .is_err()
            {
                return 0;
            }
        }
        let Some((irp, ticket)) = allocate(stack_count) else {
            return 0;
        };
        let allocation = {
            let _metadata = ProviderMetadataGuard::acquire();
            ledger().and_then(|ledger| {
                ledger
                    .allocation_at(WIN32K_POOL_VADDR, irp)
                    .and_then(|(found, allocation)| (found == ticket).then_some(allocation))
            })
        }
        .unwrap_or_else(|| crate::provider_bugcheck::report(0xc4, [0x57495250, irp, 0, 20]));
        let mut system_buffer = 0;
        let mut mdl_address = 0;
        let mut system_pin = None;
        let mut mdl_pin = None;
        let mut input_target = None;
        let mut output_target = None;
        let constructed = 'build: {
            if plan.system_buffer_len != 0 {
                system_buffer = pool_alloc(u64::from(plan.system_buffer_len));
                if system_buffer == 0 {
                    break 'build false;
                }
                system_pin = pin_system_buffer(system_buffer, u64::from(plan.system_buffer_len));
                if system_pin.is_none() {
                    break 'build false;
                }
                if !input_copy.is_empty() {
                    core::ptr::copy_nonoverlapping(
                        input_copy.as_ptr(),
                        system_buffer as *mut u8,
                        input_copy.len(),
                    );
                }
            }
            if let Some(mdl) = plan.mdl {
                let pin = if ioctl::method(code) == ioctl::METHOD_IN_DIRECT {
                    match provider_input::pin_input(
                        activation,
                        mdl.buffer,
                        u64::from(mdl.length),
                    ) {
                        Ok(pin) => {
                            input_target = Some((mdl.buffer, u64::from(mdl.length), pin));
                            true
                        }
                        Err(_) => false,
                    }
                } else {
                    match file_ioctl_target::pin_output(
                        activation,
                        mdl.buffer,
                        u64::from(mdl.length),
                    ) {
                        Ok(pin) => {
                            output_target = Some((mdl.buffer, u64::from(mdl.length), pin));
                            true
                        }
                        Err(_) => false,
                    }
                };
                if !pin {
                    break 'build false;
                }
                mdl_address = pool_alloc(nt_mdl::MDL_SIZE as u64);
                if mdl_address == 0 {
                    break 'build false;
                }
                mdl_pin = pin_system_buffer(mdl_address, nt_mdl::MDL_SIZE as u64);
                if mdl_pin.is_none() {
                    break 'build false;
                }
                core::ptr::write_bytes(mdl_address as *mut u8, 0, nt_mdl::MDL_SIZE);
                write_unaligned(
                    (mdl_address + nt_mdl::MDL_OFF_SIZE) as *mut i16,
                    nt_mdl::MDL_SIZE as i16,
                );
                write_unaligned(
                    (mdl_address + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
                    nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED,
                );
                write_unaligned(
                    (mdl_address + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64,
                    mdl.buffer,
                );
                write_unaligned(
                    (mdl_address + nt_mdl::MDL_OFF_START_VA) as *mut u64,
                    mdl.buffer & !0xfff,
                );
                write_unaligned(
                    (mdl_address + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32,
                    mdl.length,
                );
                write_unaligned(
                    (mdl_address + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32,
                    (mdl.buffer & 0xfff) as u32,
                );
            } else if ioctl::method(code) == ioctl::METHOD_NEITHER {
                match provider_input::pin_input(
                    activation,
                    input,
                    u64::from(input_length),
                ) {
                    Ok(pin) => {
                        input_target = Some((input, u64::from(input_length), pin));
                    }
                    Err(_) => break 'build false,
                }
                match file_ioctl_target::pin_output(
                    activation,
                    output,
                    u64::from(output_length),
                ) {
                    Ok(pin) => {
                        output_target = Some((output, u64::from(output_length), pin));
                    }
                    Err(_) => break 'build false,
                }
            }
            let stack = irp + plan.next_stack_offset as u64;
            let stack_bytes = core::slice::from_raw_parts_mut(
                stack as *mut u8,
                WDM_X64_IO_STACK_LOCATION_SIZE,
            );
            if write_wdm_io_stack_location(stack_bytes, plan.stack).is_err() {
                break 'build false;
            }
            let auxiliary = source_irp_aux::SourceIrpAuxiliary {
                source: allocation,
                ticket,
                system_buffer: system_pin.take(),
                mdl: mdl_pin.take(),
                input_target: input_target.take(),
                output_target: output_target.take(),
            };
            if let Err(auxiliary) = source_irp_aux::register(auxiliary) {
                source_irp_aux::rollback_unpublished(auxiliary);
                system_buffer = 0;
                mdl_address = 0;
                break 'build false;
            }
            true
        };
        if !constructed {
            if let Some((_, _, pin)) = output_target {
                file_ioctl_target::release_output(pin);
            }
            if let Some((_, _, pin)) = input_target {
                provider_input::release_input(pin, 0x57495250);
            }
            if let Some(pin) = mdl_pin {
                if !release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, mdl_address, 0, 21]);
                }
            }
            if mdl_address != 0 && !provider_pool_free(mdl_address) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, mdl_address, 0, 22]);
            }
            if let Some(pin) = system_pin {
                if !release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, system_buffer, 0, 23]);
                }
            }
            if system_buffer != 0 && !provider_pool_free(system_buffer) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, system_buffer, 0, 24]);
            }
            if !retire(irp, ticket) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, irp, 0, 25]);
            }
            return 0;
        }
        write_unaligned((irp + 0x08) as *mut u64, mdl_address);
        write_unaligned((irp + 0x10) as *mut u32, plan.irp_flags);
        write_unaligned((irp + 0x18) as *mut u64, system_buffer);
        write_unaligned((irp + 0x48) as *mut u64, iosb);
        write_unaligned((irp + 0x50) as *mut u64, event);
        write_unaligned((irp + 0x70) as *mut u64, plan.user_buffer);
        write_unaligned((irp + 0x98) as *mut u64, s_current_thread());
        irp
    }
}

/// Build a file-less synchronous FSD IRP. PnP callers fill the next stack's
/// minor and parameters before dispatch; read/write transfers follow device flags.
pub(super) extern "win64" fn build_synchronous_fsd_request(
    major: u32,
    device: u64,
    buffer: u64,
    length: u32,
    starting_offset: u64,
    event: u64,
    iosb: u64,
) -> u64 {
    unsafe {
        use nt_io_abi::major as mj;
        const MAX_BUFFER: u32 = nt_io_manager::win32k_source_irp_ioctl_wire::MAX_BUFFER_BYTES;
        let read = major == mj::IRP_MJ_READ as u32;
        let write = major == mj::IRP_MJ_WRITE as u32;
        let transfer = read || write;
        if !matches!(major as u8,
            mj::IRP_MJ_READ | mj::IRP_MJ_WRITE | mj::IRP_MJ_FLUSH_BUFFERS
                | mj::IRP_MJ_SHUTDOWN | mj::IRP_MJ_PNP | mj::IRP_MJ_POWER)
            || major > u8::MAX as u32
            || (transfer && (starting_offset == 0 || length > MAX_BUFFER || (length != 0 && buffer == 0)))
            || (!transfer && (buffer != 0 || length != 0 || starting_offset != 0))
            || iosb == 0
            || !provider_pool_contains(device)
            || device.checked_add(0x50).is_none_or(|end| {
                end > WIN32K_POOL_VADDR + WIN32K_POOL_FRAMES * 0x1000
            })
        {
            print_str(b"[win32k-fsd-builder] rejected arguments major=0x");
            print_hex_u64(major as u64);
            print_str(b" device=0x");
            print_hex_u64(device);
            print_str(b" iosb=0x");
            print_hex_u64(iosb);
            print_str(b"\n");
            return 0;
        }
        if crate::driver_launch::win32k_device_pointers::reference(device).is_err() {
            print_str(b"[win32k-fsd-builder] device reference rejected\n");
            return 0;
        }
        let stack_count = read_unaligned((device + 0x4c) as *const u8);
        let device_flags = read_unaligned((device + 0x30) as *const u32);
        if crate::driver_launch::win32k_device_pointers::dereference(device).is_err() {
            crate::provider_bugcheck::report(0xc4, [0x57495250, device, 4, 30]);
        }
        let Some(activation) = active_provider_stack_event_activation() else {
            print_str(b"[win32k-fsd-builder] no provider activation\n");
            return 0;
        };
        let byte_offset = if transfer {
            let mut bytes = [0u8; 8];
            if provider_input::copy_validated_input(
                activation, starting_offset, 8, &mut bytes, 0x57495250,
            ).is_err() {
                return 0;
            }
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        };
        let Ok(plan) = nt_io_manager::kernel_irp_builder::plan_synchronous_fsd_request(
            major as u8,
            stack_count,
            device_flags,
            device,
            buffer,
            length,
            byte_offset,
        ) else {
            print_str(b"[win32k-fsd-builder] invalid plan major=0x");
            print_hex_u64(major as u64);
            print_str(b" device=0x");
            print_hex_u64(device);
            print_str(b" stack=0x");
            print_hex_u64(stack_count as u64);
            print_str(b" flags=0x");
            print_hex_u64(device_flags as u64);
            print_str(b"\n");
            return 0;
        };
        let mut write_copy = Vec::new();
        if write && plan.system_buffer_input_len != 0 {
            if write_copy.try_reserve_exact(length as usize).is_err() {
                return 0;
            }
            write_copy.resize(length as usize, 0);
            if provider_input::copy_validated_input(
                activation, buffer, length, &mut write_copy, 0x57495250,
            ).is_err() {
                return 0;
            }
        }
        let Some((irp, ticket)) = allocate(stack_count) else {
            print_str(b"[win32k-fsd-builder] IRP allocation failed\n");
            return 0;
        };
        let allocation = {
            let _metadata = ProviderMetadataGuard::acquire();
            ledger().and_then(|ledger| {
                ledger
                    .allocation_at(WIN32K_POOL_VADDR, irp)
                    .and_then(|(found, allocation)| (found == ticket).then_some(allocation))
            })
        }
        .unwrap_or_else(|| crate::provider_bugcheck::report(0xc4, [0x57495250, irp, 0, 31]));
        let mut system_buffer = 0;
        let mut mdl_address = 0;
        let mut system_pin = None;
        let mut mdl_pin = None;
        let mut input_target = None;
        let mut output_target = None;
        let built = 'build: {
            if plan.system_buffer_len != 0 {
                system_buffer = pool_alloc(u64::from(plan.system_buffer_len));
                if system_buffer == 0 { break 'build false; }
                system_pin = pin_system_buffer(system_buffer, u64::from(plan.system_buffer_len));
                if system_pin.is_none() { break 'build false; }
                if !write_copy.is_empty() {
                    core::ptr::copy_nonoverlapping(
                        write_copy.as_ptr(), system_buffer as *mut u8, write_copy.len(),
                    );
                }
            }
            if let Some(mdl) = plan.mdl.filter(|mdl| mdl.length != 0) {
                if read {
                    match file_ioctl_target::pin_output(activation, mdl.buffer, u64::from(mdl.length)) {
                        Ok(pin) => output_target = Some((mdl.buffer, u64::from(mdl.length), pin)),
                        Err(_) => break 'build false,
                    }
                } else {
                    match provider_input::pin_input(activation, mdl.buffer, u64::from(mdl.length)) {
                        Ok(pin) => input_target = Some((mdl.buffer, u64::from(mdl.length), pin)),
                        Err(_) => break 'build false,
                    }
                }
                mdl_address = pool_alloc(nt_mdl::MDL_SIZE as u64);
                if mdl_address == 0 { break 'build false; }
                mdl_pin = pin_system_buffer(mdl_address, nt_mdl::MDL_SIZE as u64);
                if mdl_pin.is_none() { break 'build false; }
                core::ptr::write_bytes(mdl_address as *mut u8, 0, nt_mdl::MDL_SIZE);
                write_unaligned((mdl_address + nt_mdl::MDL_OFF_SIZE) as *mut i16, nt_mdl::MDL_SIZE as i16);
                write_unaligned((mdl_address + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
                    nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED);
                write_unaligned((mdl_address + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64, mdl.buffer);
                write_unaligned((mdl_address + nt_mdl::MDL_OFF_START_VA) as *mut u64, mdl.buffer & !0xfff);
                write_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, mdl.length);
                write_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32, (mdl.buffer & 0xfff) as u32);
            } else if transfer && length != 0 && plan.system_buffer_len == 0 {
                if read {
                    match file_ioctl_target::pin_output(activation, buffer, u64::from(length)) {
                        Ok(pin) => output_target = Some((buffer, u64::from(length), pin)),
                        Err(_) => break 'build false,
                    }
                } else {
                    match provider_input::pin_input(activation, buffer, u64::from(length)) {
                        Ok(pin) => input_target = Some((buffer, u64::from(length), pin)),
                        Err(_) => break 'build false,
                    }
                }
            } else if read && length != 0 {
                match file_ioctl_target::pin_output(activation, buffer, u64::from(length)) {
                    Ok(pin) => output_target = Some((buffer, u64::from(length), pin)),
                    Err(_) => break 'build false,
                }
            }
            let stack = irp + plan.next_stack_offset as u64;
            let stack_bytes = core::slice::from_raw_parts_mut(stack as *mut u8, WDM_X64_IO_STACK_LOCATION_SIZE);
            if write_wdm_io_stack_location(stack_bytes, plan.stack).is_err() {
                break 'build false;
            }
            let auxiliary = source_irp_aux::SourceIrpAuxiliary {
                source: allocation,
                ticket,
                system_buffer: system_pin.take(),
                mdl: mdl_pin.take(),
                input_target: input_target.take(),
                output_target: output_target.take(),
            };
            if let Err(auxiliary) = source_irp_aux::register(auxiliary) {
                source_irp_aux::rollback_unpublished(auxiliary);
                system_buffer = 0;
                mdl_address = 0;
                break 'build false;
            }
            true
        };
        if !built {
            print_str(b"[win32k-fsd-builder] materialization failed\n");
            if let Some((_, _, pin)) = output_target {
                file_ioctl_target::release_output(pin);
            }
            if let Some((_, _, pin)) = input_target {
                provider_input::release_input(pin, 0x57495250);
            }
            if let Some(pin) = mdl_pin {
                if !release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, mdl_address, 0, 40]);
                }
            }
            if mdl_address != 0 && !provider_pool_free(mdl_address) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, mdl_address, 0, 41]);
            }
            if let Some(pin) = system_pin {
                if !release_system_buffer(pin) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, system_buffer, 0, 42]);
                }
            }
            if system_buffer != 0 && !provider_pool_free(system_buffer) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, system_buffer, 0, 43]);
            }
            if !retire(irp, ticket) {
                crate::provider_bugcheck::report(0xc4, [0x57495250, irp, 0, 44]);
            }
            return 0;
        }
        write_unaligned((irp + 0x08) as *mut u64, mdl_address);
        write_unaligned((irp + 0x10) as *mut u32, plan.irp_flags);
        write_unaligned((irp + 0x18) as *mut u64, system_buffer);
        write_unaligned((irp + 0x48) as *mut u64, iosb);
        write_unaligned((irp + 0x50) as *mut u64, event);
        write_unaligned((irp + 0x70) as *mut u64, plan.user_buffer);
        write_unaligned((irp + 0x98) as *mut u64, s_current_thread());
        print_str(b"[win32k-fsd-builder] built major=0x");
        print_hex_u64(major as u64);
        print_str(b" irp=0x");
        print_hex_u64(irp);
        print_str(b"\n");
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
        print_str(b"[source-irp-retain] outside provider pool\n");
        return None;
    }
    let (mut metadata, _pool) = provider_metadata_pool_lock().or_else(|| {
        print_str(b"[source-irp-retain] metadata lock unavailable\n");
        None
    })?;
    let source_ledger = ledger().or_else(|| {
        print_str(b"[source-irp-retain] ledger unavailable\n");
        None
    })?;
    let (ticket, allocation) = source_ledger.allocation_at(WIN32K_POOL_VADDR, address).or_else(|| {
        print_str(b"[source-irp-retain] allocation ledger missing\n");
        None
    })?;
    if registered_provider_wait_domain() != Some(allocation.provider) {
        print_str(b"[source-irp-retain] provider domain changed\n");
        return None;
    }
    let catalog = provider_allocations_unlocked(&mut metadata).or_else(|| {
        print_str(b"[source-irp-retain] provider catalog unavailable\n");
        None
    })?;
    if catalog.snapshot_active(allocation.catalog.identity).ok() != Some(allocation.catalog) {
        print_str(b"[source-irp-retain] provider catalog mismatch\n");
        return None;
    }
    let memory = ProviderPoolMemory;
    let offset = address - WIN32K_POOL_VADDR;
    if shared_pool::allocation_identity(&memory, offset) != Ok(allocation.native)
        || shared_pool::allocation_capacity(&memory, offset) != Ok(allocation.native_capacity) {
        print_str(b"[source-irp-retain] native pool generation mismatch\n");
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
    .map_err(|_| {
        print_str(b"[source-irp-retain] WDM cursor invalid location=0x");
        print_hex(header.current_location as u32);
        print_str(b" stack=0x");
        print_hex_u64(header.current_stack_location);
        print_str(b" count=0x");
        print_hex(header.stack_count as u32);
        print_str(b" size=0x");
        print_hex(header.packet_size as u32);
        print_str(b"\n");
    }).ok()?;
    ledger()?.pin(ticket, allocation).map_err(|_| {
        print_str(b"[source-irp-retain] ledger pin rejected\n");
    }).ok()?;
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

pub(super) unsafe fn dispatch_lease_live(source: &SourceIrpDispatchLease) -> bool {
    let address = source.allocation.catalog.base;
    let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
        return false;
    };
    let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
        return false;
    };
    let memory = ProviderPoolMemory;
    let offset = address - WIN32K_POOL_VADDR;
    registered_provider_wait_domain() == Some(source.allocation.provider)
        && catalog.snapshot_active(source.allocation.catalog.identity)
            == Ok(source.allocation.catalog)
        && ledger().is_some_and(|ledger| ledger.matches(source.ticket, source.allocation))
        && shared_pool::allocation_identity(&memory, offset) == Ok(source.allocation.native)
        && shared_pool::allocation_capacity(&memory, offset)
            == Ok(source.allocation.native_capacity)
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
    if found != ticket
        || source_irp_aux::contains_exact_unlocked(ticket, allocation)
        || ledger.preflight_free(ticket, allocation).is_err()
    {
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

/// Reject an unentered builder-owned source without leaking its child buffers.
/// Reserve the exact source first so another dispatch cannot pin it while the
/// auxiliary allocations are released under their own metadata locks.
pub(super) unsafe fn retire_unentered(
    address: u64,
    ticket: ProviderSourceIrpTicket,
    native_generation: u64,
) -> bool {
    let allocation = {
        let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
            return false;
        };
        let Some(ledger) = ledger() else { return false };
        let Some((found, allocation)) = ledger.allocation_at(WIN32K_POOL_VADDR, address) else {
            return false;
        };
        if found != ticket
            || allocation.native.allocation_generation != native_generation
            || !source_irp_aux::contains_exact_unlocked(ticket, allocation)
            || ledger.preflight_free(ticket, allocation).is_err()
        {
            return false;
        }
        let memory = ProviderPoolMemory;
        let offset = address - WIN32K_POOL_VADDR;
        if registered_provider_wait_domain() != Some(allocation.provider)
            || shared_pool::allocation_identity(&memory, offset) != Ok(allocation.native)
            || shared_pool::allocation_capacity(&memory, offset) != Ok(allocation.native_capacity)
        {
            return false;
        }
        let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
            return false;
        };
        if catalog.snapshot_active(allocation.catalog.identity) != Ok(allocation.catalog)
            || catalog.begin_retirement_from_pin(allocation.catalog_pin) != Ok(allocation.catalog)
        {
            return false;
        }
        if ledger.begin_free(ticket, allocation).is_err() {
            crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 40]);
        }
        allocation
    };

    if !source_irp_aux::retire_exact(ticket, allocation) {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 41]);
    }
    let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 42]);
    };
    let mut memory = ProviderPoolMemory;
    let offset = address - WIN32K_POOL_VADDR;
    let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 43]);
    };
    let Some(ledger) = ledger() else {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 44]);
    };
    if shared_pool::allocation_identity(&memory, offset) != Ok(allocation.native)
        || shared_pool::allocation_capacity(&memory, offset) != Ok(allocation.native_capacity)
        || shared_pool::free(&mut memory, offset).is_err()
        || catalog.retire(allocation.catalog.identity) != Ok(allocation.catalog)
        || ledger.finish_free(ticket, allocation).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 45]);
    }
    true
}

pub(super) struct PinnedSystemBuffer {
    address: u64,
    snapshot: ProviderAllocationSnapshot,
    pin: ProviderAllocationPin,
    native: shared_pool::AllocationIdentity,
}

impl PinnedSystemBuffer {
    pub(super) fn address(&self) -> u64 {
        self.address
    }

    pub(super) fn native_identity(&self) -> shared_pool::AllocationIdentity {
        self.native
    }
}

pub(super) unsafe fn pin_system_buffer(address: u64, length: u64) -> Option<PinnedSystemBuffer> {
    if !provider_pool_contains(address) || length == 0 {
        return None;
    }
    let (mut metadata, _pool) = provider_metadata_pool_lock()?;
    let catalog = provider_allocations_unlocked(&mut metadata)?;
    let (snapshot, pin) = catalog.pin_containing(address, length).ok()?;
    let memory = ProviderPoolMemory;
    let offset = address - WIN32K_POOL_VADDR;
    let native = shared_pool::allocation_identity(&memory, offset);
    let capacity = shared_pool::allocation_capacity(&memory, offset);
    if snapshot.base != address
        || native.is_err()
        || capacity != Ok(snapshot.capacity)
        || native.as_ref().is_ok_and(|id| id.allocation_id != offset)
    {
        if catalog.release_pin(pin).is_err() {
            crate::provider_bugcheck::report(0xc4, [0x57495250, address, length, 5]);
        }
        return None;
    }
    Some(PinnedSystemBuffer {
        address,
        snapshot,
        pin,
        native: native.unwrap(),
    })
}

pub(super) unsafe fn system_buffer_live(buffer: &PinnedSystemBuffer) -> bool {
    let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
        return false;
    };
    let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
        return false;
    };
    let memory = ProviderPoolMemory;
    let offset = buffer.address - WIN32K_POOL_VADDR;
    catalog.snapshot_active(buffer.snapshot.identity) == Ok(buffer.snapshot)
        && shared_pool::allocation_identity(&memory, offset) == Ok(buffer.native)
        && shared_pool::allocation_capacity(&memory, offset) == Ok(buffer.snapshot.capacity)
}

pub(super) unsafe fn release_system_buffer(buffer: PinnedSystemBuffer) -> bool {
    let Some((mut metadata, _pool)) = provider_metadata_pool_lock() else {
        return false;
    };
    let Some(catalog) = provider_allocations_unlocked(&mut metadata) else {
        return false;
    };
    let memory = ProviderPoolMemory;
    let offset = buffer.address - WIN32K_POOL_VADDR;
    if catalog.snapshot_active(buffer.snapshot.identity) != Ok(buffer.snapshot)
        || shared_pool::allocation_identity(&memory, offset) != Ok(buffer.native)
        || shared_pool::allocation_capacity(&memory, offset) != Ok(buffer.snapshot.capacity)
    {
        return false;
    }
    catalog.release_pin(buffer.pin).is_ok()
}

#[must_use = "hold the source and target pins until terminal publication and acknowledgement"]
pub(crate) struct SourceBufferedDispatchLease {
    source: Option<SourceIrpDispatchLease>,
    pub device: u64,
    pub code: u32,
    pub method: u32,
    pub internal: bool,
    pub input: Vec<u8>,
    pub output_initial: Vec<u8>,
    pub output_capacity: u32,
    pub output_va: u64,
    pub iosb_va: u64,
    pub event: Option<EventIdentity>,
    event_va: u64,
    image_map_owner: u64,
    system_buffer: Option<PinnedSystemBuffer>,
    auxiliary: source_irp_aux::AuxiliarySnapshot,
    iosb_pin: file_ioctl_target::PinnedIoctlOutput,
    output_pin: file_ioctl_target::PinnedIoctlOutput,
    input_second_pin: Option<provider_input::PinnedInput>,
    event_lease: Option<nt_provider_wait::ProviderLocalEventLease>,
}

pub(super) unsafe fn target_live(
    pin: &file_ioctl_target::PinnedIoctlOutput,
    image_map_owner: u64,
    address: u64,
    length: u64,
) -> bool {
    match pin {
        file_ioctl_target::PinnedIoctlOutput::None => length == 0,
        file_ioctl_target::PinnedIoctlOutput::Stack(pin) => {
            let mut metadata = ProviderMetadataGuard::acquire();
            pin.range() == (address, length)
                && provider_input::stack_catalog_mut(&mut metadata).is_some_and(|catalog| {
                    catalog.validate_pin(*pin).is_ok()
                })
        }
        file_ioctl_target::PinnedIoctlOutput::Pool(pin) => {
            let catalog_live = with_provider_allocations(|catalog| {
                catalog.snapshot_active(pin.identity()).is_ok_and(|snapshot| {
                    snapshot.offset_of(address).is_some_and(|offset| {
                        offset.checked_add(length).is_some_and(|end| end <= snapshot.capacity)
                    })
                })
            }) == Some(true);
            catalog_live
                && matches!(
                    file_ioctl_target::capture_root_output(address, length),
                    Some(file_ioctl_target::RootIoctlOutputTarget::Pool { .. })
                )
        }
        file_ioctl_target::PinnedIoctlOutput::Image => {
            image_map_owner != 0
                && WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) == image_map_owner
                && matches!(
                    file_ioctl_target::capture_root_output(address, length),
                    Some(file_ioctl_target::RootIoctlOutputTarget::Image { .. })
                )
        }
    }
}

impl SourceBufferedDispatchLease {
    pub(crate) fn source_address(&self) -> u64 {
        self.source.as_ref().unwrap().allocation.catalog.base
    }

    pub(crate) fn source_ticket_serial(&self) -> u64 {
        self.source.as_ref().unwrap().ticket.serial.get()
    }

    pub(crate) fn source_native_generation(&self) -> u64 {
        self.source.as_ref().unwrap().allocation.native.allocation_generation
    }

    pub(crate) fn system_buffer_address(&self) -> Option<u64> {
        self.system_buffer.as_ref().map(|buffer| buffer.address)
    }

    pub(crate) fn system_buffer_native_identity(
        &self,
    ) -> Option<shared_pool::AllocationIdentity> {
        self.system_buffer.as_ref().map(|buffer| buffer.native)
    }

    pub(crate) fn mdl_native_identity(&self) -> Option<shared_pool::AllocationIdentity> {
        self.auxiliary.mdl.map(|(_, identity)| identity)
    }

    pub(crate) fn mdl_address(&self) -> Option<u64> {
        self.auxiliary.mdl.map(|(address, _)| address)
    }

    pub(crate) fn input_target_address(&self) -> Option<u64> {
        self.auxiliary.input_target.map(|(address, _)| address)
    }

    pub(crate) fn event_body(&self) -> Option<u64> {
        self.event_lease.map(|_| self.event_va)
    }

    /// Revalidate before crossing into the canonical I/O manager and before publication.
    pub(crate) unsafe fn is_live(&self) -> bool {
        let Some(source) = self.source.as_ref() else {
            return false;
        };
        if !dispatch_lease_live(source)
            || source_irp_aux::snapshot_exact(source.ticket, source.allocation)
                .is_none_or(|snapshot| !snapshot.same_identity(&self.auxiliary))
            || self
                .system_buffer
                .as_ref()
                .is_some_and(|buffer| !system_buffer_live(buffer))
            || !target_live(
                &self.iosb_pin,
                self.image_map_owner,
                self.iosb_va,
                16,
            )
            || (self.method == nt_io_abi::ioctl::METHOD_IN_DIRECT
                && self.input_second_pin.as_ref().is_none_or(|pin| {
                    !provider_input::input_live(pin, self.output_va, u64::from(self.output_capacity))
                }))
            || (self.method != nt_io_abi::ioctl::METHOD_IN_DIRECT
                && !target_live(
                    &self.output_pin,
                    self.image_map_owner,
                    self.output_va,
                    u64::from(self.output_capacity),
                ))
        {
            return false;
        }
        if let Some(event) = self.event_lease {
            let _metadata = ProviderMetadataGuard::acquire();
            provider_local_events().is_some_and(|events| {
                events.snapshot(event.id).is_ok_and(|snapshot| {
                    snapshot.body == self.event_va && snapshot.canonical == Some(event.canonical)
                })
            })
        } else {
            true
        }
    }

    pub(crate) unsafe fn validate(&self) -> bool {
        self.is_live()
    }

    /// `output_address` and `iosb_address` are root-authenticated aliases of
    /// this lease's component targets; the caller must prove their route first.
    pub(crate) unsafe fn publish_terminal(
        &self,
        status: u32,
        information: u64,
        output: &[u8],
        output_address: u64,
        iosb_address: u64,
    ) -> bool {
        if status == wire::STATUS_PENDING
            || !self.is_live()
            || iosb_address == 0
            || iosb_address.checked_add(16).is_none()
        {
            return false;
        }
        let copy_len = wire::completion_output_len(
            self.code,
            status,
            information,
            self.output_capacity,
        );
        if output.len() != copy_len
            || (copy_len != 0 && self.method != nt_io_abi::ioctl::METHOD_IN_DIRECT
                && (output_address == 0
                    || output_address.checked_add(copy_len as u64).is_none()))
        {
            return false;
        }
        if !output.is_empty() {
            if self.method == nt_io_abi::ioctl::METHOD_BUFFERED {
                let Some(buffer) = &self.system_buffer else { return false };
                core::ptr::copy_nonoverlapping(
                    output.as_ptr(),
                    buffer.address as *mut u8,
                    output.len(),
                );
            }
            if self.method != nt_io_abi::ioctl::METHOD_IN_DIRECT {
                core::ptr::copy_nonoverlapping(
                    output.as_ptr(),
                    output_address as *mut u8,
                    output.len(),
                );
            }
        }
        write_unaligned(iosb_address as *mut u32, status);
        write_unaligned((iosb_address + 8) as *mut u64, information);
        true
    }

}

pub(super) unsafe fn try_signal_event_lease(
    event: u64,
) -> Option<nt_provider_wait::ProviderLocalEventLease> {
    let mut metadata = ProviderMetadataGuard::acquire();
    let events = provider_local_events_mut()?;
    let snapshot = events.resolve_body(event).ok()?;
    if matches!(
        snapshot.storage.backing,
        nt_provider_wait::ProviderEventBacking::Allocation { .. }
    ) {
        let allocations = provider_allocations_unlocked(&mut metadata)?;
        let allocation = allocations
            .containing(event, nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64)
            .ok()?;
        if allocations.snapshot_active(allocation.identity).is_err()
            || nt_provider_wait::ProviderEventBacking::from_allocation(allocation)
                != snapshot.storage.backing
        {
            return None;
        }
    }
    events
        .acquire_lease(snapshot.id, nt_provider_wait::ProviderLocalEventLeaseKind::Signal)
        .ok()
}

pub(super) unsafe fn capture_pinned_target(
    address: u64,
    length: u32,
    route: Option<nt_component_suspension::peer_registry::PeerRoute>,
) -> Result<Vec<u8>, i32> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES_I32)?;
    if length == 0 {
        return Ok(bytes);
    }
    let stack_backed = {
        let _metadata = ProviderMetadataGuard::acquire();
        (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
            .as_ref()
            .is_some_and(|catalog| catalog.resolve(address, length as u64).is_ok())
    };
    let readable = if stack_backed {
        match route {
            Some(route) => crate::win32k_glue::win32k_stack_alias_for_route(
                route,
                address,
                length as u64,
            )
            .ok_or(STATUS_ACCESS_VIOLATION_I32)?,
            None => address,
        }
    } else {
        address
    };
    if readable == 0 || readable.checked_add(length as u64).is_none() {
        return Err(STATUS_ACCESS_VIOLATION_I32);
    }
    bytes.extend_from_slice(core::slice::from_raw_parts(readable as *const u8, length as usize));
    Ok(bytes)
}

/// Admit a freshly built, file-less device control without entering a driver.
/// No raw WDM pointer is authority: every target and the exact source packet stay pinned.
pub(crate) unsafe fn admit_buffered_dispatch(
    address: u64,
    device: u64,
    stack_pointer: u64,
    route: Option<nt_component_suspension::peer_registry::PeerRoute>,
) -> Result<SourceBufferedDispatchLease, i32> {
    use nt_io_abi::{ioctl, major};
    let mut source = Some(retain_dispatch(address).ok_or(STATUS_INVALID_PARAMETER_I32)?);
    let result = (|| {
        let stack_address = address + source.as_ref().unwrap().cursor.next_stack_offset as u64;
        let stack_bytes = core::slice::from_raw_parts(
            stack_address as *const u8,
            WDM_X64_IO_STACK_LOCATION_SIZE,
        );
        let stack = nt_io_manager::decode_wdm_kernel_built_io_stack(stack_bytes)
            .map_err(|_| STATUS_INVALID_PARAMETER_I32)?;
        let internal = match stack.major {
            major::IRP_MJ_DEVICE_CONTROL => false,
            major::IRP_MJ_INTERNAL_DEVICE_CONTROL => true,
            _ => return Err(STATUS_NOT_SUPPORTED_I32),
        };
        let nt_io_manager::WdmIoStackParameters::DeviceControl {
            output_buffer_length,
            input_buffer_length,
            io_control_code,
            type3_input_buffer,
        } = stack.parameters else {
            return Err(STATUS_INVALID_PARAMETER_I32);
        };
        let method = ioctl::method(io_control_code);
        let source_ref = source.as_ref().unwrap();
        let auxiliary = source_irp_aux::snapshot_exact(source_ref.ticket, source_ref.allocation)
            .ok_or(STATUS_INVALID_PARAMETER_I32)?;
        let capacity = if method == ioctl::METHOD_BUFFERED {
            input_buffer_length.max(output_buffer_length)
        } else if method == ioctl::METHOD_NEITHER {
            0
        } else {
            input_buffer_length
        };
        if device == 0
            || stack.device_object != device
            || stack.file_object != 0
            || input_buffer_length > wire::MAX_BUFFER_BYTES
            || output_buffer_length > wire::MAX_BUFFER_BYTES
        {
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let system_address = read_volatile((address + 0x18) as *const u64);
        let user_buffer = read_volatile((address + 0x70) as *const u64);
        let mdl_address = read_volatile((address + 0x08) as *const u64);
        let iosb_va = read_volatile((address + 0x48) as *const u64);
        let event_va = read_volatile((address + 0x50) as *const u64);
        let flags = read_volatile((address + 0x10) as *const u32);
        let expected_flags = if capacity == 0 {
            0
        } else {
            nt_io_manager::kernel_irp_builder::IRP_BUFFERED_IO
                | nt_io_manager::kernel_irp_builder::IRP_DEALLOCATE_BUFFER
                | if method == ioctl::METHOD_BUFFERED && user_buffer != 0 {
                    nt_io_manager::kernel_irp_builder::IRP_INPUT_OPERATION
                } else {
                    0
                }
        };
        if flags != expected_flags
            || iosb_va == 0
            || (capacity == 0) != (system_address == 0)
        {
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let output_va = match method {
            ioctl::METHOD_BUFFERED => {
                if type3_input_buffer != 0
                    || mdl_address != 0
                    || auxiliary.mdl.is_some()
                    || auxiliary.input_target.is_some()
                    || auxiliary.output_target.is_some()
                {
                    return Err(STATUS_INVALID_PARAMETER_I32);
                }
                user_buffer
            }
            ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                if type3_input_buffer != 0 || user_buffer != 0 {
                    return Err(STATUS_INVALID_PARAMETER_I32);
                }
                if output_buffer_length == 0 {
                    if mdl_address != 0
                        || auxiliary.mdl.is_some()
                        || auxiliary.input_target.is_some()
                        || auxiliary.output_target.is_some()
                    {
                        return Err(STATUS_INVALID_PARAMETER_I32);
                    }
                    0
                } else {
                    if auxiliary.mdl.is_none_or(|(address, _)| address != mdl_address)
                        || read_unaligned((mdl_address + nt_mdl::MDL_OFF_SIZE) as *const i16)
                            != nt_mdl::MDL_SIZE as i16
                        || read_unaligned((mdl_address + nt_mdl::MDL_OFF_FLAGS) as *const i16)
                            != (nt_mdl::MDL_MAPPED_TO_SYSTEM_VA | nt_mdl::MDL_PAGES_LOCKED)
                    {
                        return Err(STATUS_INVALID_PARAMETER_I32);
                    }
                    let mapped = read_unaligned(
                        (mdl_address + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *const u64,
                    );
                    if mapped == 0
                        || read_unaligned((mdl_address + nt_mdl::MDL_OFF_START_VA) as *const u64)
                            != mapped & !0xfff
                        || read_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_COUNT) as *const u32)
                            != output_buffer_length
                        || read_unaligned((mdl_address + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32)
                            != (mapped & 0xfff) as u32
                        || (method == ioctl::METHOD_IN_DIRECT
                            && (auxiliary.input_target != Some((mapped, output_buffer_length as u64))
                                || auxiliary.output_target.is_some()))
                        || (method == ioctl::METHOD_OUT_DIRECT
                            && (auxiliary.output_target != Some((mapped, output_buffer_length as u64))
                                || auxiliary.input_target.is_some()))
                    {
                        return Err(STATUS_INVALID_PARAMETER_I32);
                    }
                    mapped
                }
            }
            ioctl::METHOD_NEITHER => {
                if system_address != 0
                    || mdl_address != 0
                    || auxiliary.mdl.is_some()
                    || auxiliary.system_buffer.is_some()
                    || auxiliary.input_target != Some((type3_input_buffer, input_buffer_length as u64))
                    || auxiliary.output_target != Some((user_buffer, output_buffer_length as u64))
                {
                    return Err(STATUS_INVALID_PARAMETER_I32);
                }
                user_buffer
            }
            _ => return Err(STATUS_INVALID_PARAMETER_I32),
        };
        if (output_buffer_length != 0 && output_va == 0)
            || (method != ioctl::METHOD_NEITHER && type3_input_buffer != 0)
        {
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let system_buffer = if capacity == 0 {
            None
        } else {
            Some(pin_system_buffer(system_address, u64::from(capacity))
                .ok_or(STATUS_ACCESS_VIOLATION_I32)?)
        };
        if auxiliary.system_buffer
            != system_buffer.as_ref().map(|buffer| (buffer.address(), buffer.native_identity()))
        {
            if let Some(buffer) = system_buffer {
                if !release_system_buffer(buffer) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 28]);
                }
            }
            return Err(STATUS_INVALID_PARAMETER_I32);
        }
        let activation = {
            let _metadata = ProviderMetadataGuard::acquire();
            (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
                .as_ref()
                .and_then(|catalog| {
                    let (binding, _) = catalog.resolve(stack_pointer, 1).ok()?;
                    catalog.active(binding.handle).ok()
                })
        };
        let Some(activation) = activation else {
            if let Some(buffer) = system_buffer {
                if !release_system_buffer(buffer) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 6]);
                }
            }
            return Err(STATUS_NOT_SUPPORTED_I32);
        };
        let iosb_pin = match file_ioctl_target::pin_output(activation, iosb_va, 16) {
            Ok(pin) => pin,
            Err(status) => {
                if let Some(buffer) = system_buffer {
                    if !release_system_buffer(buffer) {
                        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 7]);
                    }
                }
                return Err(status);
            }
        };
        let output_pins = if method == ioctl::METHOD_IN_DIRECT {
            provider_input::pin_input(activation, output_va, u64::from(output_buffer_length))
                .map(|pin| (file_ioctl_target::PinnedIoctlOutput::None, Some(pin)))
        } else {
            file_ioctl_target::pin_output(activation, output_va, u64::from(output_buffer_length))
                .map(|pin| (pin, None))
        };
        let (output_pin, input_second_pin) = match output_pins {
            Ok(pins) => pins,
            Err(status) => {
                file_ioctl_target::release_output(iosb_pin);
                if let Some(buffer) = system_buffer {
                    if !release_system_buffer(buffer) {
                        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 8]);
                    }
                }
                return Err(status);
            }
        };
        let event_lease = if event_va == 0 {
            None
        } else {
            match try_signal_event_lease(event_va) {
                Some(lease) => Some(lease),
                None => {
                    file_ioctl_target::release_output(output_pin);
                    if let Some(pin) = input_second_pin {
                        provider_input::release_input(pin, W32_SOURCE_IOCTL_LABEL);
                    }
                    file_ioctl_target::release_output(iosb_pin);
                    if let Some(buffer) = system_buffer {
                        if !release_system_buffer(buffer) {
                            crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 9]);
                        }
                    }
                    return Err(STATUS_INVALID_PARAMETER_I32);
                }
            }
        };
        let event = event_lease.map(|lease| EventIdentity {
            local_id: lease.id.raw(),
            object_slot_plus_one: lease.canonical.object_id,
            object_generation: lease.canonical.object_generation,
        });
        let captured = (|| {
            let input = if method == ioctl::METHOD_NEITHER {
                capture_pinned_target(type3_input_buffer, input_buffer_length, route)?
            } else if let Some(buffer) = &system_buffer {
                if !system_buffer_live(buffer) {
                    return Err(STATUS_ACCESS_VIOLATION_I32);
                }
                capture_pinned_target(buffer.address, input_buffer_length, route)?
            } else {
                Vec::new()
            };
            let output_initial = if method == ioctl::METHOD_BUFFERED {
                Vec::new()
            } else {
                capture_pinned_target(output_va, output_buffer_length, route)?
            };
            Ok::<_, i32>((input, output_initial))
        })();
        let (input, output_initial) = match captured {
            Ok(captured) => captured,
            Err(status) => {
            if let Some(lease) = event_lease {
                let _metadata = ProviderMetadataGuard::acquire();
                if provider_local_events_mut().is_none_or(|events| events.release_lease(lease).is_err()) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 10]);
                }
            }
            file_ioctl_target::release_output(output_pin);
            if let Some(pin) = input_second_pin {
                provider_input::release_input(pin, W32_SOURCE_IOCTL_LABEL);
            }
            file_ioctl_target::release_output(iosb_pin);
            if let Some(buffer) = system_buffer {
                if !release_system_buffer(buffer) {
                    crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 11]);
                }
            }
            return Err(status);
            }
        };
        Ok(SourceBufferedDispatchLease {
            source: source.take(),
            device,
            code: io_control_code,
            method,
            internal,
            input,
            output_initial,
            output_capacity: output_buffer_length,
            output_va,
            iosb_va,
            event,
            event_va,
            image_map_owner: WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire),
            system_buffer,
            auxiliary,
            iosb_pin,
            output_pin,
            input_second_pin,
            event_lease,
        })
    })();
    if result.is_err() && !release_dispatch(source.take().unwrap()) {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 13]);
    }
    result
}

/// Only the terminal/ACK owner may release this lease. An uncertain identity
/// never authorizes freeing a reused source or SystemBuffer allocation.
unsafe fn finish_buffered_dispatch(
    lease: &mut SourceBufferedDispatchLease,
    retire_source: bool,
    mirror_event: Option<u64>,
) -> bool {
    if !lease.is_live() {
        return false;
    }
    if retire_source {
        let source = lease.source.as_ref().unwrap();
        if !source_irp_aux::contains_exact(source.ticket, source.allocation) {
            return false;
        }
    }
    let event = lease.event_lease.take();
    file_ioctl_target::release_output(core::mem::replace(
        &mut lease.output_pin,
        file_ioctl_target::PinnedIoctlOutput::None,
    ));
    if let Some(pin) = lease.input_second_pin.take() {
        provider_input::release_input(pin, W32_SOURCE_IOCTL_LABEL);
    }
    file_ioctl_target::release_output(core::mem::replace(
        &mut lease.iosb_pin,
        file_ioctl_target::PinnedIoctlOutput::None,
    ));
    if let Some(buffer) = lease.system_buffer.take() {
        let address = buffer.address;
        if !release_system_buffer(buffer) {
            crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 14]);
        }
    }
    let source = lease.source.take().unwrap();
    let address = source.allocation.catalog.base;
    let ticket = source.ticket;
    let allocation = source.allocation;
    if !release_dispatch(source)
        || (retire_source
            && (!source_irp_aux::retire_exact(ticket, allocation) || !retire(address, ticket)))
    {
        crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 15]);
    }
    finish_terminal_event(event, lease.event_va, mirror_event)
}

pub(crate) unsafe fn release_buffered_dispatch(lease: &mut SourceBufferedDispatchLease) -> bool {
    finish_buffered_dispatch(lease, true, None)
}

pub(crate) unsafe fn commit_buffered_dispatch(lease: &mut SourceBufferedDispatchLease, sequence: u64) -> bool {
    if lease.event_lease.is_some() != (sequence != 0) { return false; }
    finish_buffered_dispatch(lease, true, Some(sequence))
}

pub(crate) unsafe fn finish_terminal_event(
    event: Option<nt_provider_wait::ProviderLocalEventLease>,
    body: u64,
    mirror_sequence: Option<u64>,
) -> bool {
    let Some(event) = event else { return true };
    let _metadata = ProviderMetadataGuard::acquire();
    let valid = provider_local_events().is_some_and(|events| {
        events.snapshot(event.id).is_ok_and(|snapshot| {
            snapshot.body == body && snapshot.canonical == Some(event.canonical)
        })
    });
    if !valid {
        crate::provider_bugcheck::report(0xc4, [0x57495250, body, 0, 93]);
    }
    // The source is already retired; publishing local signaled state cannot expose live IRP pins.
    if let Some(sequence) = mirror_sequence {
        let apply = provider_local_events_mut().expect("retained completion Event catalog")
            .observe_state(event, sequence, true).unwrap_or_else(|_| {
                crate::provider_bugcheck::report(0xc4, [0x57495250, body, sequence, 95])
            });
        if apply { mirror_projected_event_state(body, true); }
    }
    if provider_local_events_mut().is_none_or(|events| events.release_lease(event).is_err()) {
        crate::provider_bugcheck::report(0xc4, [0x57495250, body, 0, 94]);
    }
    true
}

/// Transfer admission to the authenticated root transaction without retiring
/// the builder-owned source. Root must acquire its own exact lease before entry.
pub(crate) unsafe fn release_buffered_admission(
    lease: &mut SourceBufferedDispatchLease,
) -> bool {
    finish_buffered_dispatch(lease, false, None)
}

#[path = "win32k_source_irp_pnp.rs"]
mod pnp;
pub(crate) use pnp::{
    SourcePnpDispatchLease, abort_pnp_dispatch, admit_pnp_target_relation,
    release_pnp_dispatch, commit_pnp_dispatch,
};

#[path = "win32k_source_irp_relation.rs"]
mod relation;
pub(crate) use relation::{SourceRelationAllocationLease, allocate_target_relation};
