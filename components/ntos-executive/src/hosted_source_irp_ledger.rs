//! Root-owned lifetime authority for driver-allocated source IRPs.

use super::*;
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_auxiliary::{
    SourceIrpAuxiliary, SourceIrpAuxiliaryError, SourceIrpAuxiliaryLedger,
    SourceIrpAuxiliaryPhase, SourceIrpCompletionOwner, SourceMdlAllocationIdentity,
    SourceMemoryIdentity, SourcePoolAllocationIdentity,
};
use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpLedger, SourceIrpLedgerError, SourceIrpOwner, SourceIrpRetirement,
};

static LOCK: AtomicU64 = AtomicU64::new(0);
static mut LEDGER: SourceIrpLedger = SourceIrpLedger::new();
static mut AUXILIARY: SourceIrpAuxiliaryLedger = SourceIrpAuxiliaryLedger::new();

struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(0, Ordering::Release);
    }
}

fn lock() -> Guard {
    while LOCK
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        crate::yield_now();
    }
    Guard
}

fn ledger() -> &'static mut SourceIrpLedger {
    // The lock is held at every call site; no reference survives an external operation.
    unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) }
}

fn auxiliary() -> &'static mut SourceIrpAuxiliaryLedger {
    // Serialized by the source-IRP ownership lock alongside the primary ledger.
    unsafe { &mut *core::ptr::addr_of_mut!(AUXILIARY) }
}

unsafe fn pool_range_identity_unlocked(
    inst: DriverInstance,
    component_address: u64,
    bytes: u64,
) -> Option<SourcePoolAllocationIdentity> {
    if bytes == 0 || component_address < FSD_POOL_VADDR {
        return None;
    }
    let used = read_volatile(inst.exec_pool_va as *const u64);
    let offset = component_address.checked_sub(FSD_POOL_VADDR)?;
    let allocation = nt_io_manager::hosted_pool_range::walk_hosted_pool_allocation(
        used,
        POOL_DATA_OFF,
        offset,
        bytes,
        |header| {
            let address = inst.exec_pool_va.checked_add(header)?;
            Some(read_volatile(address as *const u64))
        },
    )?;
    let base = FSD_POOL_VADDR.checked_add(allocation.base)?;
    if hosted_instance_pool_allocation_is_free_unlocked(inst, base) != Some(false) {
        return None;
    }
    let exec = inst.exec_pool_va.checked_add(allocation.base)?;
    let generation = read_volatile((exec - 8) as *const u64);
    (generation != 0).then_some(SourcePoolAllocationIdentity {
        component_address: base,
        capacity: allocation.capacity,
        pool_generation: generation,
    })
}

unsafe fn exact_pool_identity_unlocked(
    inst: DriverInstance,
    component_address: u64,
    bytes: u64,
) -> Option<SourcePoolAllocationIdentity> {
    let identity = pool_range_identity_unlocked(inst, component_address, bytes)?;
    (identity.component_address == component_address).then_some(identity)
}

unsafe fn mapped_memory_identity_unlocked(
    instance_index: usize,
    inst: DriverInstance,
    runtime: Option<HostedDriverThreadRuntime>,
    component_address: u64,
    bytes: u64,
) -> Option<SourceMemoryIdentity> {
    if let Some(allocation) = pool_range_identity_unlocked(inst, component_address, bytes) {
        return Some(SourceMemoryIdentity::Pool {
            allocation,
            component_address,
            bytes,
        });
    }
    let exec_address = component_to_exec_va_for_instance(
        instance_index,
        inst,
        component_address,
        bytes,
    )
    .or_else(|| {
        runtime.and_then(|runtime| {
            hosted_worker_component_to_exec_va(runtime, component_address, bytes)
        })
    })?;
    Some(SourceMemoryIdentity::MappedRange {
        component_address,
        bytes,
        exec_address,
    })
}

unsafe fn memory_identity_matches_unlocked(
    instance_index: usize,
    inst: DriverInstance,
    identity: SourceMemoryIdentity,
) -> bool {
    match identity {
        SourceMemoryIdentity::Pool {
            allocation,
            component_address,
            bytes,
        } => pool_range_identity_unlocked(inst, component_address, bytes) == Some(allocation),
        SourceMemoryIdentity::MappedRange {
            component_address,
            bytes,
            exec_address,
        } => component_to_exec_va_for_instance(instance_index, inst, component_address, bytes)
            .or_else(|| {
                hosted_driver_runtime_for_worker_component_range(
                    instance_index,
                    component_address,
                    bytes,
                )
                .and_then(|runtime| {
                    hosted_worker_component_to_exec_va(runtime, component_address, bytes)
                })
            }) == Some(exec_address),
    }
}

unsafe fn mdl_identity_unlocked(
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    mdl: u64,
    expected_length: u32,
) -> Option<(SourceMdlAllocationIdentity, u64)> {
    let pool = exact_pool_identity_unlocked(inst, mdl, nt_mdl::MDL_SIZE as u64)?;
    let key = hosted_mdl_key(domain, mdl)?;
    let registry = hosted_mdl_registry_mut();
    let id = registry.id_for(key)?;
    if registry.byte_count(id) != Some(expected_length) || !registry.is_locked(id) {
        return None;
    }
    let virtual_address = registry.virtual_address(id)?;
    let mdl_exec = inst.exec_pool_va + mdl.saturating_sub(FSD_POOL_VADDR);
    let raw_flags = read_unaligned((mdl_exec + nt_mdl::MDL_OFF_FLAGS) as *const i16);
    let raw_start = read_unaligned((mdl_exec + nt_mdl::MDL_OFF_START_VA) as *const u64);
    let raw_offset = read_unaligned((mdl_exec + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32);
    if read_unaligned((mdl_exec + nt_mdl::MDL_OFF_SIZE) as *const i16)
        != nt_mdl::MDL_SIZE as i16
        || read_unaligned((mdl_exec + nt_mdl::MDL_OFF_BYTE_COUNT) as *const u32)
            != expected_length
        || raw_flags & nt_mdl::MDL_PAGES_LOCKED == 0
        || raw_start.checked_add(u64::from(raw_offset)) != Some(virtual_address)
    {
        return None;
    }
    Some((
        SourceMdlAllocationIdentity {
            pool,
            registry_generation: registry.generation(id)?,
        },
        virtual_address,
    ))
}

unsafe fn mdl_identity_matches_unlocked(
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    mdl: SourceMdlAllocationIdentity,
) -> bool {
    if exact_pool_identity_unlocked(inst, mdl.pool.component_address, nt_mdl::MDL_SIZE as u64)
        != Some(mdl.pool)
    {
        return false;
    }
    let Some(key) = hosted_mdl_key(domain, mdl.pool.component_address) else {
        return false;
    };
    let registry = hosted_mdl_registry_mut();
    registry.id_for(key).is_some_and(|id| {
        registry.generation(id) == Some(mdl.registry_generation) && registry.is_locked(id)
    })
}

fn memory_component_address(identity: SourceMemoryIdentity) -> u64 {
    match identity {
        SourceMemoryIdentity::Pool {
            component_address, ..
        }
        | SourceMemoryIdentity::MappedRange {
            component_address, ..
        } => component_address,
    }
}

fn memory_bytes(identity: SourceMemoryIdentity) -> u64 {
    match identity {
        SourceMemoryIdentity::Pool { bytes, .. }
        | SourceMemoryIdentity::MappedRange { bytes, .. } => bytes,
    }
}

unsafe fn capture_auxiliary_unlocked(
    instance_index: usize,
    inst: DriverInstance,
    caller: &HostedDriverCaller,
    expected_thread: u64,
    ticket: SourceIrpTicket,
    source: SourceIrpAllocation,
) -> Option<SourceIrpAuxiliary> {
    let irp = hosted_pool_allocation_exec_va(
        inst.exec_pool_va,
        source.component_address,
        source.bytes,
    )?;
    if allocation_unlocked(
        instance_index,
        inst,
        source.component_address,
        source.bytes,
        source.stack_count,
    ) != Some(source)
    {
        return None;
    }
    let current_location = read_unaligned(
        (irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *const u8,
    );
    let current_stack = read_unaligned((irp + 0xb8) as *const u64);
    if current_location != source.stack_count + 1
        || current_stack != source.component_address + source.bytes
    {
        return None;
    }
    let stack = irp + source.bytes - WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    let major = read_unaligned(stack as *const u8);
    if !matches!(
        major,
        major::IRP_MJ_READ
            | major::IRP_MJ_WRITE
            | major::IRP_MJ_FLUSH_BUFFERS
            | major::IRP_MJ_SHUTDOWN
            | major::IRP_MJ_PNP
            | major::IRP_MJ_POWER
    ) {
        return None;
    }
    let transfer = matches!(major, major::IRP_MJ_READ | major::IRP_MJ_WRITE);
    let length = if transfer {
        read_unaligned((stack + 0x08) as *const u32)
    } else {
        0
    };
    let flags = read_unaligned((irp + 0x10) as *const u32);
    let system_address = read_unaligned((irp + 0x18) as *const u64);
    let mdl_address = read_unaligned((irp + 0x08) as *const u64);
    let user_buffer = read_unaligned((irp + 0x70) as *const u64);
    if system_address != 0 && mdl_address != 0 {
        return None;
    }

    let system_buffer = if system_address != 0 {
        let expected = IRP_BUFFERED_IO
            | IRP_DEALLOCATE_BUFFER
            | if major == major::IRP_MJ_READ {
                IRP_INPUT_OPERATION
            } else {
                0
            };
        if !transfer || length == 0 || flags != expected {
            return None;
        }
        Some(exact_pool_identity_unlocked(
            inst,
            system_address,
            u64::from(length),
        )?)
    } else {
        None
    };

    let (mdl, mdl_buffer_address) = if mdl_address != 0 {
        if !transfer || length == 0 || flags != 0 || user_buffer != 0 {
            return None;
        }
        let (identity, virtual_address) =
            mdl_identity_unlocked(inst, source.domain, mdl_address, length)?;
        (Some(identity), Some(virtual_address))
    } else {
        (None, None)
    };

    let transfer_address = if length == 0 || major == major::IRP_MJ_WRITE && system_buffer.is_some()
    {
        None
    } else if let Some(address) = mdl_buffer_address {
        Some(address)
    } else {
        (user_buffer != 0).then_some(user_buffer)
    };
    if transfer && length != 0 && transfer_address.is_none() {
        return None;
    }
    if !transfer && (flags != 0 || system_address != 0 || mdl_address != 0 || user_buffer != 0) {
        return None;
    }
    let transfer_buffer = transfer_address.and_then(|address| {
        mapped_memory_identity_unlocked(
            instance_index,
            inst,
            caller.runtime,
            address,
            u64::from(length),
        )
    });
    if transfer_address.is_some() && transfer_buffer.is_none() {
        return None;
    }

    let event_address = read_unaligned((irp + 0x50) as *const u64);
    let iosb_address = read_unaligned((irp + 0x48) as *const u64);
    let thread_object = read_unaligned((irp + 0x98) as *const u64);
    let event = mapped_memory_identity_unlocked(
        instance_index,
        inst,
        caller.runtime,
        event_address,
        nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64,
    )?;
    let iosb = mapped_memory_identity_unlocked(
        instance_index,
        inst,
        caller.runtime,
        iosb_address,
        16,
    )?;
    let event_exec = match event {
        SourceMemoryIdentity::Pool {
            allocation,
            component_address,
            ..
        } => inst.exec_pool_va
            + allocation.component_address.saturating_sub(FSD_POOL_VADDR)
            + component_address.saturating_sub(allocation.component_address),
        SourceMemoryIdentity::MappedRange { exec_address, .. } => exec_address,
    };
    if read_unaligned(event_exec as *const u8) > 1
        || read_unaligned(
            (event_exec + nt_kernel_exec::kevent::kevent_layout::SIZE as u64) as *const u8,
        ) != 6
        || read_unaligned(
            (event_exec + nt_kernel_exec::kevent::kevent_layout::WAIT_LIST_HEAD as u64)
                as *const u64,
        ) != event_address + nt_kernel_exec::kevent::kevent_layout::WAIT_LIST_HEAD as u64
        || read_unaligned(
            (event_exec + nt_kernel_exec::kevent::kevent_layout::WAIT_LIST_HEAD as u64 + 8)
                as *const u64,
        ) != event_address + nt_kernel_exec::kevent::kevent_layout::WAIT_LIST_HEAD as u64
    {
        return None;
    }
    if thread_object == 0 || thread_object != expected_thread {
        return None;
    }
    Some(SourceIrpAuxiliary {
        source,
        ticket,
        system_buffer,
        mdl,
        transfer_buffer,
        completion: SourceIrpCompletionOwner {
            thread_handle: caller.thread_handle,
            thread_object,
            event,
            iosb,
        },
    })
}

unsafe fn auxiliary_matches_unlocked(
    instance_index: usize,
    inst: DriverInstance,
    auxiliary: SourceIrpAuxiliary,
    phase: SourceIrpAuxiliaryPhase,
) -> bool {
    let Some(irp) = hosted_pool_allocation_exec_va(
        inst.exec_pool_va,
        auxiliary.source.component_address,
        auxiliary.source.bytes,
    ) else {
        return false;
    };
    let expected_system = auxiliary
        .system_buffer
        .map_or(0, |child| child.component_address);
    let expected_mdl = auxiliary
        .mdl
        .map_or(0, |child| child.pool.component_address);
    let expected_transfer = auxiliary
        .transfer_buffer
        .map_or(0, memory_component_address);
    let expected_user = if auxiliary.mdl.is_some() {
        0
    } else if auxiliary.system_buffer.is_some() {
        if auxiliary.transfer_buffer.is_some() {
            expected_transfer
        } else {
            0
        }
    } else {
        expected_transfer
    };
    if allocation_unlocked(
        instance_index,
        inst,
        auxiliary.source.component_address,
        auxiliary.source.bytes,
        auxiliary.source.stack_count,
    ) != Some(auxiliary.source)
        || read_unaligned((irp + 0x18) as *const u64) != expected_system
        || read_unaligned((irp + 0x08) as *const u64) != expected_mdl
        || read_unaligned((irp + 0x70) as *const u64) != expected_user
        || read_unaligned((irp + 0x98) as *const u64)
            != auxiliary.completion.thread_object
        || read_unaligned((irp + 0x50) as *const u64)
            != memory_component_address(auxiliary.completion.event)
        || read_unaligned((irp + 0x48) as *const u64)
            != memory_component_address(auxiliary.completion.iosb)
        || !memory_identity_matches_unlocked(
            instance_index,
            inst,
            auxiliary.completion.event,
        )
        || !memory_identity_matches_unlocked(
            instance_index,
            inst,
            auxiliary.completion.iosb,
        )
    {
        return false;
    }
    if phase == SourceIrpAuxiliaryPhase::Completing {
        return true;
    }
    auxiliary.system_buffer.is_none_or(|child| {
        exact_pool_identity_unlocked(inst, child.component_address, 1) == Some(child)
    }) && auxiliary.mdl.is_none_or(|mdl| {
        if !mdl_identity_matches_unlocked(inst, auxiliary.source.domain, mdl) {
            return false;
        }
        let Some(key) = hosted_mdl_key(auxiliary.source.domain, mdl.pool.component_address) else {
            return false;
        };
        let registry = hosted_mdl_registry_mut();
        registry.id_for(key).is_some_and(|id| {
            registry.virtual_address(id) == Some(expected_transfer)
        })
    }) && auxiliary.transfer_buffer.is_none_or(|buffer| {
        memory_identity_matches_unlocked(instance_index, inst, buffer)
    })
}

fn allocation(
    instance_index: usize,
    inst: DriverInstance,
    component_address: u64,
    bytes: u64,
    stack_count: u8,
) -> Option<SourceIrpAllocation> {
    let _pool_guard = unsafe { hosted_instance_pool_lock(inst.exec_pool_va)? };
    allocation_unlocked(instance_index, inst, component_address, bytes, stack_count)
}

fn allocation_unlocked(
    instance_index: usize,
    inst: DriverInstance,
    component_address: u64,
    bytes: u64,
    stack_count: u8,
) -> Option<SourceIrpAllocation> {
    if !(1..=32).contains(&stack_count) {
        return None;
    }
    let expected = (WDM_X64_IRP_SIZE as u64)
        .checked_add((stack_count as u64).checked_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64)?)?;
    if bytes != expected || expected > u16::MAX as u64 {
        return None;
    }
    if unsafe { hosted_instance_pool_allocation_is_free_unlocked(inst, component_address) }
        != Some(false)
    {
        return None;
    }
    let exec_address =
        unsafe { hosted_pool_allocation_exec_va(inst.exec_pool_va, component_address, bytes)? };
    let pool_generation = unsafe { read_volatile((exec_address - 8) as *const u64) };
    let valid_header = unsafe {
        read_unaligned(exec_address as *const u16) == WDM_X64_IO_TYPE_IRP
            && read_unaligned((exec_address + 2) as *const u16) as u64 == bytes
            && read_unaligned((exec_address + WDM_X64_IRP_STACK_COUNT_OFFSET) as *const u8)
                == stack_count
    };
    if !valid_header || pool_generation == 0 {
        return None;
    }
    Some(SourceIrpAllocation {
        owner: SourceIrpOwner::HostedDriver(instance_index),
        domain: instance_domain_identity(inst)?,
        component_address,
        bytes,
        stack_count,
        pool_generation,
    })
}

pub(super) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    component_address: u64,
    bytes: u64,
    stack_count: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64) {
    let Some((instance_index, inst)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0);
    };
    if hosted_driver_pump_caller_tcb(ch, active_reply_cap, caller_badge).is_none() {
        return (STATUS_INVALID_HANDLE, 0, 0);
    }
    match op {
        1 => {
            let Some(stack_count) = u8::try_from(stack_count).ok() else {
                return (STATUS_INVALID_PARAMETER, 0, 0);
            };
            let _guard = lock();
            let Some(allocation) =
                allocation(instance_index, inst, component_address, bytes, stack_count)
            else {
                return (STATUS_INVALID_PARAMETER, 0, 0);
            };
            match ledger().register(allocation) {
                Ok(ticket) => (STATUS_SUCCESS, ticket.id.get(), ticket.generation.get()),
                Err(SourceIrpLedgerError::AlreadyLive) => {
                    (nt_status::NtStatus::OBJECT_NAME_COLLISION.raw(), 0, 0)
                }
                Err(SourceIrpLedgerError::Exhausted) => (STATUS_INSUFFICIENT_RESOURCES, 0, 0),
                Err(_) => (STATUS_INVALID_PARAMETER, 0, 0),
            }
        }
        4 if bytes == 0 && stack_count == 0 => {
            let Some(domain) = instance_domain_identity(inst) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let Some(caller) = hosted_driver_caller(instance_index, inst, caller_badge) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let expected_thread = match unsafe { crate::provider_registry_caller::resolve(ch) }
                .and_then(|native_caller| unsafe {
                    driver_ps_context::project(inst, native_caller)
                        .map(|(_, _, _, thread, _)| thread)
                })
            {
                Ok(thread) if thread != 0 => thread,
                _ => return (STATUS_INVALID_HANDLE, 0, 0),
            };
            let _guard = lock();
            let Some(_pool_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) })
            else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let Some((ticket, source)) = ledger().registered(
                SourceIrpOwner::HostedDriver(instance_index),
                domain,
                component_address,
            ) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let Some(owner) = (unsafe {
                capture_auxiliary_unlocked(
                    instance_index,
                    inst,
                    &caller,
                    expected_thread,
                    ticket,
                    source,
                )
            }) else {
                return (STATUS_INVALID_PARAMETER, 0, 0);
            };
            match auxiliary().register(owner) {
                Ok(()) => (STATUS_SUCCESS, ticket.id.get(), ticket.generation.get()),
                Err(SourceIrpAuxiliaryError::NoCapacity) => {
                    (STATUS_INSUFFICIENT_RESOURCES, 0, 0)
                }
                Err(SourceIrpAuxiliaryError::AlreadyLive) => {
                    (nt_status::NtStatus::OBJECT_NAME_COLLISION.raw(), 0, 0)
                }
                Err(_) => (STATUS_INVALID_PARAMETER, 0, 0),
            }
        }
        5 if bytes == 0 && stack_count == 0 => {
            let Some(domain) = instance_domain_identity(inst) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let Some(_caller) = hosted_driver_caller(instance_index, inst, caller_badge) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let _guard = lock();
            let Some(_pool_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) })
            else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let Some((ticket, source)) = ledger().registered(
                SourceIrpOwner::HostedDriver(instance_index),
                domain,
                component_address,
            ) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let Ok((owner, phase)) = auxiliary().snapshot(ticket, source) else {
                return (nt_status::NtStatus::OBJECT_NAME_NOT_FOUND.raw(), 0, 0);
            };
            if phase != SourceIrpAuxiliaryPhase::Protected
                || !unsafe { auxiliary_matches_unlocked(instance_index, inst, owner, phase) }
            {
                return (STATUS_INVALID_HANDLE, 0, 0);
            }
            match auxiliary().begin_completion(ticket, source) {
                Ok(owner) => (
                    STATUS_SUCCESS,
                    owner.transfer_buffer.map_or(0, memory_bytes),
                    ticket.generation.get(),
                ),
                Err(_) => (STATUS_INVALID_HANDLE, 0, 0),
            }
        }
        2 | 3 if bytes == 0 && stack_count == 0 => {
            let Some(domain) = instance_domain_identity(inst) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let _guard = lock();
            let Some(_pool_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) })
            else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            if op == 3
                && auxiliary().protected_pool_child(
                    SourceIrpOwner::HostedDriver(instance_index),
                    domain,
                    component_address,
                )
            {
                return (nt_status::NtStatus::PENDING.raw(), 0, 0);
            }
            let owner = ledger().allocation_for(
                SourceIrpOwner::HostedDriver(instance_index),
                domain,
                component_address,
            );
            let Some(owner) = owner else {
                return if op == 3
                    && unsafe {
                        hosted_instance_pool_allocation_is_free_unlocked(inst, component_address)
                    } == Some(false)
                    && unsafe { hosted_instance_pool_free_unlocked(inst, component_address) }
                {
                    (STATUS_SUCCESS, 0, 0)
                } else {
                    (STATUS_INVALID_HANDLE, 0, 0)
                };
            };
            if allocation_unlocked(
                instance_index,
                inst,
                component_address,
                owner.bytes,
                owner.stack_count,
            ) != Some(owner)
            {
                return (STATUS_INVALID_HANDLE, 0, 0);
            }
            match ledger().prepare_free(
                SourceIrpOwner::HostedDriver(instance_index),
                domain,
                component_address,
            ) {
                Ok(SourceIrpRetirement::Retired(ticket)) => {
                    if !unsafe { hosted_instance_pool_free_unlocked(inst, component_address) } {
                        return (STATUS_INVALID_HANDLE, 0, 0);
                    }
                    if ledger().retire(ticket, owner).is_err() {
                        unsafe {
                            crate::provider_bugcheck::report(
                                0xc4,
                                [
                                    FSD_SERVICE_SOURCE_IRP_LABEL,
                                    op,
                                    component_address,
                                    ticket.id.get(),
                                ],
                            );
                        }
                    }
                    match auxiliary().retire(ticket, owner) {
                        Ok(_) | Err(SourceIrpAuxiliaryError::NotFound) => {}
                        Err(_) => unsafe {
                            crate::provider_bugcheck::report(
                                0xc4,
                                [FSD_SERVICE_SOURCE_IRP_LABEL, 6, component_address, ticket.id.get()],
                            );
                        },
                    }
                    (STATUS_SUCCESS, ticket.id.get(), ticket.generation.get())
                }
                Ok(SourceIrpRetirement::Deferred(ticket)) => (
                    nt_status::NtStatus::PENDING.raw(),
                    ticket.id.get(),
                    ticket.generation.get(),
                ),
                Err(SourceIrpLedgerError::Pinned) => {
                    (nt_status::NtStatus::DELETE_PENDING.raw(), 0, 0)
                }
                Err(_) => (STATUS_INVALID_HANDLE, 0, 0),
            }
        }
        _ => (STATUS_INVALID_PARAMETER, 0, 0),
    }
}

pub(super) fn pin(
    instance_index: usize,
    domain: HostedDomainIdentity,
    component_address: u64,
) -> Option<(SourceIrpTicket, SourceIrpAllocation)> {
    let inst = instance(instance_index)?;
    if instance_domain_identity(inst)? != domain {
        return None;
    }
    let _guard = lock();
    let (ticket, owner) = ledger()
        .pin(
            SourceIrpOwner::HostedDriver(instance_index),
            domain,
            component_address,
        )
        .ok()?;
    let Some(_pool_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) }) else {
        let _ = ledger().unpin(ticket);
        return None;
    };
    if allocation_unlocked(instance_index, inst, component_address, owner.bytes, owner.stack_count)
        != Some(owner)
    {
        let _ = ledger().unpin(ticket);
        return None;
    }
    match auxiliary().snapshot(ticket, owner) {
        Ok((auxiliary, phase))
            if phase == SourceIrpAuxiliaryPhase::Protected
                && unsafe {
                    auxiliary_matches_unlocked(instance_index, inst, auxiliary, phase)
                } => {}
        Err(SourceIrpAuxiliaryError::NotFound) => {}
        _ => {
            let _ = ledger().unpin(ticket);
            return None;
        }
    }
    Some((ticket, owner))
}

pub(super) fn matches(
    instance_index: usize,
    owner: SourceIrpAllocation,
    ticket: SourceIrpTicket,
) -> bool {
    let _guard = lock();
    if !ledger().matches(SourceIrpOwner::HostedDriver(instance_index), owner, ticket) {
        return false;
    }
    let Some(inst) = instance(instance_index) else { return false; };
    let Some(_pool_guard) = (unsafe { hosted_instance_pool_lock(inst.exec_pool_va) }) else {
        return false;
    };
    match auxiliary().snapshot(ticket, owner) {
        Ok((auxiliary, phase)) => unsafe {
            auxiliary_matches_unlocked(instance_index, inst, auxiliary, phase)
        },
        Err(SourceIrpAuxiliaryError::NotFound) => true,
        Err(_) => false,
    }
}

pub(super) fn mdl_release_allowed(
    instance_index: usize,
    domain: HostedDomainIdentity,
    mdl: u64,
) -> bool {
    let _guard = lock();
    !auxiliary().protected_pool_child(
        SourceIrpOwner::HostedDriver(instance_index),
        domain,
        mdl,
    )
}

pub(super) fn unpin(ticket: SourceIrpTicket) -> bool {
    let _guard = lock();
    ledger().unpin(ticket).is_ok()
}

pub(super) fn arm_deferred_free(ticket: SourceIrpTicket) -> bool {
    let _guard = lock();
    ledger().arm_deferred_free(ticket).is_ok()
}

pub(super) fn deferred_free_requested(ticket: SourceIrpTicket) -> bool {
    let _guard = lock();
    ledger().deferred_free_requested(ticket)
}

pub(super) fn live_for_instance(instance_index: usize, domain: HostedDomainIdentity) -> usize {
    let _guard = lock();
    ledger().live_for_owner(SourceIrpOwner::HostedDriver(instance_index), domain)
}
