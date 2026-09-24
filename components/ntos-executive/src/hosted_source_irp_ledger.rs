//! Root-owned lifetime authority for driver-allocated source IRPs.

use super::*;
use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpLedger, SourceIrpLedgerError, SourceIrpRetirement,
};

static LOCK: AtomicU64 = AtomicU64::new(0);
static mut LEDGER: SourceIrpLedger = SourceIrpLedger::new();

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

fn allocation(
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
    let exec_address =
        unsafe { hosted_instance_pool_allocation_exec_if_live(inst, component_address, bytes)? };
    let valid_header = unsafe {
        read_unaligned(exec_address as *const u16) == WDM_X64_IO_TYPE_IRP
            && read_unaligned((exec_address + 2) as *const u16) as u64 == bytes
            && read_unaligned((exec_address + WDM_X64_IRP_STACK_COUNT_OFFSET) as *const u8)
                == stack_count
    };
    if !valid_header {
        return None;
    }
    Some(SourceIrpAllocation {
        instance: instance_index,
        domain: instance_domain_identity(inst)?,
        component_address,
        bytes,
        stack_count,
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
            let Some(allocation) =
                allocation(instance_index, inst, component_address, bytes, stack_count)
            else {
                return (STATUS_INVALID_PARAMETER, 0, 0);
            };
            let _guard = lock();
            match ledger().register(allocation) {
                Ok(ticket) => (STATUS_SUCCESS, ticket.id.get(), ticket.generation.get()),
                Err(SourceIrpLedgerError::AlreadyLive) => {
                    (nt_status::NtStatus::OBJECT_NAME_COLLISION.raw(), 0, 0)
                }
                Err(SourceIrpLedgerError::Exhausted) => (STATUS_INSUFFICIENT_RESOURCES, 0, 0),
                Err(_) => (STATUS_INVALID_PARAMETER, 0, 0),
            }
        }
        2 if bytes == 0 && stack_count == 0 => {
            let Some(domain) = instance_domain_identity(inst) else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            let _guard = lock();
            let Some(owner) = ledger().allocation_for(instance_index, domain, component_address)
            else {
                return (STATUS_INVALID_HANDLE, 0, 0);
            };
            if allocation(
                instance_index,
                inst,
                component_address,
                owner.bytes,
                owner.stack_count,
            ) != Some(owner)
            {
                return (STATUS_INVALID_HANDLE, 0, 0);
            }
            match ledger().request_free(instance_index, domain, component_address) {
                Ok(SourceIrpRetirement::Retired(ticket)) => {
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
        .pin(instance_index, domain, component_address)
        .ok()?;
    if allocation(
        instance_index,
        inst,
        component_address,
        owner.bytes,
        owner.stack_count,
    ) != Some(owner)
    {
        let _ = ledger().unpin(ticket);
        return None;
    }
    Some((ticket, owner))
}

pub(super) fn matches(
    instance_index: usize,
    owner: SourceIrpAllocation,
    ticket: SourceIrpTicket,
) -> bool {
    let _guard = lock();
    ledger().matches(instance_index, owner, ticket)
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
    ledger().live_for_instance(instance_index, domain)
}
