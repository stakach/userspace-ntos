//! Native Event pointer references backed by canonical handle and EventStore
//! ownership. The System-table kernel handle is resolved before the provider
//! body is installed; body memory stays pinned until exact reclaim ACK.

use super::*;
use nt_hosted_runtime::{HostedEventProjectionKey, HostedEventProjectionLifetime};

pub(super) const LABEL: u64 = 0x7D4;
const REFERENCE: u64 = 1;
const DEREFERENCE: u64 = 2;
const RETAIN_POINTER: u64 = 4;
const SET: u64 = 5;
const RESET: u64 = 6;
const CLEAR: u64 = 7;
const PULSE: u64 = 8;
const READ: u64 = 9;
const ACK_DEREFERENCE: u64 = 10;
const STATUS_UNOWNED_OBJECT: i32 = STATUS_NOT_SUPPORTED;
const BODY_BYTES: u64 = nt_kernel_exec::kevent::kevent_layout::SIZE_OF as u64;
const BODY_ALLOCATION_BYTES: u64 = BODY_BYTES + 16;
const EVENT_BODY_MARKER: u64 = 0x4556_454e_5450_5452;

struct EventProjection {
    key: HostedEventProjectionKey,
    instance: usize,
    domain: HostedDomainIdentity,
    pml4: u64,
    id: u64,
    body: u64,
    lifetime: HostedEventProjectionLifetime,
    allocation: nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity,
    pin: Option<hosted_device_allocations::TemporaryPoolPin>,
}

static mut PROJECTIONS: Vec<EventProjection> = Vec::new();

#[derive(Clone, Copy)]
struct PendingDereference {
    key: HostedEventProjectionKey,
    route: nt_component_suspension::peer_registry::PeerRoute,
    thread_handle: u64,
}

static mut PENDING_DEREFERENCES: Vec<PendingDereference> = Vec::new();

#[derive(Clone, Copy)]
pub(super) struct EventProjectionWaitLease {
    key: HostedEventProjectionKey,
    instance: usize,
}

/// Resolve a root mapping only through an extant generation-bound projection.
/// Ordinary embedded KEVENTs continue through the existing dispatcher path.
unsafe fn projected_id_for_exec(exec_body: u64) -> Option<u64> {
    let rows = &*core::ptr::addr_of!(PROJECTIONS);
    rows.iter().find_map(|row| {
        let inst = instance(row.instance)?;
        let domain = instance_domain_identity(inst)?;
        if row.pin.is_none() || domain != row.domain || inst.pml4 != row.pml4
            || !row.key.matches(domain.domain_id.raw(), domain.cookie, inst.pml4,
                row.id, row.body, row.allocation.pool_generation)
            || hosted_device_allocations::capture_range_allocation(inst,
                row.body, BODY_ALLOCATION_BYTES).ok() != Some(row.allocation)
        { return None; }
        (hosted_instance_pool_allocation_exec_if_live(inst, row.body,
            BODY_ALLOCATION_BYTES) == Some(exec_body)).then_some(row.id)
    })
}

pub(super) unsafe fn projected_ready_for_exec(exec_body: u64) -> Option<Result<bool, i32>> {
    let id = projected_id_for_exec(exec_body)?;
    Some(crate::service_sec_image::registry_live_handler_pointer()
        .ok().and_then(|handler| (&*handler).projected_event_ready(id))
        .ok_or(STATUS_INVALID_HANDLE))
}

pub(super) unsafe fn projected_consume_for_exec(exec_body: u64) -> Option<bool> {
    let id = projected_id_for_exec(exec_body)?;
    Some(crate::service_sec_image::registry_live_handler_pointer()
        .ok().and_then(|handler| (&mut *handler).projected_event_consume(id))
        .unwrap_or(false))
}

pub(super) unsafe fn projected_ready_with_handler(
    exec_body: u64, handler: &ExecNtHandler,
) -> Option<Result<bool, i32>> {
    let id = projected_id_for_exec(exec_body)?;
    Some(handler.projected_event_ready(id).ok_or(STATUS_INVALID_HANDLE))
}

pub(super) unsafe fn projected_consume_with_handler(
    exec_body: u64, handler: &mut ExecNtHandler,
) -> Option<bool> {
    let id = projected_id_for_exec(exec_body)?;
    Some(handler.projected_event_consume(id).unwrap_or(false))
}

pub(super) unsafe fn retain_wait_for_exec(
    instance_index: usize, exec_body: u64,
) -> Option<Result<EventProjectionWaitLease, i32>> {
    let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
    let row = rows.iter_mut().find(|row| row.instance == instance_index
        && row.pin.is_some()
        && instance(row.instance).is_some_and(|inst|
            instance_domain_identity(inst) == Some(row.domain)
            && inst.pml4 == row.pml4
            && row.key.matches(row.domain.domain_id.raw(), row.domain.cookie,
                row.pml4, row.id, row.body, row.allocation.pool_generation)
            && hosted_device_allocations::capture_range_allocation(inst,
                row.body, BODY_ALLOCATION_BYTES).ok() == Some(row.allocation)
            &&
            hosted_instance_pool_allocation_exec_if_live(inst, row.body,
                BODY_ALLOCATION_BYTES) == Some(exec_body)))?;
    if row.lifetime.references() == 0 { return Some(Err(STATUS_INVALID_HANDLE)); }
    let handler = match crate::service_sec_image::registry_live_handler_pointer() {
        Ok(handler) => handler,
        Err(status) => return Some(Err(status as i32)),
    };
    let id = nt_kernel_exec::EventObjectId(nt_types::ObjectId(row.id));
    if let Err(status) = (&mut *handler).provider_retain_native_event_pointer(id) {
        return Some(Err(status as i32));
    }
    if !row.lifetime.retain_wait() {
        if (&mut *handler).provider_dereference_native_event_pointer(id).is_err() {
            crate::provider_bugcheck::report(0xc4, [LABEL, row.body, row.id, 4]);
        }
        return Some(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    Some(Ok(EventProjectionWaitLease { key: row.key, instance: instance_index }))
}

pub(super) unsafe fn release_wait(lease: EventProjectionWaitLease) -> Result<(), i32> {
    let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
    let Some(row_index) = rows.iter().position(|row| row.key == lease.key
        && row.instance == lease.instance && row.pin.is_some()) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    let row = &mut rows[row_index];
    let mut next = row.lifetime;
    if !next.release_wait() { return Err(STATUS_INVALID_HANDLE); }
    let handler = crate::service_sec_image::registry_live_handler_pointer()
        .map_err(|status| status as i32)?;
    if next.retirable() {
        hosted_device_allocations::retire_owned_temporary_pool_allocation(
            row.pin.as_mut().expect("validated Event wait pin"))
            .map_err(|status| status.raw())?;
        row.pin = None;
    }
    let id = nt_kernel_exec::EventObjectId(nt_types::ObjectId(row.id));
    if (&mut *handler).provider_dereference_native_event_pointer(id).is_err() {
        crate::provider_bugcheck::report(0xc4, [LABEL, row.body, row.id, 5]);
    }
    row.lifetime = next;
    if next.retirable() { rows.swap_remove(row_index); }
    Ok(())
}

pub(super) unsafe fn exec_body_for_native_index_after(
    native_index: usize, handler: &ExecNtHandler, after: usize,
) -> Option<(usize, usize, u64)> {
    let id = handler.event_id_for_index(native_index)?.0 .0;
    let rows = &*core::ptr::addr_of!(PROJECTIONS);
    for (row_index, row) in rows.iter().enumerate().skip(after) {
        if row.id != id || row.pin.is_none() { continue; }
        let Some(inst) = instance(row.instance) else { continue; };
        let Some(domain) = instance_domain_identity(inst) else { continue; };
        if domain != row.domain || inst.pml4 != row.pml4
            || !row.key.matches(domain.domain_id.raw(), domain.cookie, inst.pml4,
                row.id, row.body, row.allocation.pool_generation)
        { continue; }
        let Some(exec) = hosted_instance_pool_allocation_exec_if_live(
            inst, row.body, BODY_ALLOCATION_BYTES) else { continue; };
        return Some((row_index + 1, row.instance, exec));
    }
    None
}

unsafe fn release_proposed_pin(pin: &mut hosted_device_allocations::TemporaryPoolPin,
    proposed: u64)
{
    if hosted_device_allocations::release_temporary_pool_pin(pin).is_err() {
        crate::provider_bugcheck::report(0xc4, [LABEL, proposed, BODY_ALLOCATION_BYTES, 0]);
    }
}

/// Only locally published Event bodies can enter this release path. A miss
/// lets the ordinary object handlers decide ownership without a broker probe.
pub(super) fn contains(body: u64) -> bool {
    unsafe {
        component_pool_allocation_capacity(body)
            .is_some_and(|capacity| capacity >= BODY_ALLOCATION_BYTES)
            && read_unaligned((body + BODY_BYTES) as *const u64) == EVENT_BODY_MARKER
            && read_unaligned((body + BODY_BYTES + 8) as *const u64) != 0
    }
}

pub(super) extern "win64" fn reference_object_by_handle(
    handle: u64,
    desired_access: u32,
    object_type: u64,
    access_mode: u8,
    object_out: u64,
    handle_information: u64,
) -> i32 {
    if handle == 0 || object_out == 0 || access_mode > 1
        || object_type != FSD_DATA_EX_EVENT_OBJECT_TYPE_BODY_VA
    { return STATUS_INVALID_HANDLE; }
    unsafe {
        write_unaligned(object_out as *mut u64, 0);
        let _guard = component_device_reply_lock();
        let proposed = pool_alloc(BODY_ALLOCATION_BYTES);
        if proposed == 0 { return STATUS_INSUFFICIENT_RESOURCES; }
        let (words, raw, body, id, packed) = call_on4_raw(
            (LABEL << 12) | 4,
            REFERENCE,
            handle,
            u64::from(desired_access),
            proposed | (u64::from(access_mode) << 63),
        );
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        let status = raw as u32 as i32;
        if words != 4 || !canonical || (status == STATUS_SUCCESS) != (body != 0 && id != 0) {
            crate::provider_bugcheck::report(0xc4, [LABEL, REFERENCE, words, raw]);
        }
        if status != STATUS_SUCCESS {
            pool_free(proposed);
            return status;
        }
        let metadata = packed >> 32;
        let granted = packed as u32;
        if body == proposed {
            let kind = if metadata & 1 != 0 {
                nt_kernel_exec::kevent::EventKind::Synchronization
            } else {
                nt_kernel_exec::kevent::EventKind::Notification
            };
            nt_kernel_exec::kevent::init_kevent(
                body as *mut u8, kind, metadata & 2 != 0);
            write_unaligned((body + BODY_BYTES) as *mut u64, EVENT_BODY_MARKER);
            write_unaligned((body + BODY_BYTES + 8) as *mut u64, id);
        } else {
            pool_free(proposed);
            if !contains(body)
                || read_unaligned((body + BODY_BYTES + 8) as *const u64) != id {
                crate::provider_bugcheck::report(0xc4, [LABEL, REFERENCE, body, id]);
            }
        }
        write_unaligned(object_out as *mut u64, body);
        if handle_information != 0 {
            write_unaligned(handle_information as *mut u32, 0);
            write_unaligned((handle_information + 4) as *mut u32, granted);
        }
        STATUS_SUCCESS
    }
}

pub(super) fn release_if_owned(body: u64) -> Option<u64> {
    if !contains(body) { return None; }
    unsafe {
        let id = read_unaligned((body + BODY_BYTES + 8) as *const u64);
        let (words, raw, _count, unused0, unused1) = call_on4_raw(
            (LABEL << 12) | 4, DEREFERENCE, body, 0, 0);
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused0 != 0 || unused1 != 0
            || raw as u32 as i32 != STATUS_SUCCESS
        { crate::provider_bugcheck::report(0xc4, [LABEL, DEREFERENCE, words, raw]); }
        let (ack_words, ack_raw, ack_count, ack0, ack1) = call_on4_raw(
            (LABEL << 12) | 4, ACK_DEREFERENCE, body, id, 0);
        let ack_canonical = ack_raw == ack_raw as u32 as u64
            || ack_raw == ack_raw as u32 as i32 as i64 as u64;
        if ack_words != 4 || !ack_canonical
            || ack0 != 0 || ack1 != 0 || ack_raw as u32 as i32 != STATUS_SUCCESS
        { crate::provider_bugcheck::report(0xc4, [LABEL, ACK_DEREFERENCE, body, ack_raw]); }
        Some(ack_count)
    }
}

pub(super) fn retain_if_owned(body: u64) -> Option<u64> {
    if !contains(body) { return None; }
    unsafe {
        let (words, raw, _count, unused0, unused1) = call_on4_raw(
            (LABEL << 12) | 4, RETAIN_POINTER, body, 0, 0);
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused0 != 0 || unused1 != 0
            || raw as u32 as i32 != STATUS_SUCCESS
        { crate::provider_bugcheck::report(0xc4, [LABEL, RETAIN_POINTER, words, raw]); }
        Some(body)
    }
}

pub(super) fn state_if_owned(body: u64, op: u64) -> Option<u64> {
    if !contains(body) { return None; }
    unsafe {
        let (words, raw, previous, current, unused) = call_on4_raw(
            (LABEL << 12) | 4, op, body, 0, 0);
        let canonical = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
        if words != 4 || !canonical || unused != 0 || previous > 1 || current > 1
            || raw as u32 as i32 != STATUS_SUCCESS
        { crate::provider_bugcheck::report(0xc4, [LABEL, op, body, raw]); }
        match op {
            SET | RESET | CLEAR | PULSE => {
                if current != 0 { kevent::kevent_set(body as *mut u8); }
                else { kevent::kevent_clear(body as *mut u8); }
            }
            READ => {}
            _ => crate::provider_bugcheck::report(0xc4, [LABEL, op, body, 0]),
        }
        Some(if op == READ { current } else { previous })
    }
}

pub(super) fn set_if_owned(body: u64) -> Option<u64> { state_if_owned(body, SET) }
pub(super) fn reset_if_owned(body: u64) -> Option<u64> { state_if_owned(body, RESET) }
pub(super) fn clear_if_owned(body: u64) -> Option<u64> { state_if_owned(body, CLEAR) }
pub(super) fn pulse_if_owned(body: u64) -> Option<u64> { state_if_owned(body, PULSE) }
pub(super) fn read_if_owned(body: u64) -> Option<u64> { state_if_owned(body, READ) }

pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let Some(physical_caller) = hosted_driver_caller(index, inst, caller_badge) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let verified = unsafe { crate::service_sec_image::with_provider_process_manager(|pm|
        pm.validate_native_handle_caller(caller)) };
    if let Err(status) = verified { return (status as i32, 0, 0, 0); }
    match op {
        REFERENCE => unsafe {
            let access_mode = arg3 >> 63;
            let proposed = arg3 & !(1u64 << 63);
            if access_mode > 1 || proposed == 0 || arg2 > u32::MAX as u64 {
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            }
            let access_caller = if access_mode == 0 {
                caller
            } else {
                match crate::service_sec_image::with_provider_process_manager(|pm|
                    pm.capture_native_handle_caller(caller.original_thread(),
                        nt_types::AccessMode::UserMode)) {
                    Ok(caller) => caller,
                    Err(status) => return (status as i32, 0, 0, 0),
                }
            };
            let mut pin = match hosted_device_allocations::pin_temporary_pool_range(
                inst, proposed, BODY_ALLOCATION_BYTES) {
                Ok(pin) => pin,
                Err(status) => return (status.raw(), 0, 0, 0),
            };
            let allocation = pin.allocation();
            if allocation.component_address != proposed
                || hosted_instance_pool_allocation_exec_if_live(inst, proposed, BODY_ALLOCATION_BYTES)
                    .is_none()
            {
                release_proposed_pin(&mut pin, proposed);
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            }
            let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
            if rows.try_reserve(1).is_err() {
                release_proposed_pin(&mut pin, proposed);
                return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
            }
            let handler = match crate::service_sec_image::registry_live_handler_pointer() {
                Ok(handler) => handler,
                Err(status) => {
                    release_proposed_pin(&mut pin, proposed);
                    return (status as i32, 0, 0, 0);
                }
            };
            let result = (&mut *handler).provider_reference_native_event(
                access_caller, arg1, arg2 as u32);
            let (id, metadata, granted) = match result {
                Ok(value) => value,
                Err(status) => {
                    release_proposed_pin(&mut pin, proposed);
                    return (status as i32, 0, 0, 0);
                }
            };
            let raw_id = id.0 .0;
            if let Some(row) = rows.iter_mut().find(|row| row.id == raw_id
                && row.instance == index && row.domain == domain && row.pml4 == inst.pml4)
            {
                if row.pin.is_none()
                    || !row.key.matches(domain.domain_id.raw(), domain.cookie, inst.pml4,
                        raw_id, row.body, row.allocation.pool_generation)
                    || hosted_device_allocations::capture_range_allocation(inst,
                        row.body, BODY_ALLOCATION_BYTES).ok() != Some(row.allocation)
                {
                    if (&mut *handler).provider_dereference_native_event_pointer(id).is_err() {
                        crate::provider_bugcheck::report(0xc4, [LABEL, raw_id, proposed, 1]);
                    }
                    release_proposed_pin(&mut pin, proposed);
                    return (STATUS_INVALID_HANDLE, 0, 0, 0);
                }
                if !row.lifetime.retain_reference() {
                    if (&mut *handler).provider_dereference_native_event_pointer(id).is_err() {
                        crate::provider_bugcheck::report(0xc4, [LABEL, raw_id, proposed, 6]);
                    }
                    release_proposed_pin(&mut pin, proposed);
                    return (nt_status::NtStatus::DEVICE_BUSY.raw(), 0, 0, 0);
                }
                let body = row.body;
                release_proposed_pin(&mut pin, proposed);
                return (STATUS_SUCCESS, body, raw_id,
                    (metadata << 32) | u64::from(granted));
            }
            let body = proposed;
            let Some(key) = HostedEventProjectionKey::new(domain.domain_id.raw(),
                domain.cookie, inst.pml4, raw_id, body, allocation.pool_generation)
            else {
                if (&mut *handler).provider_dereference_native_event_pointer(id).is_err() {
                    crate::provider_bugcheck::report(0xc4, [LABEL, raw_id, proposed, 2]);
                }
                release_proposed_pin(&mut pin, proposed);
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            };
            rows.push(EventProjection { key, instance: index, domain, pml4: inst.pml4,
                id: raw_id, body, lifetime: HostedEventProjectionLifetime::new()
                    .expect("one native Event reference"), allocation, pin: Some(pin) });
            (STATUS_SUCCESS, body, raw_id,
                (metadata << 32) | u64::from(granted))
        },
        DEREFERENCE | RETAIN_POINTER => unsafe {
            if arg1 == 0 || arg2 != 0 || arg3 != 0 {
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            }
            let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
            let Some(row_index) = rows.iter().position(|row| row.body == arg1
                && row.instance == index && row.domain == domain && row.pml4 == inst.pml4) else {
                return (STATUS_UNOWNED_OBJECT, 0, 0, 0);
            };
            let row = &mut rows[row_index];
            if !row.key.matches(domain.domain_id.raw(), domain.cookie, inst.pml4,
                row.id, row.body, row.allocation.pool_generation)
                || row.pin.is_none()
                || row.lifetime.references() == 0
                || hosted_device_allocations::capture_range_allocation(inst,
                    row.body, BODY_ALLOCATION_BYTES).ok() != Some(row.allocation)
            { return (STATUS_INVALID_HANDLE, 0, 0, 0); }
            let handler = match crate::service_sec_image::registry_live_handler_pointer() {
                Ok(handler) => handler,
                Err(status) => return (status as i32, 0, 0, 0),
            };
            let id = nt_kernel_exec::EventObjectId(nt_types::ObjectId(row.id));
            if op == RETAIN_POINTER {
                if row.lifetime.references() == u32::MAX {
                    return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
                }
                match (&mut *handler).provider_retain_native_event_pointer(id) {
                    Ok(_) => {
                        if !row.lifetime.retain_reference() {
                            crate::provider_bugcheck::report(0xc4, [LABEL, row.body, row.id, 7]);
                        }
                        (STATUS_SUCCESS, u64::from(row.lifetime.references()), 0, 0)
                    }
                    Err(status) => (status as i32, 0, 0, 0),
                }
            } else {
                let pending = &mut *core::ptr::addr_of_mut!(PENDING_DEREFERENCES);
                if pending.try_reserve(1).is_err() {
                    return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
                }
                if !row.lifetime.begin_dereference() {
                    return (STATUS_INVALID_HANDLE, 0, 0, 0);
                }
                pending.push(PendingDereference { key: row.key,
                    route: physical_caller.route,
                    thread_handle: physical_caller.thread_handle });
                (STATUS_SUCCESS, u64::from(row.lifetime.references()), 0, 0)
            }
        },
        ACK_DEREFERENCE => unsafe {
            if arg1 == 0 || arg2 == 0 || arg3 != 0 {
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            }
            let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
            let Some(row_index) = rows.iter().position(|row| row.body == arg1
                && row.id == arg2 && row.instance == index
                && row.domain == domain && row.pml4 == inst.pml4) else {
                return (STATUS_INVALID_HANDLE, 0, 0, 0);
            };
            let row = &mut rows[row_index];
            if row.pin.is_none() || !row.key.matches(domain.domain_id.raw(),
                domain.cookie, inst.pml4, row.id, row.body,
                row.allocation.pool_generation)
            { return (STATUS_INVALID_HANDLE, 0, 0, 0); }
            let pending = &mut *core::ptr::addr_of_mut!(PENDING_DEREFERENCES);
            let Some(pending_index) = pending.iter().position(|receipt|
                receipt.key == row.key && receipt.route == physical_caller.route
                && receipt.thread_handle == physical_caller.thread_handle)
            else { return (STATUS_INVALID_HANDLE, 0, 0, 0); };
            let mut next = row.lifetime;
            let Some(count) = next.complete_dereference_ack() else {
                return (STATUS_INVALID_HANDLE, 0, 0, 0);
            };
            let handler = match crate::service_sec_image::registry_live_handler_pointer() {
                Ok(handler) => handler,
                Err(status) => return (status as i32, 0, 0, 0),
            };
            if next.retirable() {
                let pin = row.pin.as_mut().expect("validated Event projection pin");
                if let Err(status) = hosted_device_allocations::retire_owned_temporary_pool_allocation(pin) {
                    return (status.raw(), 0, 0, 0);
                }
                row.pin = None;
            }
            let id = nt_kernel_exec::EventObjectId(nt_types::ObjectId(row.id));
            if (&mut *handler).provider_dereference_native_event_pointer(id).is_err() {
                crate::provider_bugcheck::report(0xc4, [LABEL, row.body, row.id, 8]);
            }
            row.lifetime = next;
            pending.swap_remove(pending_index);
            if next.retirable() { rows.swap_remove(row_index); }
            (STATUS_SUCCESS, u64::from(count), 0, 0)
        },
        SET | RESET | CLEAR | PULSE | READ => unsafe {
            if arg1 == 0 || arg2 != 0 || arg3 != 0 {
                return (STATUS_INVALID_PARAMETER, 0, 0, 0);
            }
            let rows = &*core::ptr::addr_of!(PROJECTIONS);
            let Some(row) = rows.iter().find(|row| row.body == arg1
                && row.instance == index && row.domain == domain && row.pml4 == inst.pml4)
            else { return (STATUS_UNOWNED_OBJECT, 0, 0, 0); };
            if !row.key.matches(domain.domain_id.raw(), domain.cookie, inst.pml4,
                row.id, row.body, row.allocation.pool_generation)
                || row.pin.is_none() || row.lifetime.references() == 0
                || hosted_device_allocations::capture_range_allocation(inst,
                    row.body, BODY_ALLOCATION_BYTES).ok() != Some(row.allocation)
            { return (STATUS_INVALID_HANDLE, 0, 0, 0); }
            let handler = match crate::service_sec_image::registry_live_handler_pointer() {
                Ok(handler) => handler,
                Err(status) => return (status as i32, 0, 0, 0),
            };
            let outcome = match op {
                SET => (&mut *handler).projected_event_set(row.id).map(|(previous, native)| {
                    if !previous { let _ = crate::wait_wake_event_set(native, &mut *handler); }
                    (previous, (&*handler).projected_event_ready(row.id).unwrap_or(false))
                }),
                RESET => (&mut *handler).projected_event_reset(row.id).map(|previous| (previous, false)),
                CLEAR => (&mut *handler).projected_event_clear(row.id).map(|()| (false, false)),
                PULSE => (&mut *handler).projected_event_set(row.id).map(|(previous, native)| {
                    if previous { let _ = (&mut *handler).projected_event_reset(row.id); }
                    else { let _ = crate::wait_wake_event_pulse(native, &mut *handler); }
                    (previous, false)
                }),
                READ => (&*handler).projected_event_ready(row.id)
                    .ok_or(nt_process::STATUS_INVALID_HANDLE).map(|current| (current, current)),
                _ => unreachable!(),
            };
            match outcome {
                Ok((previous, current)) => (STATUS_SUCCESS, u64::from(previous), u64::from(current), 0),
                Err(status) => (status as i32, 0, 0, 0),
            }
        },
        _ => (STATUS_INVALID_PARAMETER, 0, 0, 0),
    }
}
