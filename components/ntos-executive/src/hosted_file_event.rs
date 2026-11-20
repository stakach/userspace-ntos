//! FO_SKIP_SET_EVENT: a driver that sets it owns FILE_OBJECT.Event as its own readiness event.
//!
//! ConDrv initializes FileObject->Event itself, sets FO_SKIP_SET_EVENT, and signals or clears the
//! event as console input becomes available. The I/O manager then never edits that event, and a
//! handle wait observes exactly the driver's state. The component reports each edit of a live,
//! published FILE_OBJECT's event; the root admits it only for the exact bound File and adopts or
//! updates its canonical waitable state (`nt_io_completion::FileCompletionTable`).

use super::*;
use nt_io_manager::WDM_X64_FILE_OBJECT_EVENT_OFFSET;

pub(super) const FO_SKIP_SET_EVENT: u32 = 0x0400_0000;
const FILE_OBJECT_FLAGS_OFFSET: u64 = 0x50;
const OP_EVENT_CLEARED: u64 = 12;
const OP_EVENT_SIGNALED: u64 = 13;

/// After a driver edited `event`, mirror it when it is the Event of a published FILE_OBJECT that
/// the driver marked FO_SKIP_SET_EVENT. Ordinary KEVENTs are untouched.
pub(super) unsafe fn mirror(event: u64) {
    let Some(file_object) = event.checked_sub(WDM_X64_FILE_OBJECT_EVENT_OFFSET as u64) else { return };
    let Some(file) = (unsafe { hosted_file_objects::fo_file_for_address(file_object) }) else { return };
    let flags = unsafe { read_volatile((file_object + FILE_OBJECT_FLAGS_OFFSET) as *const u32) };
    if flags & FO_SKIP_SET_EVENT == 0 { return; }
    let signaled = unsafe { kevent::kevent_read_state(event as *const u8) };
    let op = if signaled { OP_EVENT_SIGNALED } else { OP_EVENT_CLEARED };
    let (words, status, value, reserved0, reserved1) = unsafe {
        call_on4_raw((FSD_SERVICE_FILE_LABEL << 12) | 4, op, 0, file, file_object)
    };
    if words != 4 || status as u32 as i32 != STATUS_SUCCESS || value != 0 || reserved0 != 0 || reserved1 != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_FILE_LABEL, op, file, status]); }
    }
}

/// Root half: the exact File must be bound at `address` in this domain and its FILE_OBJECT must
/// carry FO_SKIP_SET_EVENT before the canonical waitable state follows the driver.
pub(super) fn service(
    domain: HostedDomainIdentity,
    instance: DriverInstance,
    file: FileId,
    address: u64,
    operation: u64,
) -> Result<u64, nt_status::NtStatus> {
    let bound = io_manager_mut().hosted_file_identity_at(domain, file, address)?;
    if bound.is_none() {
        return Err(nt_status::NtStatus::ACCESS_DENIED);
    }
    let file_object = unsafe {
        hosted_instance_pool_allocation_exec_if_live(instance, address, WDM_X64_FILE_OBJECT_SIZE as u64)
    }.ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let flags = unsafe { read_volatile((file_object + FILE_OBJECT_FLAGS_OFFSET) as *const u32) };
    if flags & FO_SKIP_SET_EVENT == 0 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let handler = crate::service_sec_image::registry_live_handler_pointer()
        .map_err(|_| nt_status::NtStatus::DEVICE_NOT_READY)?;
    unsafe { (&mut *handler).mirror_driver_file_event(file.0, operation == OP_EVENT_SIGNALED) }
        .map(|()| 0)
        .map_err(|status| nt_status::NtStatus(status as i32))
}
