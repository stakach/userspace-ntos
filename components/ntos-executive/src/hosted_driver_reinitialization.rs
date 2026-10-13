//! Retained `IoRegisterDriverReinitialization` callbacks for isolated hosted drivers.

use super::*;
use nt_io_manager::driver_reinitialization::{
    DriverReinitializationError, DriverReinitializationIdentity,
    DriverReinitializationQueue,
};

static mut QUEUE: DriverReinitializationQueue = DriverReinitializationQueue::new();

fn queue() -> &'static mut DriverReinitializationQueue {
    unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) }
}

/// Component-side void import. The root records ownership before returning; malformed transport
/// acknowledgements enter the existing provider fault path instead of permitting a replay.
pub(super) extern "win64" fn register(driver_object: u64, routine: u64, context: u64) {
    let (info, raw, first, second, reserved) = unsafe {
        call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_REGISTER_DRIVER_REINIT,
            driver_object,
            routine,
            context,
        )
    };
    if info != 4 || first != 0 || second != 0 || reserved != 0
        || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
        || raw as u32 as i32 != STATUS_SUCCESS
    {
        unsafe { crate::provider_bugcheck::report(
            0xc4,
            [FSD_SERVICE_DEVICE_LABEL, HOSTED_DEVICE_OP_REGISTER_DRIVER_REINIT, info, raw],
        ); }
    }
    unsafe {
        let flags = read_unaligned((driver_object + 4) as *const u32);
        write_unaligned((driver_object + 4) as *mut u32, flags | 8);
    }
}

/// Called by the authenticated hosted DEVICE service during DriverEntry.
pub(super) fn service_register(
    ch: &crate::spawn_hosts::PumpChannel,
    driver_object: u64,
    routine: u64,
    context: u64,
    active_reply_cap: u64,
) -> i32 {
    let Some((instance_index, inst)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return STATUS_ACCESS_DENIED;
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return STATUS_ACCESS_DENIED;
    };
    let Some(image_end) = inst.image_frames.checked_mul(0x1000)
        .and_then(|bytes| FSD_CODE_VA.checked_add(bytes))
    else {
        return STATUS_INVALID_PARAMETER;
    };
    if inst.driver_id == 0 || driver_object == 0 || routine < FSD_CODE_VA
        || routine >= image_end || inst.exec_shared_va != ch.shared_va
        || ch.physical_domain != Some(domain)
        || instance(instance_index).is_none()
        || unsafe { read_volatile((ch.shared_va + SH_DRVOBJ) as *const u64) } != driver_object
    {
        return STATUS_ACCESS_DENIED;
    }
    let valid_driver = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, driver_object)
            .is_some_and(|(exec, capacity)| {
                capacity >= WDM_X64_DRIVER_OBJECT_SIZE as u64
                    && hosted_instance_pool_allocation_is_free_unlocked(inst, driver_object) == Some(false)
                    && read_unaligned(exec as *const i16) == WDM_X64_IO_TYPE_DRIVER
                    && read_unaligned((exec + 2) as *const u16) == WDM_X64_DRIVER_OBJECT_SIZE as u16
            })
    };
    if !valid_driver {
        return STATUS_INVALID_PARAMETER;
    }
    let identity = DriverReinitializationIdentity {
        driver_id: inst.driver_id,
        domain_id: domain.domain_id.raw(),
        domain_cookie: domain.cookie,
        driver_object,
        routine,
        context,
    };
    match queue().register(identity) {
        Ok(_) => STATUS_SUCCESS,
        Err(DriverReinitializationError::Exhausted) => STATUS_INSUFFICIENT_RESOURCES,
        Err(_) => STATUS_INVALID_PARAMETER,
    }
}

/// Component-side reinit dispatch. The local driver extension owns Count and Flags, and the
/// guarded callback boundary contains faults before the root can acknowledge the queue ticket.
pub(super) unsafe fn component_dispatch() -> (i32, u64) {
    let driver_object = read_volatile((FSD_SHARED_VADDR + SH_DRVOBJ) as *const u64);
    let routine = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
    let context = read_volatile((FSD_SHARED_VADDR + SH_REQ_FSCTL) as *const u64);
    if driver_object == 0 || routine == 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let extension = read_unaligned((driver_object + WDM_X64_DRIVER_EXTENSION_OFFSET as u64) as *const u64);
    if extension == 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let old_count = read_unaligned((extension + 0x10) as *const u32);
    let Some(count) = old_count.checked_add(1) else {
        return (STATUS_INVALID_PARAMETER, 0);
    };
    write_unaligned((extension + 0x10) as *mut u32, count);
    let flags = read_unaligned((driver_object + 4) as *const u32);
    write_unaligned((driver_object + 4) as *mut u32, flags & !8);
    let jb = &mut *core::ptr::addr_of_mut!(BUGCHECK_JB);
    jb[0] = 0;
    jb[1] = 0;
    jb[2] = 0;
    let args = [driver_object, context, u64::from(count), 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let boundary = read_volatile((FSD_SHARED_VADDR + SH_SEH_FOREIGN_CALL16_VA) as *const u64);
    if boundary == 0 {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let _ = fsd_guarded_call_vector(routine, args.as_ptr(), 12, jb.as_mut_ptr(), boundary);
    let bugchecked = jb[2] != 0;
    jb[1] = 0;
    jb[2] = 0;
    if bugchecked {
        return (STATUS_UNSUCCESSFUL, 0);
    }
    (STATUS_SUCCESS, u64::from(count))
}

/// Run the exact queued callbacks after successful DriverEntry publication. A fault, uncertain
/// pump result, or count mismatch leaves its ticket Executing and blocks later replay/unload.
pub(super) unsafe fn run_pending_for_instance(
    index: usize,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> Result<(), nt_status::NtStatus> {
    let inst = instance(index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
    loop {
        let Some(ticket) = queue().begin_next_for(
            inst.driver_id, domain.domain_id.raw(), domain.cookie,
        ) else {
            return Ok(());
        };
        let count = dispatch_device_projection_control_for_instance(
            index,
            ticket.identity.driver_object,
            FSD_DISPATCH_DRIVER_REINIT,
            ticket.identity.routine,
            ticket.identity.context,
            false,
            None,
            caller,
        )?;
        if count != u64::from(ticket.count) {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        queue().acknowledge(ticket).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    }
}

pub(super) fn instance_quiesced(inst: DriverInstance) -> bool {
    instance_domain_identity(inst).is_some_and(|domain| {
        queue().quiesced(inst.driver_id, domain.domain_id.raw(), domain.cookie)
    })
}
