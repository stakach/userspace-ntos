//! Driver-local REGINFO dispatch with an owned source IRP and bounded output.
//! The caller must establish a root registration transaction before invoking
//! this callback; this helper only produces terminal bytes, never publication.

use super::*;

pub(super) struct RegInfoReply {
    pub status: i32,
    pub information: u64,
    pub bytes: Vec<u8>,
}

struct HeldRegInfoIrp {
    irp: u64,
}

impl Drop for HeldRegInfoIrp {
    fn drop(&mut self) {
        if self.irp != 0 {
            unsafe { s_io_complete_request(self.irp, 0); }
        }
    }
}

/// Dispatch to the device's current `IRP_MJ_SYSTEM_CONTROL` handler and wait
/// through an inline or pending terminal. The completion callback parks the
/// source packet; the guard resumes normal terminal cleanup after the copy.
pub(super) unsafe fn query(device: u64, capacity: u32) -> Result<RegInfoReply, i32> {
    if device == 0 || capacity < 24 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut completion = HostedSyncForwardContext {
        event: [0; 3],
        completed: AtomicBool::new(false),
    };
    let event = completion.event.as_mut_ptr() as u64;
    let mut iosb = [0u64; 2];
    let iosb = iosb.as_mut_ptr() as u64;
    s_ke_initialize_event(event, 0, 0);

    let irp = hosted_synchronous_fsd_request::build_wmi_reginfo(
        device, capacity, event, iosb,
    );
    if irp == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let buffer = read_unaligned((irp + 0x18) as *const u64);
    let next = irp_next_stack_location(irp);
    write_unaligned(
        (next + WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET) as *mut u64,
        s_io_forward_sync_completion as *const () as usize as u64,
    );
    write_unaligned((next + WDM_X64_IO_STACK_CONTEXT_OFFSET) as *mut u64, event);
    write_unaligned((next + WDM_X64_IO_STACK_CONTROL_OFFSET) as *mut u8, 0xe0);
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32,
        STATUS_NOT_SUPPORTED);

    let dispatch_status = s_iof_call_driver(device, irp);
    if dispatch_status as u32 == STATUS_PENDING {
        let wait_status = s_ke_wait_for_single_object(event, 5, 0, 0, 0);
        if wait_status != STATUS_SUCCESS {
            crate::provider_bugcheck::report(
                0xc4,
                [device, irp, event, wait_status as u32 as u64],
            );
        }
    }
    if !completion.completed.load(Ordering::Acquire) {
        // Dispatch may already have had effects. Retain its IRP and source
        // allocation instead of freeing or replaying an uncertain request.
        crate::provider_bugcheck::report(
            0xc4,
            [device, irp, event, dispatch_status as u32 as u64],
        );
    }
    let _held = HeldRegInfoIrp { irp };
    let status = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const i32);
    let information = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *const u64);
    if status != STATUS_SUCCESS {
        return Ok(RegInfoReply { status, information, bytes: Vec::new() });
    }
    let Some(actual_capacity) = component_pool_allocation_capacity(buffer) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    if buffer == 0 || read_unaligned((irp + 0x18) as *const u64) != buffer
        || information < 24 || information > u64::from(capacity)
        || information > actual_capacity
    {
        return Err(STATUS_INVALID_BUFFER_SIZE as i32);
    }
    let length = usize::try_from(information).map_err(|_| STATUS_INVALID_BUFFER_SIZE as i32)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    bytes.resize(length, 0);
    core::ptr::copy_nonoverlapping(buffer as *const u8, bytes.as_mut_ptr(), length);
    Ok(RegInfoReply { status, information, bytes })
}
