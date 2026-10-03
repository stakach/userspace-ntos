//! Native `IoBuildSynchronousFsdRequest` materialization for hosted drivers.
//!
//! The shared planner owns WDM layout policy. This adapter owns component-pool
//! allocations and transfers them to the registered source IRP only after the
//! complete request is ready for dispatch.

use super::*;
use nt_io_manager::kernel_irp_builder::{
    plan_synchronous_fsd_request, KernelBuiltIrpPlan, MdlAccess,
};

/// Children remain unpublished until `publish`. Dropping an incomplete build
/// releases them in reverse ownership order, then retires the exact source IRP.
struct UnpublishedRequest {
    irp: u64,
    system_buffer: u64,
    mdl: u64,
    mdl_locked: bool,
}

impl UnpublishedRequest {
    unsafe fn allocate(stack_count: u8) -> Option<Self> {
        let irp = s_io_allocate_irp(stack_count, 0);
        (irp != 0).then_some(Self {
            irp,
            system_buffer: 0,
            mdl: 0,
            mdl_locked: false,
        })
    }

    unsafe fn allocate_system_buffer(&mut self, length: u32) -> bool {
        debug_assert_ne!(length, 0);
        self.system_buffer = pool_alloc_zeroed(u64::from(length));
        self.system_buffer != 0
    }

    unsafe fn allocate_mdl(&mut self, buffer: u64, length: u32, access: MdlAccess) -> bool {
        debug_assert_ne!(buffer, 0);
        debug_assert_ne!(length, 0);
        self.mdl = s_io_allocate_mdl(buffer, length, 0, 0, self.irp);
        if self.mdl == 0 {
            return false;
        }
        let operation = match access {
            MdlAccess::Read => 0,  // IoReadAccess
            MdlAccess::Write => 1, // IoWriteAccess
        };
        s_mm_probe_and_lock_pages(self.mdl, 0, operation);
        self.mdl_locked = true;
        true
    }

    unsafe fn publish(mut self, plan: KernelBuiltIrpPlan, event: u64, iosb: u64) -> u64 {
        write_unaligned((self.irp + 0x08) as *mut u64, self.mdl);
        write_unaligned((self.irp + 0x10) as *mut u32, plan.irp_flags);
        write_unaligned((self.irp + 0x18) as *mut u64, self.system_buffer);
        write_unaligned((self.irp + 0x48) as *mut u64, iosb);
        write_unaligned((self.irp + 0x50) as *mut u64, event);
        write_unaligned((self.irp + 0x70) as *mut u64, plan.user_buffer);
        write_unaligned((self.irp + 0x98) as *mut u64, s_current_thread());

        let (label, status, ticket, generation, _) = call_on4(
            (FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4,
            4,
            self.irp,
            0,
            0,
        );
        if label != 0 {
            crate::provider_bugcheck::report(
                0xc4,
                [FSD_SERVICE_SOURCE_IRP_LABEL, 4, self.irp, label],
            );
        }
        if status as u32 as i32 == STATUS_SUCCESS && (ticket == 0 || generation == 0) {
            // A success reply means the root may already own every child. A malformed
            // acknowledgement is therefore uncertain and must not enter guard rollback.
            crate::provider_bugcheck::report(
                0xc4,
                [FSD_SERVICE_SOURCE_IRP_LABEL, 4, self.irp, status],
            );
        }
        if status as u32 as i32 != STATUS_SUCCESS {
            return 0;
        }

        // Normal terminal completion now owns all three allocations.
        let irp = self.irp;
        self.irp = 0;
        self.system_buffer = 0;
        self.mdl = 0;
        self.mdl_locked = false;
        irp
    }
}

impl Drop for UnpublishedRequest {
    fn drop(&mut self) {
        unsafe {
            if self.mdl != 0 {
                if self.mdl_locked {
                    s_mm_unlock_pages(self.mdl);
                    self.mdl_locked = false;
                }
                s_io_free_mdl(self.mdl);
                self.mdl = 0;
            }
            if self.system_buffer != 0 {
                pool_free(self.system_buffer);
                self.system_buffer = 0;
            }
            if self.irp != 0 {
                s_io_free_irp(self.irp);
                self.irp = 0;
            }
        }
    }
}

unsafe fn device_contract(device: u64) -> Option<(u8, u32)> {
    let capacity = component_pool_allocation_capacity(device)?;
    if capacity < WDM_X64_DEVICE_OBJECT_SIZE as u64
        || read_unaligned(device as *const i16) != WDM_X64_IO_TYPE_DEVICE
    {
        return None;
    }
    let size = u64::from(read_unaligned((device + 2) as *const u16));
    if size < WDM_X64_DEVICE_OBJECT_SIZE as u64 || size > capacity {
        return None;
    }
    let stack_count = read_unaligned((device + 0x4c) as *const u8);
    if !(1..=32).contains(&stack_count) {
        return None;
    }
    let flags = read_unaligned((device + 0x30) as *const u32);
    Some((stack_count, flags))
}

/// Build a caller-owned synchronous FSD request. Dispatch and waiting remain
/// explicit; this routine materializes the packet and registers its lifetime.
pub(super) extern "win64" fn build(
    major: u32,
    device: u64,
    buffer: u64,
    length: u32,
    starting_offset: u64,
    event: u64,
    iosb: u64,
) -> u64 {
    unsafe {
        let Ok(major) = u8::try_from(major) else {
            return 0;
        };
        let transfer = matches!(major, major::IRP_MJ_READ | major::IRP_MJ_WRITE);
        if device == 0
            || event == 0
            || iosb == 0
            || (transfer
                && (starting_offset == 0
                    || (length != 0
                        && (buffer == 0 || buffer.checked_add(u64::from(length)).is_none()))))
        {
            return 0;
        }
        let Some((stack_count, device_flags)) = device_contract(device) else {
            return 0;
        };
        let byte_offset = transfer
            .then(|| read_unaligned(starting_offset as *const u64));
        let Ok(plan) = plan_synchronous_fsd_request(
            major,
            stack_count,
            device_flags,
            device,
            buffer,
            length,
            byte_offset,
        ) else {
            return 0;
        };
        let Some(mut request) = UnpublishedRequest::allocate(plan.stack_count) else {
            return 0;
        };

        if plan.system_buffer_len != 0 {
            if !request.allocate_system_buffer(plan.system_buffer_len) {
                return 0;
            }
            if plan.system_buffer_input_len != 0 {
                core::ptr::copy_nonoverlapping(
                    plan.system_buffer_input as *const u8,
                    request.system_buffer as *mut u8,
                    plan.system_buffer_input_len as usize,
                );
            }
        }
        if let Some(mdl) = plan.mdl {
            if !request.allocate_mdl(mdl.buffer, mdl.length, mdl.access) {
                return 0;
            }
        }

        let stack = request.irp + plan.next_stack_offset as u64;
        let stack_bytes = core::slice::from_raw_parts_mut(
            stack as *mut u8,
            WDM_X64_IO_STACK_LOCATION_SIZE,
        );
        if write_wdm_io_stack_location(stack_bytes, plan.stack).is_err() {
            return 0;
        }
        request.publish(plan, event, iosb)
    }
}
