//! I/O manager-owned power requests dispatched through the real device stack.
//!
//! The extra metadata frame remains live through a deferred completion. The
//! completion callback alone retires the source IRP and its referenced top
//! device. In particular the dispatch return never implies completion.

use super::*;

const IRP_MJ_POWER_LOCAL: u8 = 0x16;
const IRP_MN_WAIT_WAKE: u8 = 0x00;
const POWER_STATE_TYPE_DEVICE: u32 = 1;
const STATUS_MORE_PROCESSING_REQUIRED_LOCAL: i32 = 0xC000_0016u32 as i32;

/// `PIO_COMPLETION_ROUTINE` for an I/O manager-owned power request.
extern "win64" fn complete_request(top_device: u64, irp: u64, completion: u64) -> i32 {
    unsafe {
        let metadata = irp_current_stack_location(irp);
        assert_ne!(metadata, 0, "power request lost its retained metadata frame");
        let original_device = read_unaligned((metadata + 0x08) as *const u64);
        let minor = read_unaligned((metadata + 0x10) as *const u64);
        let power_state = read_unaligned((metadata + 0x18) as *const u64);
        let context = read_unaligned((metadata + 0x20) as *const u64);
        assert_eq!(read_unaligned((metadata + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *const u64),
            top_device, "power completion lost its referenced top device");
        if completion != 0 {
            call_hosted_pe(completion, &[
                original_device, minor, power_state, context,
                irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET,
            ]);
        }
        // The caller's requestor IRP pointer expires on this callback. ReactOS
        // frees the IRP, then drops the top-stack reference, and stops unwind.
        s_io_free_irp(irp);
        s_obf_dereference_object(top_device);
    }
    STATUS_MORE_PROCESSING_REQUIRED_LOCAL
}

/// `NTSTATUS PoRequestPowerIrp(PDEVICE_OBJECT, UCHAR, POWER_STATE,
/// PREQUEST_POWER_COMPLETE, PVOID, PIRP*)`.
extern "win64" fn request_power_irp(
    device: u64,
    minor: u8,
    power_state: u32,
    completion: u64,
    context: u64,
    irp_out: u64,
) -> i32 {
    use nt_io_manager::power_irp_request::{PowerIrpPlan, PowerIrpPlanError};

    if !matches!(minor, 0x00 | 0x02 | 0x03) {
        return STATUS_INVALID_PARAMETER_2;
    }
    if device == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let top = s_io_get_attached_device_reference(device);
    if top == 0 {
        return nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
    }
    unsafe {
        let top_stack_size = read_unaligned((top + 0x4c) as *const u8);
        let plan = match PowerIrpPlan::new(top_stack_size, minor) {
            Ok(plan) => plan,
            Err(PowerIrpPlanError::InvalidMinor) => unreachable!(),
            Err(PowerIrpPlanError::InvalidStack) => {
                s_obf_dereference_object(top);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        };
        let irp = s_io_allocate_irp(plan.stack_count, 0);
        if irp == 0 {
            s_obf_dereference_object(top);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let base = irp + WDM_X64_IRP_SIZE as u64;
        let metadata = base + (plan.metadata_location as u64 - 1)
            * WDM_X64_IO_STACK_LOCATION_SIZE as u64;
        let request = base + (plan.request_location as u64 - 1)
            * WDM_X64_IO_STACK_LOCATION_SIZE as u64;

        write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32, STATUS_NOT_SUPPORTED);
        write_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64, 0);
        write_unaligned((metadata + 0x08) as *mut u64, device);
        write_unaligned((metadata + 0x10) as *mut u64, minor as u64);
        write_unaligned((metadata + 0x18) as *mut u64, power_state as u64);
        write_unaligned((metadata + 0x20) as *mut u64, context);
        write_unaligned((metadata + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *mut u64, top);

        write_unaligned(request as *mut u8, IRP_MJ_POWER_LOCAL);
        write_unaligned((request + WDM_X64_IO_STACK_MINOR_OFFSET) as *mut u8, minor);
        if minor == IRP_MN_WAIT_WAKE {
            write_unaligned((request + 0x08) as *mut u32, power_state);
        } else {
            write_unaligned((request + PowerIrpPlan::POWER_TYPE_OFFSET) as *mut u32,
                POWER_STATE_TYPE_DEVICE);
            write_unaligned((request + PowerIrpPlan::POWER_STATE_OFFSET) as *mut u32,
                power_state);
        }
        write_unaligned((request + WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET) as *mut u64,
            complete_request as *const () as usize as u64);
        write_unaligned((request + WDM_X64_IO_STACK_CONTEXT_OFFSET) as *mut u64, completion);
        write_unaligned((request + WDM_X64_IO_STACK_CONTROL_OFFSET) as *mut u8, 0xe0);
        write_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8,
            plan.pre_dispatch_location);
        write_unaligned((irp + 0xb8) as *mut u64, metadata);

        if irp_out != 0 {
            write_unaligned(irp_out as *mut u64, irp);
        }
        let _dispatch_status = s_po_call_driver(top, irp);
        // Completion may have freed `irp` before PoCallDriver returned; no IRP
        // field can be touched here. A pending lower owner retains it instead.
        STATUS_PENDING as i32
    }
}

pub(crate) fn bind_power_irp_export(reg: &mut nt_compat_exports::DriverExportRegistry) {
    reg.bind("PoRequestPowerIrp", request_power_irp as *const () as usize as u64);
}
