//! VideoPort lifecycle and device controls over the ordinary retained native IRP graph.

use super::*;
use nt_video_miniport::{
    classify_start_io_status, VideoRequestPacketX64, VIDEO_REQUEST_PACKET_X64_SIZE,
};

fn protocol_violation(device: u64, irp: u64, status: u64, information: u64) -> ! {
    // The guarded run_irp caller retains the graph and reports indeterminate provider execution.
    s_ke_bug_check_ex(0xC4, device, irp, status, information);
    park()
}

unsafe fn complete(irp: u64, status: i32, information: u64) -> i32 {
    write_unaligned(
        (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32,
        status,
    );
    write_unaligned(
        (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
        information,
    );
    s_io_complete_request(irp, 0);
    status
}

pub(super) unsafe extern "win64" fn dispatch(device: u64, irp: u64) -> i32 {
    let Some((stack_count, current_location, stack)) = validate_hosted_irp_packet(irp) else {
        protocol_violation(device, irp, STATUS_INVALID_PARAMETER as u32 as u64, 0);
    };
    if current_location > stack_count || !pending_irp_raw_identity_exists(irp) {
        protocol_violation(device, irp, STATUS_INVALID_PARAMETER as u32 as u64, 0);
    }
    let request_major = read_unaligned(stack as *const u8);
    if read_unaligned((stack + WDM_X64_IO_STACK_DEVICE_OBJECT_OFFSET) as *const u64) != device {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let hw_extension = match component_video_hw_extension_for_device(device) {
        Ok(extension) => extension,
        Err(status) => return complete(irp, status, 0),
    };
    match request_major {
        major::IRP_MJ_CREATE | major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE => {
            let file = read_unaligned((stack + 0x30) as *const u64);
            if component_pool_allocation_capacity(file)
                .is_none_or(|capacity| capacity < WDM_X64_FILE_OBJECT_SIZE as u64)
                || read_unaligned(file as *const i16) != WDM_X64_IO_TYPE_FILE
            {
                return complete(irp, STATUS_INVALID_PARAMETER, 0);
            }
            let (status, information) = if request_major == major::IRP_MJ_CREATE {
                component_dispatch_video_initialize(device)
            } else {
                (STATUS_SUCCESS, 0)
            };
            return complete(irp, status, information);
        }
        major::IRP_MJ_DEVICE_CONTROL => {}
        _ => return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0),
    }
    let start_io = read_volatile((FSD_SHARED_VADDR + SH_VIDEO_HW_START_IO) as *const u64);
    if start_io == 0 {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let output_len = read_unaligned((stack + 0x08) as *const u32);
    let input_len = read_unaligned((stack + 0x10) as *const u32);
    let code = read_unaligned((stack + 0x18) as *const u32);
    if ioctl::method(code) != ioctl::METHOD_BUFFERED {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let buffer = read_unaligned((irp + 0x18) as *const u64);
    let required = u64::from(input_len.max(output_len));
    if required != 0
        && component_pool_allocation_capacity(buffer).is_none_or(|capacity| capacity < required)
    {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    if code == IOCTL_VIDEO_INIT_WIN32K_CALLBACKS {
        let (status, information) = component_dispatch_video_win32k_callbacks(
            device,
            buffer,
            input_len as u64,
            output_len as u64,
        );
        return complete(irp, status, information);
    }

    // NT5's VRP is transient; the real IRP owns both IoStatus and SystemBuffer through completion.
    write_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32, 0);
    write_unaligned(
        (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
        0,
    );
    let packet = VideoRequestPacketX64::buffered(
        code,
        irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET,
        buffer,
        input_len,
        output_len,
    );
    let mut bytes = [0u8; VIDEO_REQUEST_PACKET_X64_SIZE];
    if packet.write(&mut bytes).is_err() {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    let start: extern "win64" fn(u64, u64) -> u8 = core::mem::transmute(start_io as *const ());
    let _accepted = start(hw_extension, bytes.as_mut_ptr() as u64);
    let calls = read_volatile((FSD_SHARED_VADDR + SH_VIDEO_HW_START_IO_CALLS) as *const u64);
    write_volatile(
        (FSD_SHARED_VADDR + SH_VIDEO_HW_START_IO_CALLS) as *mut u64,
        calls.saturating_add(1),
    );
    let status = read_unaligned((irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *const u32);
    let information =
        read_unaligned((irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *const u64);
    let completion = match classify_start_io_status(status, information) {
        Ok(completion) => completion,
        Err(_) => protocol_violation(device, irp, status as u64, information),
    };
    complete(irp, completion.nt_status as i32, completion.information)
}
