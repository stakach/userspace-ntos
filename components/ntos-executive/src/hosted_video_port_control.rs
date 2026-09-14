//! VideoPort lifecycle and device controls over the ordinary retained native IRP graph.

use super::*;
use nt_video_miniport::{
    classify_start_io_status, validate_device_control_requestor, VideoOpenAction,
    VideoPortDeviceState, VideoPortDeviceStateCell, VideoPortLifecycleError, VideoRequestPacketX64,
    VIDEO_PORT_DEVICE_STATE_SIZE, VIDEO_REQUEST_PACKET_X64_SIZE,
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

unsafe fn port_extension(device: u64) -> Result<u64, i32> {
    if read_volatile((FSD_SHARED_VADDR + SH_VIDEO_PORT_INITIALIZED) as *const u32) == 0 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let capacity = component_pool_allocation_capacity(device).ok_or(STATUS_INVALID_PARAMETER)?;
    let extension_size =
        read_volatile((FSD_SHARED_VADDR + SH_VIDEO_HW_DEVICE_EXTENSION_SIZE) as *const u32);
    let required = WDM_X64_DEVICE_OBJECT_SIZE as u64
        + VIDEO_PORT_DEVICE_STATE_SIZE as u64
        + u64::from(extension_size);
    if extension_size == 0 || capacity < required {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let driver = read_volatile((FSD_SHARED_VADDR + SH_DRVOBJ) as *const u64);
    let extension = device + WDM_X64_DEVICE_OBJECT_SIZE as u64;
    if read_unaligned(device as *const i16) != WDM_X64_IO_TYPE_DEVICE
        || u64::from(read_unaligned((device + 2) as *const u16)) != required
        || read_unaligned((device + 8) as *const u64) != driver
        || read_unaligned((device + 0x40) as *const u64) != extension
        || read_unaligned((device + 0x48) as *const u32) != nt_video_miniport::FILE_DEVICE_VIDEO
    {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok(extension)
}

unsafe fn update_device_state<T>(
    device: u64,
    update: impl FnMut(&mut VideoPortDeviceState) -> Result<T, VideoPortLifecycleError>,
) -> Result<T, i32> {
    let extension = port_extension(device)?;
    // The validated pool body and WDM header keep this zero-initialized prefix 16-byte aligned.
    (&*(extension as *const VideoPortDeviceStateCell))
        .update(update)
        .map_err(|error| match error {
            VideoPortLifecycleError::Busy => 0x8000_0011u32 as i32, // STATUS_DEVICE_BUSY
            VideoPortLifecycleError::InvalidSnapshot
            | VideoPortLifecycleError::BufferTooSmall { .. } => {
                protocol_violation(device, 0, STATUS_INVALID_PARAMETER as u32 as u64, extension)
            }
            VideoPortLifecycleError::InvalidRequestorMode => STATUS_INVALID_PARAMETER,
            VideoPortLifecycleError::InvalidTransition => 0xc000_0184u32 as i32, // STATUS_INVALID_DEVICE_STATE
        })
}

pub(super) unsafe fn begin_find_adapter(device: u64) -> Result<u64, i32> {
    update_device_state(device, |state| state.begin_find_adapter())?;
    Ok(device + WDM_X64_DEVICE_OBJECT_SIZE as u64 + VIDEO_PORT_DEVICE_STATE_SIZE as u64)
}

pub(super) unsafe fn finish_find_adapter(device: u64, success: bool) {
    if let Err(status) = update_device_state(device, |state| state.record_find_adapter(success)) {
        protocol_violation(device, 0, status as u32 as u64, u64::from(success));
    }
}

unsafe fn create(device: u64, irp: u64, stack: u64, hw_extension: u64) -> i32 {
    let mode = read_unaligned((irp + 0x40) as *const u8);
    if mode > 1 {
        return complete(irp, STATUS_INVALID_PARAMETER, 0);
    }
    let access = if mode == 1 {
        0
    } else {
        let security = read_unaligned((stack + 0x08) as *const u64);
        if component_pool_allocation_capacity(security).is_none_or(|capacity| capacity < 0x18) {
            return complete(irp, STATUS_INVALID_PARAMETER, 0);
        }
        read_unaligned((security + 0x10) as *const u32)
    };
    match update_device_state(device, |state| state.begin_open(mode, access)) {
        Ok(VideoOpenAction::Complete {
            status,
            information,
        }) => {
            return complete(irp, status as i32, information);
        }
        Ok(VideoOpenAction::Busy) => return complete(irp, 0x8000_0011u32 as i32, 0),
        Ok(VideoOpenAction::Initialize) => {}
        Err(status) => return complete(irp, status, 0),
    }
    // Publish Running before entering arbitrary miniport code; no state borrow spans the call.
    let initialize = read_volatile((FSD_SHARED_VADDR + SH_VIDEO_HW_INITIALIZE) as *const u64);
    if initialize == 0 {
        protocol_violation(device, irp, STATUS_INVALID_DEVICE_REQUEST as u32 as u64, 0);
    }
    let init: extern "win64" fn(u64) -> u8 = core::mem::transmute(initialize as *const ());
    let ok = init(hw_extension);
    let calls = read_volatile((FSD_SHARED_VADDR + SH_VIDEO_HW_INITIALIZE_CALLS) as *const u64);
    write_volatile(
        (FSD_SHARED_VADDR + SH_VIDEO_HW_INITIALIZE_CALLS) as *mut u64,
        calls.saturating_add(1),
    );
    write_volatile(
        (FSD_SHARED_VADDR + SH_VIDEO_HW_INITIALIZE_OK) as *mut u8,
        ok,
    );
    let completion = update_device_state(device, |state| state.finish_initialize(ok != 0))
        .unwrap_or_else(|status| protocol_violation(device, irp, status as u32 as u64, ok as u64));
    complete(irp, completion.status as i32, completion.information)
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
    let hw_extension = match port_extension(device) {
        Ok(extension) => extension + VIDEO_PORT_DEVICE_STATE_SIZE as u64,
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
            if request_major == major::IRP_MJ_CREATE {
                return create(device, irp, stack, hw_extension);
            }
            return complete(irp, STATUS_SUCCESS, 0);
        }
        major::IRP_MJ_DEVICE_CONTROL => {}
        _ => return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0),
    }
    let output_len = read_unaligned((stack + 0x08) as *const u32);
    let input_len = read_unaligned((stack + 0x10) as *const u32);
    let code = read_unaligned((stack + 0x18) as *const u32);
    if let Err(status) =
        validate_device_control_requestor(read_unaligned((irp + 0x40) as *const u8), code)
    {
        return complete(irp, status as i32, 0);
    }
    let start_io = read_volatile((FSD_SHARED_VADDR + SH_VIDEO_HW_START_IO) as *const u64);
    if start_io == 0 {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
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
