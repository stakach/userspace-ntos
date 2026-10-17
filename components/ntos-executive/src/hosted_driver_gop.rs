//! The bootloader GOP record exposed to hosted WDDM drivers by Inbv.

use super::*;
use core::sync::atomic::AtomicBool;

/// Once a display driver takes postdisplay ownership, this boot-video owner never paints again.
static DISPLAY_OWNERSHIP_LOST: AtomicBool = AtomicBool::new(false);

/// LiberNT `LOADER_PARAMETER_FRAMEBUFFER` from `sdk/include/reactos/loader_framebuffer.h`.
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct LoaderParameterFramebuffer {
    FrameBufferBase: u64,
    FrameBufferSize: u32,
    HorizontalResolution: u32,
    VerticalResolution: u32,
    PixelsPerScanLine: u32,
    PixelFormat: u32,
    RedMask: u32,
    GreenMask: u32,
    BlueMask: u32,
    Reserved: u32,
    Dpi: u32,
}

const _: () = assert!(core::mem::size_of::<LoaderParameterFramebuffer>() == 48);
const GOP_ARG_BYTES: u64 = core::mem::size_of::<LoaderParameterFramebuffer>() as u64;
const _: () = assert!(GOP_ARG_BYTES <= FSD_ARG_BYTES);

// Simpleboot validates 32-bpp RGB mask positions before producing these four framebuffer types.
fn masks(fb_type: u64) -> Option<(u32, u32, u32)> {
    match fb_type {
        0 => Some((0x00ff_0000, 0x0000_ff00, 0x0000_00ff)), // ARGB
        1 => Some((0xff00_0000, 0x00ff_0000, 0x0000_ff00)), // RGBA
        2 => Some((0x0000_00ff, 0x0000_ff00, 0x00ff_0000)), // ABGR
        3 => Some((0x0000_ff00, 0x00ff_0000, 0xff00_0000)), // BGRA
        _ => None,
    }
}

/// BOOLEAN InbvGetGopFrameBufferInfo(PLOADER_PARAMETER_FRAMEBUFFER).
pub(super) extern "win64" fn s_inbv_get_gop_frame_buffer_info(output: u64) -> u8 {
    if output == 0 || output.checked_add(GOP_ARG_BYTES).is_none() {
        return 0;
    }
    let (label, valid, _, _, _) = unsafe {
        call_on4(FSD_SERVICE_GOP_QUERY_LABEL << 12, 0, 0, 0, 0)
    };
    if label != 0 || valid != 1 {
        return 0;
    }
    unsafe {
        let arg = hosted_provider_export_lane::current_component_arg()
            .or_else(hosted_class_irp_lane::current_component_arg)
            .unwrap_or(FSD_ARG_VADDR);
        copy_bytes_unchecked(output, arg, GOP_ARG_BYTES);
    }
    1
}

/// BOOLEAN InbvHasValidGopFrameBuffer(void). LiberNT checks these four fields after GetGopInfo.
pub(super) extern "win64" fn s_inbv_has_valid_gop_frame_buffer() -> u8 {
    let mut record = core::mem::MaybeUninit::<LoaderParameterFramebuffer>::uninit();
    if s_inbv_get_gop_frame_buffer_info(record.as_mut_ptr() as u64) == 0 {
        return 0;
    }
    let record = unsafe { record.assume_init() };
    (record.FrameBufferBase != 0
        && record.FrameBufferSize != 0
        && record.HorizontalResolution != 0
        && record.VerticalResolution != 0) as u8
}

/// VOID InbvNotifyDisplayOwnershipLost(INBV_RESET_DISPLAY_PARAMETERS).
/// LiberNT dxgkrnl passes NULL at the postdisplay handoff. A non-NULL callback needs a
/// separate retained reset-callback lifetime, so reject it terminally until implemented.
pub(super) extern "win64" fn s_inbv_notify_display_ownership_lost(callback: u64) {
    let (info, status, _, _, _) = unsafe {
        call_on4_raw((FSD_SERVICE_DISPLAY_OWNERSHIP_LABEL << 12) | 1, callback, 0, 0, 0)
    };
    if info != 1 || status as u32 as i32 != STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(
            0xc4, [FSD_SERVICE_DISPLAY_OWNERSHIP_LABEL, callback, info, status],
        ); }
    }
}

pub(crate) fn service_hosted_driver_display_ownership_lost(
    channel: &crate::spawn_hosts::PumpChannel,
    callback: u64,
    caller_badge: u64,
    reply_cap: u64,
) -> i32 {
    let Some((instance, inst)) = instance_for_pump_channel(channel, reply_cap) else {
        return STATUS_ACCESS_DENIED;
    };
    if hosted_driver_caller(instance, inst, caller_badge).is_none() {
        return STATUS_ACCESS_DENIED;
    }
    if callback != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    if crate::FB_BAR_FRAME_COUNT.load(Ordering::Acquire) == 0 {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    DISPLAY_OWNERSHIP_LOST.store(true, Ordering::Release);
    STATUS_SUCCESS
}

/// The pointer returned to the driver is always in its own VSpace. The root writes only the
/// authenticated caller's shared argument bank; no process address is sent through IPC.
pub(crate) fn service_hosted_driver_gop_query(
    channel: &crate::spawn_hosts::PumpChannel,
    caller_badge: u64,
    reply_cap: u64,
) -> u64 {
    let Some((instance, inst)) = instance_for_pump_channel(channel, reply_cap) else {
        return 0;
    };
    if hosted_driver_caller(instance, inst, caller_badge).is_none() {
        return 0;
    }
    let arg = unsafe { hosted_provider_export_lane::executive_arg_for_shared(channel.shared_va) }
        .or_else(|| unsafe { hosted_class_irp_lane::executive_arg_for_shared(channel.shared_va) })
        .unwrap_or(inst.exec_arg_va);
    if arg == 0 { return 0; }
    let bar = crate::FB_BAR_PADDR.load(Ordering::Acquire);
    let pages = crate::FB_BAR_FRAME_COUNT.load(Ordering::Acquire);
    let offset = crate::FB_SCANOUT_BAR_OFFSET.load(Ordering::Acquire);
    let size = crate::FB_SIZE_BYTES.load(Ordering::Acquire);
    let width = crate::FB_WIDTH.load(Ordering::Acquire);
    let height = crate::FB_HEIGHT.load(Ordering::Acquire);
    let scanline = crate::FB_SCANLINE.load(Ordering::Acquire);
    let Some((red, green, blue)) = masks(crate::FB_TYPE.load(Ordering::Acquire)) else {
        return 0;
    };
    if bar == 0 || pages == 0 || width == 0 || height == 0 || scanline < width * 4
        || scanline % 4 != 0 || size == 0 || size > u32::MAX as u64
        || size > pages.saturating_mul(0x1000).saturating_sub(offset)
    {
        return 0;
    }
    let Some(base) = bar.checked_add(offset) else { return 0; };
    let (Ok(width), Ok(height), Ok(pixels_per_scanline)) = (
        u32::try_from(width), u32::try_from(height), u32::try_from(scanline / 4),
    ) else { return 0; };
    let record = LoaderParameterFramebuffer {
        FrameBufferBase: base,
        FrameBufferSize: size as u32,
        HorizontalResolution: width,
        VerticalResolution: height,
        PixelsPerScanLine: pixels_per_scanline,
        PixelFormat: 32,
        RedMask: red,
        GreenMask: green,
        BlueMask: blue,
        Reserved: !(red | green | blue),
        Dpi: 96, // LiberNT LOADER_PARAMETER_FRAMEBUFFER_DPI_DEFAULT.
    };
    unsafe {
        core::ptr::write_unaligned(arg as *mut LoaderParameterFramebuffer, record);
    }
    1
}
