//! Native stack capture for a hosted kernel driver on its exact paused IRP lane.

use nt_compat_exports::DriverExportRegistry;
use nt_unwind::{project_stack_back_trace, stack_back_trace_request};

pub(super) const LABEL: u64 = 0x7EF;

unsafe extern "win64" fn hosted_driver_native_frame_chain_bridge(packet_va: u64) -> u32 {
    let (words, count, _, _, _) = unsafe {
        super::call_on4_raw((LABEL << 12) | 1, packet_va, 0, 0, 0)
    };
    if words != 1 || count > nt_unwind::kernel_frame_ingress::FRAME_CHAIN_RESULT_CAPACITY as u64 {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, packet_va, words, count]) }
    }
    count as u32
}

extern "win64" fn dispatch_captured_frame(packet: *const u64) -> u32 {
    crate::kernel_frame_capture::dispatch_captured_frame(
        packet,
        hosted_driver_native_frame_chain_bridge,
    )
}

crate::kernel_frame_capture::kernel_frame_capture_entry!(rtl_walk_frame_chain, dispatch_captured_frame);

/// `USHORT RtlCaptureStackBackTrace(ULONG Skip, ULONG Capture, PVOID* Trace, PULONG Hash)`.
///
/// The native walker records its own caller before the Rust prologue; the pure contract skips the
/// `RtlCaptureStackBackTrace` frame, then copies only observed return PCs and their wrapping hash.
/// No result is reported if the exact live lane or admitted unwind image cannot be captured.
pub(super) unsafe extern "win64" fn rtl_capture_stack_back_trace(
    frames_to_skip: u32,
    frames_to_capture: u32,
    back_trace: *mut u64,
    back_trace_hash: *mut u32,
) -> u16 {
    if frames_to_capture != 0 && back_trace.is_null() {
        return 0;
    }
    let Some((skip, total)) = stack_back_trace_request(frames_to_skip, frames_to_capture) else {
        return 0;
    };
    let mut frames = [0u64; nt_unwind::kernel_frame_ingress::FRAME_CHAIN_RESULT_CAPACITY];
    let count = unsafe { rtl_walk_frame_chain(frames.as_mut_ptr(), total as u32, 0) as usize };
    if count <= skip || count > total {
        return 0;
    }
    // A zero requested capture may still reach here. Construct no slice from a null pointer.
    let mut empty = [];
    let output = if frames_to_capture == 0 {
        &mut empty[..]
    } else {
        unsafe { core::slice::from_raw_parts_mut(back_trace, frames_to_capture as usize) }
    };
    let Some((written, hash)) = project_stack_back_trace(&frames[..count], skip, output) else {
        return 0;
    };
    if !back_trace_hash.is_null() {
        unsafe { core::ptr::write(back_trace_hash, hash) };
    }
    written as u16
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind(
        "RtlCaptureStackBackTrace",
        rtl_capture_stack_back_trace as *const () as usize as u64,
    );
}
