//! Native Win64 RtlWalkFrameChain entry capture for an isolated win32k lane.

// The unresolved symbol is intentional until the win32k bridge is linked into its component.
unsafe extern "win64" {
    fn win32k_native_frame_chain_bridge(packet_va: u64) -> u32;
}

extern "win64" fn dispatch_captured_frame(packet: *const u64) -> u32 {
    crate::kernel_frame_capture::dispatch_captured_frame(packet, win32k_native_frame_chain_bridge)
}

crate::kernel_frame_capture::kernel_frame_capture_entry!(rtl_walk_frame_chain, dispatch_captured_frame);
