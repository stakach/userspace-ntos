//! The hosted storage class driver captures its own live kernel stack through an owned IRP lane.

#[test]
fn native_stack_capture_uses_exact_paused_driver_lane_and_image_catalog() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let route = include_str!("../../../components/ntos-executive/src/hosted_driver_frame_capture.rs");
    let broker = include_str!("../../../components/ntos-executive/src/hosted_exception_frame_chain.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");

    assert!(launch.contains("hosted_driver_frame_capture::bind(reg);"));
    assert!(route.contains("RtlCaptureStackBackTrace"));
    assert!(route.contains("stack_back_trace_request"));
    assert!(route.contains("project_stack_back_trace"));
    assert!(route.contains("rtl_walk_frame_chain"));
    assert!(route.contains("call_on4_raw"));
    assert!(pump.contains("FSD_SERVICE_FRAME_CHAIN_LABEL"));
    assert!(pump.contains("authenticated_badge(ch, msg.badge)"));
    assert!(pump.contains("capture_hosted_driver_frame_chain"));
    assert!(broker.contains("StackLease::new(channel, reply_cap, badge)"));
    assert!(broker.contains("KernelFrameIngressPacket::capture_bounded"));
    assert!(broker.contains("super::with_catalog(channel, reply_cap"));
    assert!(broker.contains("CapturedKernelCallSite::from_entry"));
    assert!(broker.contains("Err(Uncertain)"));
}
