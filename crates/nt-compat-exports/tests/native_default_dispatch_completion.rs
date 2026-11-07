//! The default MajorFunction is a real terminal IRP dispatch.
//! A status-only return leaves the retained source graph without completion ownership.

const NATIVE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn default_invalid_device_request_completes_after_publishing_status() {
    let dispatch = NATIVE
        .split("unsafe extern \"win64\" fn fsd_invalid_device_request(")
        .nth(1)
        .expect("default MajorFunction")
        .split("fn component_video_device_name(")
        .next()
        .expect("default MajorFunction boundary");
    let status = dispatch.find("WDM_X64_IRP_IO_STATUS_STATUS_OFFSET")
        .expect("default status publication");
    let information = dispatch.find("(irp + 0x38) as *mut u64")
        .expect("default zero Information publication");
    let completion = dispatch.find("s_io_complete_request(irp, 0)")
        .expect("default handler must call IoCompleteRequest");
    assert!(status < information && information < completion,
        "completion must observe the terminal status and zero Information");
}
