use std::fs;
use std::path::PathBuf;

use nt_io_manager::video_monitor_array_projection::{
    monitor_projection_layout, projected_monitor_layout, VIDEO_MONITOR_DEVICE_X64_BYTES,
};

fn native_source(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join("../../components/ntos-executive/src").join(name))
        .expect("native source")
}

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).expect("function");
    let body = &source[start..];
    let open = body.find('{').expect("body");
    let mut depth = 0;
    for (offset, byte) in body.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[..open + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function")
}

#[test]
fn populated_projection_places_ownership_after_the_null_entry() {
    let layout = monitor_projection_layout(2).unwrap();
    assert_eq!(layout.visible_bytes, 3 * VIDEO_MONITOR_DEVICE_X64_BYTES);
    let mut bytes = vec![0u8; layout.allocation_bytes];
    bytes[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[VIDEO_MONITOR_DEVICE_X64_BYTES + 8..VIDEO_MONITOR_DEVICE_X64_BYTES + 16]
        .copy_from_slice(&0x2000u64.to_le_bytes());
    assert_eq!(projected_monitor_layout(&bytes), Ok(layout));

    let bridge = native_source("hosted_kernel_win32k_source_ioctl.rs");
    let project = function(&bridge, "project_monitor_array");
    assert!(project.contains("monitor_projection_layout"),
        "allocate the caller-visible entries, null entry, and private ownership metadata");
    assert!(!project.contains("VIDEO_MONITOR_ARRAY_PROJECTION_BYTES"),
        "a fixed one-entry allocation cannot hold a populated monitor list");
    let component = native_source("win32k_source_irp_call.rs");
    assert!(function(&component, "register_monitor_array_projection")
        .contains("projected_monitor_layout"),
        "terminal admission must locate metadata after the complete null entry");
    let free = function(&component, "claim_monitor_array_projection_free");
    assert!(free.contains("metadata_offset") && !free.contains("projected_monitor_layout"),
        "the exact free claim must use the admitted offset even if caller entries changed");
    let retirement = function(&bridge, "retire_released_monitor_arrays");
    assert!(retirement.contains("monitor_projection_layout(row.monitor_count)")
        && !retirement.contains("projected_monitor_layout"),
        "root retirement must use the retained row layout, not mutable caller entries");
}

#[test]
fn populated_source_pdos_gain_canonical_caller_references_before_publication() {
    let bridge = native_source("hosted_kernel_win32k_source_ioctl.rs");
    let project = function(&bridge, "project_monitor_array");
    assert!(!project.contains("if !monitors.is_empty()"),
        "real monitor PDOs cannot be rejected as unsupported");
    assert!(project.contains("hosted_device_by_identity")
        && project.contains("hosted_device_pointer_registration"),
        "each foreign pointer must resolve to an exact canonical device registration");
    assert!(project.contains("ensure_projection")
        && project.contains("reference_hosted_device_pointer"),
        "the win32k pointer needs its own counted caller reference before publication");
    assert!(bridge.contains("MonitorPdoReferenceLedger"),
        "retain per-array reference progress across redrive, stop, and uncertain effects");
}

#[test]
fn source_free_precedes_exact_video_port_reference_ack() {
    let bridge = native_source("hosted_kernel_win32k_source_ioctl.rs");
    let retirement = function(&bridge, "retire_released_monitor_arrays");
    let source_free = retirement.find("retire_transferred").expect("exact source free");
    let ack = retirement.find("acknowledge_hosted_video_monitor_array")
        .expect("array-specific VideoPort reference acknowledgement");
    let projection_free = retirement.find("try_retire_root_provider_pool_allocation")
        .expect("dependent projection retirement");
    assert!(source_free < ack && ack < projection_free,
        "do not release source PDO references before source free or lose ACK ownership");

    let driver = native_source("driver_launch.rs");
    assert!(driver.contains("FSD_DISPATCH_VIDEO_MONITOR_ARRAY_ACK"),
        "monitor arrays require an ACK distinct from BusRelations");
    assert!(driver.contains("hosted_video_port_pnp::acknowledge_monitor_array"),
        "the ACK must settle the provider's exact parent, allocation, and generation row");
    let stop = function(&bridge, "settle_monitor_array_on_stop");
    assert!(stop.contains("acknowledge_hosted_video_monitor_array"),
        "a sealed unpublished stop must release the source array's counted PDO references");
}

#[test]
fn empty_video_port_array_has_no_provider_reference_ack() {
    let driver = native_source("driver_launch.rs");
    let acknowledgement = function(&driver, "acknowledge_hosted_video_monitor_array");
    let empty = acknowledgement.find("if count == 0 { return Some(true); }")
        .expect("empty arrays transfer no PDO references");
    let dispatch = acknowledgement.find("dispatch_irp_for_instance_exact(")
        .expect("populated array provider ACK");
    assert!(empty < dispatch, "an empty array cannot ACK a missing provider row");
}

#[test]
fn monitor_source_classification_uses_the_completing_device() {
    let driver = native_source("driver_launch.rs");
    let capture = function(&driver, "capture_hosted_video_monitor_array");
    assert!(capture.contains("hosted_device_video_port_initialized(device_id)"),
        "a driver-wide flag cannot identify the exact FDO that returned this array");
}
