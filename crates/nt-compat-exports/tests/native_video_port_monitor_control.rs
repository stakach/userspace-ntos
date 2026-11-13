use std::fs;
use std::path::PathBuf;

fn native_source(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join("../../components/ntos-executive/src").join(name))
        .expect("native source")
}

#[test]
fn monitor_enumeration_is_consumed_by_video_port_before_miniport_start_io() {
    let control = native_source("hosted_video_port_control.rs");
    let port_dispatch = control.find("pub(super) unsafe extern \"win64\" fn dispatch(")
        .expect("VideoPort dispatch");
    let body = &control[port_dispatch..];
    let miniport_call = body.find("call_hosted_pe(start_io,")
        .expect("miniport StartIO");
    let miniport_gate = body.find("if start_io == 0")
        .expect("miniport availability gate");
    let port_enum = body.find("IOCTL_VIDEO_ENUM_MONITOR_PDO")
        .expect("port-owned monitor enumeration branch");
    assert!(port_enum < miniport_gate && port_enum < miniport_call,
        "port-owned monitor enumeration must not require HwStartIO");
    assert!(body[port_enum..miniport_call].contains("enumerate_monitor_pdos("),
        "VideoPort must enumerate its actual published child PDOs");
}

#[test]
fn empty_monitor_array_is_an_allocated_null_terminated_port_result() {
    let pnp = native_source("hosted_video_port_pnp.rs");
    assert!(pnp.contains("fn enumerate_monitor_pdos("));
    assert!(pnp.contains("parent.children.iter()"), "published child graph is authoritative");
    assert!(pnp.contains("monitor_projection_layout(children.len())"),
        "the empty list still has space for a null terminator");
    assert!(pnp.contains("pool_alloc(layout.visible_bytes as u64)"));
    assert!(pnp.contains("core::ptr::write_bytes(allocation as *mut u8, 0,"));
    let control = native_source("hosted_video_port_control.rs");
    assert!(control.contains("return complete(irp, status, core::mem::size_of::<u64>() as u64)"));
}

#[test]
fn absent_child_list_requires_a_validated_live_video_fdo() {
    let pnp = native_source("hosted_video_port_pnp.rs");
    let start = pnp.find("fn enumerate_monitor_pdos(").expect("monitor enumeration");
    let body = &pnp[start..];
    let snapshot = body.find("let children =").expect("child list snapshot");
    assert!(body[..snapshot].contains("opened_video_fdo(parent_device)"),
        "an absent child list must be tied to a validated live VideoPort FDO");
}

#[test]
fn populated_monitor_array_retains_each_real_child_before_publication() {
    let pnp = native_source("hosted_video_port_pnp.rs");
    let enumeration = pnp.split("fn enumerate_monitor_pdos(").nth(1)
        .expect("VideoPort monitor enumeration");
    let enumeration = enumeration.split("unsafe fn complete(").next()
        .expect("enumeration boundary");
    assert!(!enumeration.contains("return Err(0xc000_00bbu32 as i32)"),
        "a populated child list must not be silently replaced or rejected");
    assert!(enumeration.contains("monitor_projection_layout"),
        "the output allocation must fit every child and its null terminator");
    assert!(enumeration.contains("component_pool_allocation_generation(device)"),
        "each child must have an exact physical allocation identity");
    assert!(enumeration.contains("parent.monitor_arrays.push"),
        "the source array must own references independently of BusRelations");
    assert!(enumeration.find("MonitorReferencePhase::Referencing").unwrap()
        < enumeration.find("s_obf_reference_object").unwrap(),
        "each possible native reference effect must have a durable owner first");
    let acknowledgement = pnp.split("fn acknowledge_monitor_array(").nth(1)
        .expect("array-specific reference acknowledgement");
    assert!(acknowledgement.contains("row.allocation == allocation && row.allocation_generation == allocation_generation"));
    assert!(acknowledgement.find("MonitorReferencePhase::Releasing").unwrap()
        < acknowledgement.find("s_obf_dereference_object").unwrap(),
        "an uncertain dereference must remain fenced against replay");
}
