const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn foreign_device_mirror_with_empty_major_function_routes_internal_control() {
    let dispatch = LAUNCH
        .split("extern \"win64\" fn s_iof_call_driver(")
        .nth(1)
        .expect("hosted IofCallDriver");
    let empty_handler = dispatch
        .split("if handler == 0 {")
        .nth(1)
        .expect("empty consumer mirror dispatch handler")
        .split("return 0xC000_0010u32 as i32;")
        .next()
        .expect("empty handler rejection");
    assert!(
        empty_handler.contains("forward_hosted_internal_control(device, irp, next, current_location_after_forward)"),
        "file-less internal control must route before the empty mirror handler rejects it"
    );
}
