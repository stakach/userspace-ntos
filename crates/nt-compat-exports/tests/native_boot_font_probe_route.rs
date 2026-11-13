//! Diagnostic font probes use synchronous routed reads only on the inline Boot block route.

const MOUNTED: &str = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const PROBE: &str = include_str!("../../../components/ntos-executive/src/mounted_section_probe.rs");
const BACKEND: &str = include_str!("../../../components/ntos-executive/src/mounted_volume_backend.rs");

#[test]
fn synchronous_font_probes_are_confined_to_inline_boot_reads() {
    let route_guard = MOUNTED.split("fn boot_inline_read_admitted(").nth(1)
        .expect("mount owner must expose an inline-only Boot route guard")
        .split("\n}").next().unwrap();
    assert!(route_guard.contains("exec_block_route_kind"));
    assert!(route_guard.contains("BlockSourceKind::Boot"));

    let file_probe = DRIVER.split("fn probe_kernel_volume_file(").nth(1).unwrap()
        .split("pub(crate) fn driver_id_by_name").next().unwrap();
    assert!(file_probe.contains("boot_inline_read_admitted(mount)"));
    let file_guard = file_probe.find("boot_inline_read_admitted(mount)").unwrap();
    let file_read = file_probe.find("routed_section_io::read(").unwrap();
    assert!(file_guard < file_read, "route must be checked before synchronous file READ");

    let section_probe = PROBE.split("fn probe_font_section_after_file_close(").nth(1).unwrap();
    assert!(section_probe.contains("boot_inline_read_admitted(mount)"));
    let section_guard = section_probe.find("boot_inline_read_admitted(mount)").unwrap();
    let frame_read = section_probe.find("service_generic_section_frame(").unwrap();
    assert!(section_guard < frame_read, "route must be checked before synchronous page fill");

    assert!(BACKEND.contains("route_kind != nt_fs::BlockSourceKind::Boot"),
        "native mounted reads must remain deferred rather than inline");
}
