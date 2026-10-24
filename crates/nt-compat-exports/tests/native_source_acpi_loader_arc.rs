//! The released LiberNT ACPI driver locates its loader node by the compiled ARC ABI.

#[test]
fn acpi_bios_node_uses_multifunction_adapter_arc_type() {
    let config = include_str!("../src/configuration.rs");
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let fixture = include_str!("fixtures/libernt_acpi_loader_abi.txt");
    assert!(fixture.contains("loader_configuration_root_offset=0xb0"));
    assert!(fixture.contains("adapter_class=3"));
    assert!(fixture.contains("multifunction_adapter=12"));
    assert!(config.contains("pub const ARC_ADAPTER_CLASS: u32 = 3;"));
    assert!(config.contains("pub const ARC_MULTIFUNCTION_ADAPTER: u32 = 12;"));
    assert!(launch.contains("const FSD_LOADER_CONFIGURATION_ROOT_OFF: u64 = 0xB0;"));
    assert!(launch.contains("(block + FSD_LOADER_CONFIGURATION_ROOT_OFF) as *mut u64"));
    assert!(launch.contains("nt_compat_exports::configuration::ARC_ADAPTER_CLASS"));
    assert!(launch.contains("nt_compat_exports::configuration::ARC_MULTIFUNCTION_ADAPTER"));
}
