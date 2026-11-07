//! KeNumberProcessors is a byte in each hosted driver's mapped DATA page.

#[test]
fn processor_count_data_export_uses_component_va_and_boot_topology() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let resolver = source.split("fn fsd_data_export_addr(").nth(1).expect("data resolver");
    let resolver = resolver.split("unsafe fn hosted_configuration_entry_matches(").next().unwrap();
    assert!(resolver.contains("\"KeNumberProcessors\" => FSD_DATA_KE_NUMBER_PROCESSORS_VA"));

    let init = source.split("unsafe fn initialize_hosted_driver_data_exports(").nth(1)
        .expect("per-instance data initialization");
    let init = init.split("fn fsd_data_export_addr(").next().unwrap();
    assert!(init.contains("FSD_DATA_KE_NUMBER_PROCESSORS_OFF"));
    assert!(init.contains("SYSTEM_PROCESSOR_COUNT.load("));
    assert!(init.contains("as *mut u8"));

    let registry = source.split("fn register_fsd_trampolines()").nth(1).unwrap();
    let registry = registry.split("fn lookup_videoprt_export(").next().unwrap();
    assert!(!registry.contains("addr_of!(KE_NUMBER_PROCESSORS_VALUE)"),
        "root-only data address must not be inserted into an isolated provider IAT");
}
