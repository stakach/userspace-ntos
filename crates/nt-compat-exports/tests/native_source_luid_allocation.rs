//! Released dxgkrnl's kernel LUID import must share Nt's root allocator.

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

#[test]
fn pinned_dxg_luid_import_uses_root_owned_nt_allocator() {
    let imports = libernt_driver_imports::imports("dxgkrnl.sys", &["ntoskrnl.exe"]);
    assert!(imports.contains("ZwAllocateLocallyUniqueId"));

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let broker = include_str!("../../../components/ntos-executive/src/hosted_driver_luid.rs");
    let exec = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    assert!(launch.contains("\"ZwAllocateLocallyUniqueId\","));
    assert!(broker.contains("instance_for_pump_channel"));
    assert!(broker.contains("hosted_driver_caller"));
    assert!(broker.contains("EXP_LUID.allocate()"));
    assert!(exec.contains("EXP_LUID.allocate()"));
}
