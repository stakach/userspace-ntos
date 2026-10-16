//! The released dxgkrnl PoFx imports must reach an owned component-power broker.

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

#[test]
fn pinned_dxg_pofx_imports_have_live_native_entry_points() {
    let imports = libernt_driver_imports::imports("dxgkrnl.sys", &["ntoskrnl.exe"]);
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_pofx.rs");
    for name in [
        "PoFxRegisterDevice", "PoFxUnregisterDevice", "PoFxActivateComponent",
        "PoFxIdleComponent", "PoFxSetComponentLatency", "PoFxSetComponentResidency",
        "PoFxCompleteIdleCondition", "PoFxCompleteIdleState",
        "PoFxCompleteDevicePowerNotRequired", "PoFxReportDevicePoweredOn",
        "PoFxPowerControl",
    ] {
        assert!(imports.contains(name), "pinned dxg import inventory changed: {name}");
        assert!(launch.contains(&format!("\"{name}\",")), "missing export {name}");
    }
    for contract in [
        "authenticated_hosted_pdo", "instance_domain_identity", "hosted_driver_caller",
        "PofxManager", "PoFxDeviceV3", "PoFxComponentV2", "try_reserve",
        "retire_domain", "quiesced",
    ] {
        assert!(adapter.contains(contract), "PoFx adapter lost {contract}");
    }
}
