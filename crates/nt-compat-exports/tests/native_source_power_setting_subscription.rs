//! Pinned dxgkrnl's optional AC/DC and lid subscriptions cannot be reported
//! successful until a provider supplies the real current setting and callback.

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

#[test]
fn pinned_dxg_power_setting_imports_use_authenticated_root_subscription() {
    let imports = libernt_driver_imports::imports("dxgkrnl.sys", &["ntoskrnl.exe"]);
    assert!(imports.contains("PoRegisterPowerSettingCallback"));
    assert!(imports.contains("PoUnregisterPowerSettingCallback"));

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("\"PoRegisterPowerSettingCallback\","));
    assert!(launch.contains("\"PoUnregisterPowerSettingCallback\","));
    let broker = include_str!("../../../components/ntos-executive/src/hosted_driver_power_setting.rs");
    for authority in [
        "instance_for_pump_channel", "hosted_driver_caller", "authenticated_hosted_device",
        "instance_domain_identity", "hosted_provider_singletons", "STATUS_DEVICE_NOT_READY",
    ] {
        assert!(broker.contains(authority), "power subscription lost {authority}");
    }
}
