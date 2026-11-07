//! Boot source preload must use the CM generation selected after ACPI root publication.

#[test]
fn preload_uses_the_validated_boot_plan_generation() {
    let source = std::env::var("BOOT_PRELOAD_SOURCE")
        .map(|path| std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|_| include_str!("../../../components/ntos-executive/src/main.rs").into());
    let acpi = source.find("publish_acpi_root_devnode_from_registry_policy()")
        .expect("ACPI root publication");
    let boot_plan = source[acpi..].find("let boot_driver_snapshot = config_manager_query_driver_launch_plan(")
        .map(|offset| acpi + offset).expect("post-publication boot launch plan");
    let preload = source[boot_plan..].find("driver_launch::stage_registry_boot_driver_sources(")
        .map(|offset| boot_plan + offset).expect("boot source preload");
    let call = &source[preload..source[preload..].find(')').unwrap() + preload + 1];
    assert!(call.contains("boot_driver_snapshot.mount_generation"),
        "preload must use the validated plan generation after the ACPI root mutation: {call}");
    assert!(!call.contains("live_cm_mount.generation"));
}
