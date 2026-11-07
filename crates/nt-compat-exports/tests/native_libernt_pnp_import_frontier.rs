//! Released boot drivers must resolve the kernel data and function imports they use.

use nt_pe_loader::{ImportRef, PeFile};
use std::{collections::BTreeSet, path::Path};

fn kernel_imports(path: &Path) -> Option<BTreeSet<String>> {
    let image = std::fs::read(path).ok()?;
    let pe = PeFile::parse(&image).expect("released driver PE");
    Some(pe.imports().expect("driver imports").into_iter()
        .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
        .flat_map(|dll| dll.functions)
        .filter_map(|item| match item { ImportRef::ByName { name, .. } => Some(name), _ => None })
        .collect())
}

#[test]
fn pinned_boot_driver_imports_have_owned_kernel_bindings() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    for (driver, symbol) in [
        ("storport.sys", "IoGetConfigurationInformation"),
        ("isapnp.sys", "HalDispatchTable"),
        ("ndis.sys", "ExAllocatePoolWithTagPriority"),
    ] {
        if let Some(imports) = kernel_imports(&drivers.join(driver)) {
            assert!(imports.contains(symbol), "pinned {driver} no longer imports {symbol}");
        }
    }

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let config = include_str!("../../../components/ntos-executive/src/hosted_driver_configuration.rs");
    assert!(launch.contains("hosted_driver_configuration::bind_configuration_export(reg);"));
    assert!(config.contains("reg.bind(\"IoGetConfigurationInformation\","));
    assert!(launch.contains("\"HalDispatchTable\" => FSD_DATA_HAL_DISPATCH_VA"));
    assert!(launch.contains("FSD_DATA_HAL_DISPATCH_VERSION"));
    assert!(launch.contains("reg.bind(\"ExAllocatePoolWithTagPriority\","));
}

#[test]
fn released_storage_and_network_dpc_imports_have_exact_native_contracts() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    for (driver, symbol) in [
        ("storport.sys", "KeAcquireInStackQueuedSpinLockAtDpcLevel"),
        ("storport.sys", "KeReleaseInStackQueuedSpinLockFromDpcLevel"),
        ("ndis.sys", "KeGetCurrentProcessorNumberEx"),
    ] {
        if let Some(imports) = kernel_imports(&drivers.join(driver)) {
            assert!(imports.contains(symbol), "pinned {driver} no longer imports {symbol}");
        }
    }

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let spin = include_str!("../../../components/ntos-executive/src/hosted_driver_queued_spin_lock.rs");
    let cpu = include_str!("../../../components/ntos-executive/src/hosted_driver_processor_mask.rs");
    assert!(launch.contains("\"KeAcquireInStackQueuedSpinLockAtDpcLevel\""));
    assert!(launch.contains("\"KeReleaseInStackQueuedSpinLockFromDpcLevel\""));
    assert!(spin.contains("fn acquire_at_dpc(") && spin.contains("fn release_from_dpc("));
    assert!(spin.contains("current_irql < DISPATCH_LEVEL"));
    assert!(launch.contains("\"KeGetCurrentProcessorNumberEx\""));
    assert!(cpu.contains("fn current_processor_number_ex("));
}

#[test]
fn released_for_dpc_and_processor_index_imports_preserve_real_topology() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    for (driver, symbol) in [
        ("storport.sys", "KeAcquireInStackQueuedSpinLockForDpc"),
        ("storport.sys", "KeReleaseInStackQueuedSpinLockForDpc"),
        ("ndis.sys", "KeGetProcessorNumberFromIndex"),
    ] {
        if let Some(imports) = kernel_imports(&drivers.join(driver)) {
            assert!(imports.contains(symbol), "pinned {driver} no longer imports {symbol}");
        }
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let spin = include_str!("../../../components/ntos-executive/src/hosted_driver_queued_spin_lock.rs");
    let cpu = include_str!("../../../components/ntos-executive/src/hosted_driver_processor_mask.rs");
    for symbol in ["KeAcquireInStackQueuedSpinLockForDpc", "KeReleaseInStackQueuedSpinLockForDpc", "KeGetProcessorNumberFromIndex"] {
        assert!(launch.contains(&format!("\"{symbol}\"")), "missing {symbol} binding");
    }
    assert!(spin.contains("fn acquire_for_dpc(") && spin.contains("fn release_for_dpc("));
    assert!(cpu.contains("fn processor_number_from_index("));
}

#[test]
fn released_network_processor_relationship_import_has_a_native_topology_owner() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    if let Some(imports) = kernel_imports(&drivers.join("ndis.sys")) {
        assert!(imports.contains("KeQueryLogicalProcessorRelationship"));
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let cpu = include_str!("../../../components/ntos-executive/src/hosted_driver_processor_mask.rs");
    assert!(launch.contains("reg.bind(\n        \"KeQueryLogicalProcessorRelationship\""));
    assert!(cpu.contains("fn query_logical_processor_relationship("));
    assert!(cpu.contains("write_relation_group("));
}

#[test]
fn released_network_group_and_guid_imports_have_native_bindings() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    let expected = [
        "KeQueryMaximumProcessorCountEx",
        "KeSetTargetProcessorDpcEx",
        "RtlGUIDFromString",
    ];
    if let Some(imports) = kernel_imports(&drivers.join("ndis.sys")) {
        for symbol in expected { assert!(imports.contains(symbol), "pinned ndis.sys no longer imports {symbol}"); }
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for symbol in expected { assert!(launch.contains(&format!("\"{symbol}\"")), "missing native {symbol}"); }
}

#[test]
fn released_storage_and_network_timer_watchdog_imports_have_native_owners() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    for (driver, symbol) in [
        ("ndis.sys", "KeSetCoalescableTimer"),
        ("storport.sys", "KeQueryDpcWatchdogInformation"),
    ] {
        if let Some(imports) = kernel_imports(&drivers.join(driver)) {
            assert!(imports.contains(symbol), "pinned {driver} no longer imports {symbol}");
        }
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"KeSetCoalescableTimer\""));
    assert!(launch.contains("reg.bind(\n        \"KeQueryDpcWatchdogInformation\""));
    assert!(launch.contains("s_ke_set_coalescable_timer as *const ()"));
    assert!(launch.contains("s_ke_query_dpc_watchdog_information as *const ()"));
}

#[test]
fn released_storport_physical_inverse_uses_published_mappings() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    if let Some(imports) = kernel_imports(&drivers.join("storport.sys")) {
        assert!(imports.contains("MmGetVirtualForPhysical"));
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"MmGetVirtualForPhysical\""));
    assert!(launch.contains("s_mm_get_virtual_for_physical as *const ()"));
    assert!(launch.contains("hosted_component_virtual_address(physical_address, 1)"));
}

#[test]
fn released_network_image_directory_import_uses_checked_pe_parser() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    if let Some(imports) = kernel_imports(&drivers.join("ndis.sys")) {
        assert!(imports.contains("RtlImageDirectoryEntryToData"));
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let image = include_str!("../../../components/ntos-executive/src/hosted_driver_image_directory.rs");
    assert!(launch.contains("reg.bind(\n        \"RtlImageDirectoryEntryToData\""));
    assert!(image.contains("nt_pe_loader::image_directory_entry("));
}

#[test]
fn released_network_unicode_prefix_import_has_a_counted_kernel_binding() {
    let drivers = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rust-micro/.tmp/libernt/tree/Windows/system32/drivers");
    if let Some(imports) = kernel_imports(&drivers.join("ndis.sys")) {
        assert!(imports.contains("RtlPrefixUnicodeString"));
    }
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(launch.contains("reg.bind(\n        \"RtlPrefixUnicodeString\""));
    assert!(launch.contains("fn s_rtl_prefix_unicode_string("));
}
