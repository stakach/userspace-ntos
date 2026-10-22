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
