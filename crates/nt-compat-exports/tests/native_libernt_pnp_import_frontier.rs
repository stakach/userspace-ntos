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
