//! The pinned storage class driver must resolve its entire native kernel IAT before DriverEntry.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const REVISION: &str = "8e478a22a1e8f8a22bab17131f3184a7b4548c3d";

fn pinned_imports() -> BTreeSet<String> {
    let fixture = include_str!("fixtures/libernt_classpnp_native_imports.txt");
    let mut lines = fixture.lines();
    assert_eq!(
        lines.next(),
        Some(format!("# LiberNT source revision {REVISION}").as_str())
    );
    lines.map(str::to_owned).collect()
}

fn binding_names(source: &str) -> BTreeSet<&str> {
    source
        .split("reg.bind(")
        .skip(1)
        .filter_map(|call| call.trim_start().strip_prefix('"'))
        .filter_map(|call| call.split_once('"').map(|(name, _)| name))
        .collect()
}

#[test]
fn pinned_classpnp_native_imports_are_all_bound() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt"))
        .expect("pinned LiberNT manifest");
    assert!(manifest.contains(&format!("source_revision={REVISION}")));

    let expected = pinned_imports();
    assert_eq!(
        expected.len(),
        129,
        "review classpnp imports when the release changes"
    );
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/classpnp.sys");
    if image.exists() {
        let bytes = std::fs::read(image).expect("staged pinned classpnp.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("classpnp PE");
        let actual: BTreeSet<String> = pe
            .imports()
            .expect("classpnp imports")
            .into_iter()
            .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
            .flat_map(|dll| {
                let module = dll.name.to_ascii_lowercase();
                dll.functions.into_iter().map(move |entry| match entry {
                    ImportRef::ByName { name, .. } => format!("{module} {name}"),
                    ImportRef::ByOrdinal { ordinal, .. } => {
                        panic!("classpnp imports {module} by ordinal {ordinal}")
                    }
                })
            })
            .collect();
        assert_eq!(actual, expected, "review changed pinned classpnp IAT");
    }

    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let register = launch
        .split_once("fn register_fsd_trampolines()")
        .expect("native driver export registration")
        .1
        .split_once("pub(crate) fn initialize_fsd_export_registry()")
        .expect("end of native driver export registration")
        .0;
    let mut bound = binding_names(register);
    let void_stubs: Vec<_> = expected
        .iter()
        .filter_map(|entry| {
            let name = entry.split_once(' ')?.1;
            register
                .contains(&format!("reg.bind(\"{name}\", s_void as *const () as usize as u64);"))
                .then_some(name)
        })
        .collect();
    assert!(
        void_stubs.is_empty(),
        "pinned classpnp imports must implement behavior, not bind s_void: {void_stubs:?}"
    );

    // These helper binders are called by register_fsd_trampolines. The win32k registry is
    // deliberately excluded: its bindings do not resolve classpnp's native driver IAT.
    for (call, source) in [
        (
            "crate::ex_rundown_exports::bind_ex_rundown_exports(reg);",
            include_str!("../../../components/ntos-executive/src/ex_rundown_exports.rs"),
        ),
        (
            "io_paging_priority_exports::bind(reg);",
            include_str!("../../../components/ntos-executive/src/io_paging_priority_exports.rs"),
        ),
        (
            "hosted_irp_lifecycle_exports::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_irp_lifecycle_exports.rs"),
        ),
        (
            "crate::rtl_avl_exports::bind_rtl_avl_exports(reg);",
            include_str!("../../../components/ntos-executive/src/rtl_avl_exports.rs"),
        ),
        (
            "crate::hosted_driver_nls_exports::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_nls_exports.rs"),
        ),
        (
            "hosted_driver_object_reference::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_object_reference.rs"),
        ),
        (
            "hosted_driver_interface_registry::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_interface_registry.rs"),
        ),
        (
            "hosted_driver_frame_capture::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_frame_capture.rs"),
        ),
        (
            "hosted_hard_error_verify_device::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_hard_error_verify_device.rs"),
        ),
        (
            "hosted_driver_apc_region::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_apc_region.rs"),
        ),
        (
            "hosted_driver_wmi::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_wmi.rs"),
        ),
        (
            "hosted_partition_table::bind(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_partition_table.rs"),
        ),
        (
            "hosted_driver_remove_lock::bind_remove_lock_exports(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_remove_lock.rs"),
        ),
        (
            "hosted_driver_configuration::bind_configuration_export(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_configuration.rs"),
        ),
        (
            "hosted_driver_pci_kernel::bind_pci_kernel_exports(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_pci_kernel.rs"),
        ),
        (
            "hosted_driver_range_list::bind_range_list_exports(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_range_list.rs"),
        ),
        (
            "hosted_driver_hal_pci::bind_pci_hal_exports(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_hal_pci.rs"),
        ),
        (
            "hosted_driver_power_irp::bind_power_irp_export(reg);",
            include_str!("../../../components/ntos-executive/src/hosted_driver_power_irp.rs"),
        ),
    ] {
        if register.contains(call) {
            bound.extend(binding_names(source));
        }
    }
    for helper in ["bind_debug_exports", "bind_kd_debug_export"] {
        if register.contains(&format!("{helper}(reg);")) {
            let body = launch
                .split_once(&format!("fn {helper}("))
                .expect("native driver debug binder")
                .1
                .split_once("\n}")
                .expect("end of native driver debug binder")
                .0;
            bound.extend(binding_names(body));
        }
    }

    // Data cells are resolved by fsd_data_export_addr before the function registry.
    let data = launch
        .split_once("fn fsd_data_export_addr(name: &str)")
        .expect("native driver data exports")
        .1
        .split_once("\n}")
        .expect("end of native driver data exports")
        .0;
    for line in data.lines() {
        if let Some(name) = line
            .trim_start()
            .strip_prefix('"')
            .and_then(|tail| tail.split_once('"'))
        {
            bound.insert(name.0);
        }
    }

    // Classpnp is loaded as disk.sys's dependency. The primary image's SEH addresses do not
    // prove these imports resolve for that dependency; inspect the dependency resolver itself.
    let dependency_resolver = launch
        .split_once("let mut resolver = HostedProviderImportResolver {")
        .expect("dependency import resolver")
        .1
        .split_once("\n        };")
        .expect("end of dependency import resolver")
        .0;
    if dependency_resolver.contains("seh_unwind_va: Some(") {
        bound.insert("RtlUnwindEx");
    }
    if dependency_resolver.contains("seh_legacy_unwind_va: Some(") {
        bound.insert("RtlUnwind");
    }

    let missing: Vec<_> = expected
        .iter()
        .filter(|entry| !bound.contains(entry.split_once(' ').unwrap().1))
        .collect();
    assert!(
        missing.is_empty(),
        "unbound pinned classpnp native imports ({}):\n{}",
        missing.len(),
        missing
            .iter()
            .map(|entry| entry.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
