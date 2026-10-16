//! The released display kernel imports both callable Ps state queries and
//! pointer-valued Ps data exports. The generic driver loader must preserve
//! that distinction when it resolves the pinned PE's eager import table.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

const FUNCTIONS: [&str; 3] = [
    "PsGetProcessExitStatus",
    "PsIsSystemProcess",
    "PsIsThreadTerminating",
];
const DATA: [&str; 3] = ["PsInitialSystemProcess", "PsProcessType", "PsThreadType"];

#[test]
fn released_dxgkrnl_process_state_functions_bind_in_the_generic_driver_registry() {
    let imports = pinned_dxgkrnl_ntoskrnl_imports();
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let bindings = source
        .split_once("fn register_fsd_trampolines()")
        .expect("generic hosted-driver registry")
        .1
        .split_once("pub(crate) fn initialize_fsd_export_registry()")
        .expect("generic hosted-driver registry end")
        .0;
    for name in FUNCTIONS {
        assert!(imports.contains(name), "released dxgkrnl must import {name}");
        assert!(
            nt_compat_exports::module_export_descriptor("ntoskrnl.exe", name).is_some(),
            "kernel provider must declare {name}"
        );
        assert!(
            bindings.contains(&format!("\"{name}\"")),
            "generic native driver registry must bind {name}"
        );
    }
}

#[test]
fn released_dxgkrnl_ps_data_imports_resolve_to_cells_not_trampolines() {
    let imports = pinned_dxgkrnl_ntoskrnl_imports();
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let cells = source
        .split_once("fn fsd_data_export_addr(name: &str) -> Option<u64> {")
        .expect("generic hosted-driver data exports")
        .1
        .split_once("unsafe fn hosted_configuration_entry_matches(")
        .expect("generic hosted-driver data export end")
        .0;
    for name in DATA {
        assert!(imports.contains(name), "released dxgkrnl must import {name}");
        assert!(
            nt_compat_exports::module_export_descriptor("ntoskrnl.exe", name).is_some(),
            "kernel provider must declare {name}"
        );
        assert!(
            cells.contains(&format!("\"{name}\" => hosted_driver_process_state::")),
            "{name} must resolve through a mapped pointer-valued data cell"
        );
    }
}

#[test]
fn ps_data_cell_targets_live_in_the_mapped_shared_executive_image() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let spawn = driver
        .split_once("unsafe fn spawn_fsd_component(")
        .expect("generic driver component spawn")
        .1
        .split_once("unsafe fn hosted_kuser_frame(")
        .expect("generic driver component spawn end")
        .0;
    assert!(spawn.contains("image_rights: Rights::Uniform(3)"));
    assert!(spawn.contains("lazy_image: true"));
    let mechanism = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    assert!(mechanism.contains("base = `IMAGE_BASE`, count = `IMAGE_FRAMES_COUNT`"));
    let bootstrap = include_str!("../../../components/ntos-executive/src/ps_bootstrap.rs");
    assert!(bootstrap.contains("struct InitialObjectPage([u8; 4096])"));
    assert!(bootstrap.contains("static mut INITIAL_PROCESS: InitialObjectPage"));
    let types = include_str!("../../nt-object-manager/src/object_type.rs");
    assert!(types.contains("pub static mut PROCESS_OBJECT_TYPE: ObjectType"));
    assert!(types.contains("pub static mut THREAD_OBJECT_TYPE: ObjectType"));
    let cells = include_str!("../../../components/ntos-executive/src/hosted_driver_process_state.rs");
    assert!(cells.contains("initial.process_body"));
    assert!(cells.contains("process_object_type_addr()"));
    assert!(cells.contains("thread_object_type_addr()"));
}

fn pinned_dxgkrnl_ntoskrnl_imports() -> BTreeSet<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bytes = std::fs::read(
        root.join("rust-micro/.tmp/libernt/tree/Windows/system32/drivers/dxgkrnl.sys"),
    )
    .expect("pinned released dxgkrnl.sys");
    let pe = nt_pe_loader::PeFile::parse(&bytes).expect("released dxgkrnl PE");
    pe.imports()
        .expect("released dxgkrnl imports")
        .into_iter()
        .filter(|dll| dll.name.eq_ignore_ascii_case("ntoskrnl.exe"))
        .flat_map(|dll| dll.functions)
        .filter_map(|entry| match entry {
            ImportRef::ByName { name, .. } => Some(name),
            ImportRef::ByOrdinal { .. } => None,
        })
        .collect()
}
