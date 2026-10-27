//! Pinned LiberNT win32k.sys must resolve its complete native kernel/HAL IAT by exact name.

use nt_pe_loader::ImportRef;
use std::collections::BTreeSet;
use std::path::Path;

fn pinned_native_imports() -> BTreeSet<String> {
    include_str!("fixtures/libernt_win32k_native_imports.txt")
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn pinned_win32k_native_imports_are_all_bound() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Ok(manifest) = std::fs::read_to_string(root.join("rust-micro/vendor/libernt/manifest.txt")) {
        assert!(manifest.contains("source_revision=8e478a22a1e8f8a22bab17131f3184a7b4548c3d"));
    }

    let expected = pinned_native_imports();
    assert_eq!(expected.len(), 272, "review the pinned native import inventory on release change");
    let image = root.join("rust-micro/.tmp/libernt/tree/Windows/system32/win32k.sys");
    if image.exists() {
        let bytes = std::fs::read(image).expect("staged pinned LiberNT win32k.sys");
        let pe = nt_pe_loader::PeFile::parse(&bytes).expect("pinned LiberNT win32k PE");
        let actual: BTreeSet<String> = pe
            .imports()
            .expect("pinned LiberNT win32k imports")
            .into_iter()
            .filter(|dll| {
                dll.name.eq_ignore_ascii_case("ntoskrnl.exe")
                    || dll.name.eq_ignore_ascii_case("hal.dll")
            })
            .flat_map(|dll| {
                let module = dll.name.to_ascii_lowercase();
                dll.functions.into_iter().filter_map(move |function| match function {
                    ImportRef::ByName { name, .. } => Some(format!("{module} {name}")),
                    ImportRef::ByOrdinal { .. } => None,
                })
            })
            .collect();
        assert_eq!(actual, expected, "pinned win32k.sys imports changed; refresh reviewed inventory");
    }

    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let register = source
        .split_once("fn register_trampolines()")
        .expect("win32k export registration")
        .1
        .split_once("pub(crate) fn initialize_export_registry()")
        .expect("end of win32k export registration")
        .0;
    let mut bound = binding_names(register);
    let driver_launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for helper in ["bind_debug_exports", "bind_kd_debug_export"] {
        assert!(register.contains(&format!("crate::driver_launch::{helper}(reg);")));
        let body = driver_launch
            .split_once(&format!("fn {helper}("))
            .expect("shared native export binder")
            .1
            .split_once("\n}\n")
            .expect("end of shared native export binder")
            .0;
        bound.extend(binding_names(body));
    }
    assert!(register.contains("crate::ex_rundown_exports::bind_ex_rundown_exports(reg);"));
    bound.extend(binding_names(include_str!(
        "../../../components/ntos-executive/src/ex_rundown_exports.rs"
    )));
    assert!(register.contains("crate::rtl_avl_exports::bind_rtl_avl_exports(reg);"));
    bound.extend(binding_names(include_str!(
        "../../../components/ntos-executive/src/rtl_avl_exports.rs"
    )));
    let data_exports = source
        .split_once("const DATA_EXPORTS: ")
        .expect("win32k data export declarations")
        .1
        .split_once("fn object_type_cell_value")
        .expect("end of win32k data export declarations")
        .0;
    bound.extend(
        data_exports
            .split("(\"")
            .skip(1)
            .filter_map(|entry| entry.split_once('"').map(|(name, _)| name)),
    );
    let missing: Vec<_> = expected
        .iter()
        .filter(|entry| !bound.contains(entry.split_once(' ').unwrap().1))
        .collect();
    assert!(missing.is_empty(), "unbound pinned win32k native imports ({}):\n{}", missing.len(), missing.iter().map(|entry| entry.as_str()).collect::<Vec<_>>().join("\n"));
}

fn binding_names(source: &str) -> BTreeSet<&str> {
    source
        .split("reg.bind(")
        .skip(1)
        .filter_map(|call| call.trim_start().strip_prefix('"'))
        .filter_map(|call| call.split_once('"').map(|(name, _)| name))
        .collect()
}
