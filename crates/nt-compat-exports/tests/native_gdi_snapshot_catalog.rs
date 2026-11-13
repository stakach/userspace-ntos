//! A mapped GDI dependency must use the bytes retained by its load owner.

const LOADER: &str = include_str!("../../../components/ntos-executive/src/win32k_image_loader.rs");

fn body(name: &str) -> &'static str {
    let start = LOADER.find(&format!("fn {name}(")).expect("loader function");
    let source = &LOADER[start..];
    let end = source.find("\n}").expect("loader function end");
    &source[..end]
}

#[test]
fn retained_catalog_is_authoritative_for_recursive_gdi_imports() {
    let load = body("load_installed_from_catalog");
    assert!(load.contains("snapshot_for(catalog, &name)"));
    assert!(!load.contains("fat_open_path(") && !load.contains("fat_read_file("));
    let dependency = body("load_dependency");
    assert!(dependency.contains("Some(catalog) => load_installed_from_catalog"));
    let checked = body("checked_image");
    assert!(checked.contains("load_dependency(&name, pml4, catalog)"));
    assert!(checked.contains("resolve_import(&dll.name, symbol, pml4, catalog"));
    let resolver = body("resolve_import");
    assert!(resolver.contains("load_dependency(&module, pml4, catalog)"));
}
