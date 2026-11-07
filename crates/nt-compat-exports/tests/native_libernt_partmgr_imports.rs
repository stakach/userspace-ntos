//! The pinned partmgr import table must resolve through the native driver registry.
//!
//! CI checks the reviewed exact-IAT fixture; a locally staged release is additionally compared
//! byte-for-byte by the shared PE fixture reader before this registry audit runs.

use std::collections::BTreeSet;

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

fn direct_bindings(source: &str) -> BTreeSet<String> {
    source.split("reg.bind(").skip(1).filter_map(|tail| {
        let quoted = tail.trim_start().strip_prefix('"')?;
        let (name, _) = quoted.split_once('"')?;
        Some(name.to_owned())
    }).collect()
}

#[test]
fn pinned_partmgr_entire_ntoskrnl_import_table_resolves_before_driver_entry() {
    let imports = libernt_driver_imports::imports("partmgr.sys", &["ntoskrnl.exe"]);
    assert_eq!(imports.len(), 50, "review the pinned partmgr IAT when the release changes");

    let resolver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(resolver.contains("hosted_driver_remove_lock::bind_remove_lock_exports(reg);"));
    assert!(resolver.contains("hosted_partition_table::bind(reg);"));
    let mut bindings = direct_bindings(resolver);
    bindings.extend(direct_bindings(include_str!(
        "../../../components/ntos-executive/src/hosted_driver_remove_lock.rs"
    )));
    bindings.extend(direct_bindings(include_str!(
        "../../../components/ntos-executive/src/hosted_partition_table.rs"
    )));
    let missing: BTreeSet<_> = imports.difference(&bindings).cloned().collect();
    assert!(missing.is_empty(), "pinned partmgr.sys cannot load; missing native imports: {missing:?}");
}
