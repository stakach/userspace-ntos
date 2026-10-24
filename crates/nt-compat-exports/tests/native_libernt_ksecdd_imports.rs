//! Every released KsecDD kernel import must have an explicit generic-driver binding.

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

#[test]
fn released_ksecdd_imports_are_bound_by_name() {
    let imports = libernt_driver_imports::imports("ksecdd.sys", &["ntoskrnl.exe"]);
    assert_eq!(imports.len(), 34, "review the pinned KsecDD import inventory");
    let exports = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for name in imports {
        assert!(
            exports.contains(&format!("\"{name}\",")),
            "generic driver export registry lacks KsecDD import {name}"
        );
    }
}
