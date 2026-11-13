//! Pinned driver imports must resolve to source-owned generic kernel exports.

#[path = "support/libernt_driver_imports.rs"]
mod libernt_driver_imports;

#[test]
fn released_acpi_and_basicdisplay_imports_have_generic_bindings() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    for (driver, symbol) in [
        ("acpi.sys", "ExpInterlockedFlushSList"),
        ("basicdisplay.sys", "KeRemoveQueueDpc"),
    ] {
        let imported = libernt_driver_imports::imports(driver, &["ntoskrnl.exe"])
            .contains(symbol);
        assert!(imported, "pinned {driver} no longer imports {symbol}");
        assert!(launch.contains(&format!("\"{symbol}\",")), "generic export registry lacks {symbol}");
    }
}
