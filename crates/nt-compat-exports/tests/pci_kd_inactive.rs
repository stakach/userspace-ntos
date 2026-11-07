//! A missing kernel-debug transport is an explicit failure, not a debug-state change.

use nt_compat_exports::kd_debug_control::status_without_transport;

#[test]
fn released_pci_kd_toggle_imports_report_inactive_without_transport() {
    assert_eq!(status_without_transport(), 0xC000_0354u32 as i32);
    let native = include_str!("../../../components/ntos-executive/src/hosted_kd_debug.rs");
    assert!(native.contains("status_without_transport()"));
    assert!(native.contains("kernel_debugger_connected()"));
}
