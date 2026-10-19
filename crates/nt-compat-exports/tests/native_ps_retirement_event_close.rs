//! A Win32k thread exit closes its Event handle while the executive owns the
//! provider activation. The close must use the retained exiting process.

#[test]
fn kernel_owned_thread_exit_closes_only_its_retained_event_handle() {
    let source = include_str!("../../../components/ntos-executive/src/kernel_provider_activation.rs");
    let service = source
        .split("pub(super) unsafe fn service_event(")
        .nth(1)
        .expect("kernel Event service exists")
        .split("pub(crate) unsafe fn validate_win32k_service_call(")
        .next()
        .unwrap();
    assert!(service.contains("W32_EVENT_OP_CLOSE"),
        "a kernel owned Ps exit must route ObCloseHandle to the target process");
    assert!(service.contains("ps_retirement()") && service.contains("ps_retirement_is_current"),
        "the close must require the exact retained Ps target and current generation");
    assert!(service.contains("provider_close_event"),
        "use the existing typed Event handle close contract");
    assert!(service.contains("arg2 != 0 || arg3 != 0")
        || service.contains("!(arg2 == 0 && arg3 == 0)"),
        "reject noncanonical close arguments");
}
