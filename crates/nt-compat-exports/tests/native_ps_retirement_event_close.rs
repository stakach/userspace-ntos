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

#[test]
fn kernel_owned_ps_wait_restores_effective_client_before_each_physical_resume() {
    let resume = include_str!("../../../components/ntos-executive/src/kernel_provider_resume.rs");
    let wait = resume
        .split("unsafe fn claim_driver_entry_wait_resume(")
        .nth(1)
        .expect("kernel wait claim exists")
        .split("pub(crate) enum DriverEntryWaitOutcome")
        .next()
        .unwrap();
    let restore = wait.find("restore_ps_retirement_window(caller, &channel)")
        .expect("retained Ps target restores the effective alias owner");
    let consume = wait.find(".begin_wait_resume(").unwrap();
    assert!(restore < consume, "restore before consuming the retained wait ticket");

    let activation = include_str!("../../../components/ntos-executive/src/kernel_provider_activation.rs");
    let yields = activation
        .split("unsafe fn receive_driver_entry_yields(")
        .nth(1)
        .expect("kernel receive yield exists")
        .split("pub(super) unsafe fn service_ps(")
        .next()
        .unwrap();
    let restore = yields.find("restore_ps_retirement_window(caller, &receiving)")
        .expect("IRQ yield reselects the retained Ps target");
    let resume = yields.find("component_pump_continue_receive_after_scheduler_service(")
        .expect("serviced scheduler yield continues the retained physical receive");
    assert!(restore < resume, "restore after IRQ work and before physical receive");

    let attach = include_str!("../../../components/ntos-executive/src/win32k_process_attach_root.rs");
    let kernel = attach
        .split("pub(crate) unsafe fn select_effective_kernel(")
        .nth(1)
        .expect("kernel resume has an attach-aware selector")
        .split("pub(crate) unsafe fn current_query_process(")
        .next()
        .unwrap();
    assert!(kernel.contains("record.state.original().owner != Some(original)")
        && kernel.contains("record.state.original().eprocess != eprocess")
        && kernel.contains("record.inflight.is_some()")
        && kernel.contains("select(record.state.current())"),
        "the retained kernel APC attach must be authenticated and restored");
}
