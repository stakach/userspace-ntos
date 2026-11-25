//! A nested START/CREATE stall needs receipts from the owners before a reentrant call.
//! Inspecting root-owned vectors from the enclosed pump would itself be unsafe.

const INGRESS: &str = include_str!("../../../components/ntos-executive/src/component_ingress_services.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const CREATE: &str = include_str!("../../../components/ntos-executive/src/hosted_io_create_file_work.rs");
const FILE: &str = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
const START: &str = include_str!("../../../components/ntos-executive/src/hosted_start_fdo_work.rs");

#[test]
fn enclosed_wait_observes_only_copied_identity_and_owners_report_park_and_wake() {
    let enclosed = PUMP.split_once("unsafe fn trace_enclosed_dispatch_wait(").unwrap().1
        .split_once("static PARKED_DISPATCH_YIELDS").unwrap().0;
    assert!(enclosed.contains("trace_enclosed_receive_candidates(n)"));
    assert!(!enclosed.contains("HOSTED_DRIVER_WAITERS"));
    assert!(!enclosed.contains("hosted_file_owners::"));
    assert!(!enclosed.contains("hosted_start_fdo_work::"));

    let park = INGRESS.split_once("unsafe fn park(").unwrap().1
        .split_once("pub(crate) unsafe fn wake_service(").unwrap().0;
    assert!(park.contains("trace_nested_pnp_service_wait(b\"parked\""));
    let wake = INGRESS.split_once("unsafe fn wake_service_inner(").unwrap().1
        .split_once("pub(crate) unsafe fn resume_acknowledged_retained_services(").unwrap().0;
    assert!(wake.contains("trace_nested_pnp_service_wait(b\"reply-entered\""));
    assert!(wake.contains("trace_nested_pnp_service_wait(b\"acknowledged\""));
    assert!(INGRESS.contains("wait.dispatch.lane().generation"));
    assert!(INGRESS.contains("wait.reply") && INGRESS.contains("wait.token"));
}

#[test]
fn create_and_start_emit_exact_preentry_receipts_before_nested_provider_calls() {
    let create = CREATE.split_once("unsafe fn dispatch_create(").unwrap().1
        .split_once("unsafe fn observe_terminal(").unwrap().0;
    let receipt = create.find("trace_nested_pnp_create_stage(self, b\"provider-pre-entry\"").unwrap();
    let entry = create.find("dispatch_hosted_file_create_irp_result_exact(").unwrap();
    assert!(receipt < entry);
    assert!(CREATE.contains("work.dispatch.lane().generation"));
    assert!(CREATE.contains("work.route.badge()") && CREATE.contains("work.reply")
        && CREATE.contains("work.token"));

    let start = START.split_once("unsafe fn dispatch_prepared(").unwrap().1
        .split_once("unsafe fn poll_provider(").unwrap().0;
    let receipt = start.find("trace_start_fdo(self, b\"provider-pre-entry\"").unwrap();
    let entry = start.find("invocation.invoke(").unwrap();
    assert!(receipt < entry);
    assert!(START.contains("work.source_instance.hosted_domain_cookie"));
    assert!(START.contains("work.dispatch.lane().generation"));
    assert!(START.contains("trace_start_fdo(self, b\"provider-returned\""));
}

#[test]
fn nested_file_owner_receipts_recheck_live_authority_and_canonical_irp() {
    let trace = FILE.split_once("fn trace_nested_pnp_create_owner(").unwrap().1
        .split_once("/// What a dispatch does when no hosted lane").unwrap().0;
    assert!(trace.contains("owner.irp_id != Some(irp)"));
    assert!(trace.contains("authority.live()"));
    assert!(trace.contains("owner.flight") && trace.contains("owner.payload"));
    assert!(trace.contains("owner.admission_epoch") && trace.contains("owner.retry_after"));
    assert!(trace.contains("owner.plain_pump") && trace.contains("owner.terminal_receipt"));
}
