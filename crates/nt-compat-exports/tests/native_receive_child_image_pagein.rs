//! Issue322: a Receive child's routed image fault must never turn a provider Pending READ into
//! an executive panic. The owned page-in row retains the child Reply, the selected Receive row
//! retains the held parent, and the root admits only notifications until the exact settlement.

use syn::{visit::Visit, Item};

const ADMISSION: &str =
    include_str!("../../../components/ntos-executive/src/executor/admission.rs");
const MAINTENANCE: &str =
    include_str!("../../../components/ntos-executive/src/executor/maintenance.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/executor/receive.rs");
const INGRESS: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");
const SERVICE_LOOP: &str =
    include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const PAGEIN: &str =
    include_str!("../../../components/ntos-executive/src/native_image_pagein_work.rs");
const RECEIVE_PAGEIN: &str =
    include_str!("../../../components/ntos-executive/src/receive_child_pagein.rs");

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            if let Some(last) = path.path.segments.last() {
                self.0.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn function<'a>(source: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("native boundary must exist: {name}"))
}

fn calls(function: &syn::ItemFn) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls.0
}

fn position(calls: &[String], name: &str) -> usize {
    calls.iter().position(|call| call == name)
        .unwrap_or_else(|| panic!("boundary must invoke {name}"))
}

fn after<'a>(source: &'a str, marker: &str) -> &'a str {
    source.split(marker).nth(1).unwrap_or_else(|| panic!("missing marker {marker}"))
}

#[test]
fn receive_child_fault_outcome_is_retained_never_expected() {
    let child = after(ADMISSION, "receive_child_observation(");
    let child = child.split("lp.exit.iters += 1;").next().unwrap();
    assert!(!child.contains(".expect(\"changed or uncertain Receive fault"),
        "a changed or uncertain Receive fault must retain its child Call and parent, not panic");
    assert!(child.contains("ReceiveChildFaultOutcome::PageInOwned"),
        "an owned page-in keeps the child Reply out of the inline reply_receive");
    assert!(child.contains("b\"receive-child-fault-retained\""),
        "a refused fault stops the root with the child and parent still retained");
    let owned = after(child, "ReceiveChildFaultOutcome::PageInOwned");
    let owned = owned.split("Err(status)").next().unwrap();
    assert!(!owned.contains("reply_receive"), "the page-in row alone sends the child Reply");
}

#[test]
fn receive_child_native_image_admits_owned_pagein_before_direct_residency() {
    let root = syn::parse_file(SERVICE_LOOP).unwrap();
    let service = calls(function(&root, "service_receive_child_fault"));
    assert!(position(&service, "submit_receive_child")
        < position(&service, "service_native_image_page_residency"),
        "an unready routed source is owned before any Direct-mode provider READ");

    let pagein = syn::parse_file(PAGEIN).unwrap();
    let submit = calls(function(&pagein, "submit_receive_child"));
    assert!(position(&submit, "admit") < position(&submit, "install_work"),
        "the pure turn is bound before the child Reply is parked");
    assert!(PAGEIN.contains("ReceiveChild"), "the receive child has its own page-in purpose");
}

#[test]
fn receive_child_pagein_replies_once_after_map_and_retains_failure() {
    let pagein = syn::parse_file(PAGEIN).unwrap();
    let advance = calls(function(&pagein, "advance"));
    assert!(position(&advance, "page_mapped") < position(&advance, "enter_reply"));
    let arm = after(after(PAGEIN, "Phase::ReplyReady => {"), "Purpose::ReceiveChild => {");
    let arm = arm.split("Purpose::SyscallCopy(_) => {").next().unwrap();
    assert!(arm.find("enter_reply").unwrap() < arm.find("client_reply_on").unwrap(),
        "the child Reply is entered in the turn before the one send");
    call_once(&advance, "acknowledge");
    let cancel = after(PAGEIN, "Phase::Cancel => {");
    let cancel = cancel.split("Phase::Cancelled =>").next().unwrap();
    let receive_arm = cancel.find("ReceiveChild").expect("receive child failure arm");
    let stop = cancel.find("stop_and_cancel_hosted").expect("ordinary fault cancellation");
    assert!(receive_arm < stop,
        "a held Receive parent has no cancellation settlement; the child Reply is retained");
    assert!(cancel.contains(".retain("), "the turn records the retained failure");
}

fn call_once(calls: &[String], name: &str) {
    assert_eq!(calls.iter().filter(|call| call.as_str() == name).count(), 1,
        "{name} must be a single transition");
}

#[test]
fn root_admits_only_notifications_while_the_child_reply_is_owned() {
    let receive = after(INGRESS, "pub(crate) unsafe fn receive(reply_cptr: u64)");
    let receive = receive.split("pub(crate) unsafe fn reply_receive(").next().unwrap();
    assert!(receive.contains("owns_receive_child()"),
        "a page-in-owned child may block for notifications instead of asserting");
    let autonomous = receive.find("service_autonomous").unwrap();
    let gate = receive[..autonomous].rsplit("exact settlement").next().unwrap();
    assert!(gate.contains("if !runtime::receive_child_pending()"),
        "autonomous provider work cannot run while the Receive parent is held");

    let maintenance = after(MAINTENANCE, "// This delivery still owns its Reply and captured message.");
    let action = maintenance.find("receive_child_root_action").expect("root action");
    let service = maintenance.find("receive_child_pagein::service_notification")
        .expect("restricted notification service");
    let ordinary = maintenance.find("admit_hosted_thread_ingress").expect("selected child");
    assert!(action < service && service < ordinary);

    for wrapper in ["pub(super) unsafe fn receive(", "pub(super) unsafe fn reply_receive("] {
        let body = after(RECEIVE, wrapper);
        let prepare = body.find("receive_child_pagein::prepare_receive()").expect("timer shot");
        let ordinary = body.find("prepare_service_receive").unwrap();
        assert!(prepare < ordinary, "{wrapper} arms only the exact page-in shot");
    }
}

#[test]
fn restricted_notification_runs_only_storage_completion_and_the_exact_row() {
    let source = syn::parse_file(RECEIVE_PAGEIN).unwrap();
    let service = calls(function(&source, "service_notification"));
    for required in ["latch_hosted_irq_badge", "drain_pending_hosted_irqs",
        "drain_hosted_driver_dpcs", "service_mounted_native_blocks",
        "service_pending_file_backends", "redrive_receive_child"] {
        position(&service, required);
    }
    for forbidden in ["run_outer", "drain_hosted_ready", "service_autonomous", "redrive",
        "delay_timer_interrupt", "pending_file_io_redrive_all", "take_hosted_with"] {
        assert!(!service.iter().any(|call| call == forbidden),
            "restricted receive-child turn may not run {forbidden}");
    }
    let prepare = calls(function(&source, "prepare_receive"));
    position(&prepare, "delay_timer_program");
}
