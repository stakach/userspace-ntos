//! #285: how the executive's fault arms end a user exception. Each arm hands the exception to
//! the thread through one first-chance path, and an exception that can never reach a handler
//! ends the process through the same turn a terminating syscall uses.

use syn::visit::Visit;

const SYSCALL_NT: &str = include_str!("../../../components/ntos-executive/src/executor/syscall_nt.rs");
const USER_EXCEPTION: &str =
    include_str!("../../../components/ntos-executive/src/executor/user_exception.rs");
const EXCEPTIONS: &str = include_str!("../../../components/ntos-executive/src/executor/exceptions.rs");
const VM_FAULT: &str = include_str!("../../../components/ntos-executive/src/executor/vm_fault.rs");
const EXEC_HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

/// The last path segment of every function or method called inside function `name`.
fn callees(source: &str, name: &str) -> Vec<String> {
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
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
    struct Find<'a> {
        name: &'a str,
        calls: Option<Calls>,
    }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == self.name {
                let mut calls = Calls::default();
                calls.visit_block(&item.block);
                self.calls = Some(calls);
            }
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if item.sig.ident == self.name {
                let mut calls = Calls::default();
                calls.visit_block(&item.block);
                self.calls = Some(calls);
            }
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
    let mut find = Find { name, calls: None };
    find.visit_file(&syn::parse_file(source).expect("native source must parse"));
    find.calls.unwrap_or_else(|| panic!("function {name} not found")).0
}

fn calls(source: &str, function: &str, callee: &str) -> bool {
    callees(source, function).iter().any(|name| name == callee)
}

#[test]
fn a_syscall_and_an_unwritable_exception_frame_share_one_process_termination() {
    assert!(calls(SYSCALL_NT, "syscall_nt_route", "terminate_process_turn"));
    assert!(calls(SYSCALL_NT, "syscall_nt_route", "critical_termination_turn"));
    assert!(!calls(SYSCALL_NT, "syscall_nt_route", "terminate_hosted_process_mechanisms"),
        "the syscall tail must not keep a private copy of process teardown");
    assert!(calls(USER_EXCEPTION, "terminate_for_unwritable_frame", "terminate_process_for_exception"));
    assert!(calls(USER_EXCEPTION, "terminate_for_unwritable_frame", "terminate_process_turn"));
    assert!(calls(USER_EXCEPTION, "terminate_for_unwritable_frame", "critical_termination_turn"));
    assert!(calls(USER_EXCEPTION, "deliver_to_user", "terminate_for_unwritable_frame"));
    // NtRaiseException's last chance decides termination the same way.
    assert!(calls(EXEC_HANDLER, "nt_raise_exception", "terminate_process_for_exception"));
}

#[test]
fn every_first_chance_reaches_the_debugger_before_the_thread() {
    assert!(calls(USER_EXCEPTION, "dispatch_first_chance", "dbgk_forward_exception"));
    assert!(calls(USER_EXCEPTION, "dispatch_first_chance", "deliver_to_user"));
    // Guard pages and stack overflow have no earlier debugger report in the VM fault arm.
    for outcome in ["GuardPage", "StackOverflow"] {
        let site = VM_FAULT
            .find(&format!("PageFaultOutcome::{outcome})"))
            .unwrap_or_else(|| panic!("{outcome} is delivered"));
        let call = VM_FAULT[..site].rfind("if ").expect("delivery call");
        assert!(VM_FAULT[call..site].contains("dispatch_first_chance("),
            "{outcome} must be forwarded to a debugger first");
    }
}

#[test]
fn failed_page_ins_raise_the_memory_manager_status() {
    for tag in ["private-page", "native-image", "section-fault", "image-protect"] {
        let park = VM_FAULT
            .find(&format!("b\"{tag}\""))
            .unwrap_or_else(|| panic!("{tag} park"));
        let window = &VM_FAULT[park.saturating_sub(900)..park];
        assert!(window.contains("from_access_fault_status(status)"),
            "{tag}: a failed page-in raises STATUS_IN_PAGE_ERROR (or its access status) first");
    }
}

#[test]
fn a_general_protection_fault_is_decoded_from_its_instruction() {
    assert!(calls(EXCEPTIONS, "cpu_exception", "cpu_fault"));
    let delivery = include_str!("../../../components/ntos-executive/src/user_exception_delivery.rs");
    assert!(calls(delivery, "cpu_fault", "process_memory_read_status"));
    assert!(calls(delivery, "cpu_fault", "general_protection"));
}
