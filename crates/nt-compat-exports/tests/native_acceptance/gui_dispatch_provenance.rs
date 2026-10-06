use std::path::PathBuf;
use syn::visit::{self, Visit};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(item.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing actual function {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        visit::visit_expr_method_call(self, call);
    }
}

fn calls(function: &syn::ItemFn) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_item_fn(function);
    calls.0
}

#[derive(Default)]
struct Names(Vec<String>);
impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0.push(ident.to_string());
    }
}

#[test]
fn gui_dispatch_provenance_originates_after_the_actual_ssdt_handler_return() {
    let dispatch = function(&source("win32k_subsystem.rs"), "dispatch_ssn");
    let names = calls(&dispatch);
    let invoke = names
        .iter()
        .position(|name| name == "call")
        .expect("existing actual SSDT invocation");
    let receipt = names
        .iter()
        .position(|name| name == "record_win32k_handler_return")
        .expect("transport completion alone currently credits context refusal as GUI success");
    assert!(
        invoke < receipt,
        "handler receipt is not dispatch or context-admission intent"
    );
    struct ReceiptArguments(bool);
    impl<'ast> Visit<'ast> for ReceiptArguments {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "record_win32k_handler_return")
            {
                let mut names = Names::default();
                for argument in &call.args {
                    names.visit_expr(argument);
                }
                for required in ["dispatch_id", "ssn", "ret"] {
                    assert!(
                        names.0.iter().any(|name| name == required),
                        "actual handler receipt must retain original {required}"
                    );
                }
                self.0 = true;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut receipt = ReceiptArguments(false);
    receipt.visit_item_fn(&dispatch);
    assert!(receipt.0);
}

#[test]
fn gui_dispatch_provenance_is_copied_and_correlated_before_shared_bank_reuse() {
    let glue = source("win32k_glue.rs");
    let wrapper = function(&glue, "win32k_dispatch_wide_with_completion_args_and_kind");
    assert!(calls(&wrapper)
        .iter()
        .any(|name| name == "win32k_dispatch_wide_observed"));
    let observed = function(&glue, "win32k_dispatch_wide_observed");
    assert!(calls(&observed)
        .iter()
        .any(|name| name == "win32k_dispatch_wide_observed_inner"));
    let dispatch = function(&glue, "win32k_dispatch_wide_observed_inner");
    let calls = calls(&dispatch);
    let read = calls
        .iter()
        .position(|name| name == "capture_win32k_dispatch_return")
        .expect("root needs an immutable return receipt, not raw RAX plus completed");
    let retire = calls
        .iter()
        .position(|name| name == "finish_win32k_lane_return")
        .expect("existing exact physical completion retirement");
    assert!(
        read < retire,
        "capture response before making the lane/shared bank reusable"
    );
    struct Captured(bool);
    impl<'ast> Visit<'ast> for Captured {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "capture_win32k_dispatch_return")
            {
                let mut names = Names::default();
                for argument in &call.args {
                    names.visit_expr(argument);
                }
                for required in ["dispatch_id", "ssn", "pr", "completed"] {
                    assert!(
                        names.0.iter().any(|name| name == required),
                        "capture must correlate actual {required}"
                    );
                }
                self.0 = true;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut capture = Captured(false);
    capture.visit_item_fn(&dispatch);
    assert!(capture.0);
    let completion = glue
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "CompletedWin32kDispatch" => Some(item),
            _ => None,
        })
        .unwrap();
    assert!(completion.fields.iter().any(|field| field.ident.as_ref().is_some_and(|name| name == "dispatch_return")),
        "resumed callback completion must retain the exact typed return rather than reread shared bytes");
}

#[test]
fn gui_dispatch_provenance_not_transport_status_controls_both_observer_routes() {
    let service = source("service_sec_image.rs");
    let observe = function(&service, "observe_completed_desktop_dispatch");
    assert!(
        calls(&observe).iter().any(|name| name == "handler_value"),
        "Refused C000009A with completed transport must never become a GUI fact"
    );
    struct ObserverInputs(usize);
    impl<'ast> Visit<'ast> for ObserverInputs {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "observe_completed_desktop_dispatch")
            {
                let mut names = Names::default();
                for argument in &call.args {
                    names.visit_expr(argument);
                }
                assert!(
                    names.0.iter().any(|name| name == "dispatch_return"),
                    "observer input must retain typed provider provenance"
                );
                self.0 += 1;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut inline = ObserverInputs(0);
    inline.visit_item_fn(&function(&service, "service_sec_image"));
    assert_eq!(inline.0, 1);
    let mut resumed = ObserverInputs(0);
    resumed.visit_item_fn(&function(
        &service,
        "process_completed_user_callback_outer_dispatch",
    ));
    assert_eq!(resumed.0, 1);
}
