//! StartIo must cross the native import boundary with real packet and device owners.

use std::collections::{HashMap, HashSet};
use syn::{visit::Visit, Expr, Item};

fn parse_native(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).expect("native StartIo adapter source"))
        .expect("parse native StartIo adapter")
}

#[derive(Default)]
struct Calls {
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*expression.func {
            if let Some(last) = path.path.segments.last() {
                self.names.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.names.push(expression.method.to_string());
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn functions(file: &syn::File) -> HashMap<String, HashSet<String>> {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) => {
                let mut calls = Calls::default();
                calls.visit_block(&function.block);
                Some((function.sig.ident.to_string(), calls.names.into_iter().collect()))
            }
            _ => None,
        })
        .collect()
}

fn reachable_calls(graph: &HashMap<String, HashSet<String>>, entry: &str) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut pending = vec![entry.to_owned()];
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if let Some(calls) = graph.get(&name) {
            pending.extend(calls.iter().cloned());
        }
    }
    seen
}

fn native_bindings() -> HashMap<String, String> {
    let file = parse_native("driver_launch.rs");
    let registry = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "register_fsd_trampolines" => Some(function),
        _ => None,
    }).expect("native import registry");

    struct Bindings(HashMap<String, String>);
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.method == "bind" && expression.args.len() == 2 {
                if let Expr::Lit(name) = &expression.args[0] {
                    if let syn::Lit::Str(name) = &name.lit {
                        let mut target = &expression.args[1];
                        while let Expr::Cast(cast) = target {
                            target = &cast.expr;
                        }
                        if let Expr::Path(path) = target {
                            if let Some(adapter) = path.path.segments.last() {
                                self.0.insert(name.value(), adapter.ident.to_string());
                            }
                        }
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, expression);
        }
    }

    let mut bindings = Bindings(HashMap::new());
    bindings.visit_block(&registry.block);
    bindings.0
}

#[test]
fn start_io_attributes_import_reaches_root_request_adapter() {
    assert_eq!(native_bindings().get("IoSetStartIoAttributes").map(String::as_str),
        Some("s_io_set_start_io_attributes"));
}

#[test]
fn start_io_attributes_are_committed_by_authenticated_root_device_service() {
    let native = functions(&parse_native("hosted_start_io.rs"));
    let component = reachable_calls(&native, "s_io_set_start_io_attributes");
    assert!(component.contains("call_on4_raw"),
        "component import must request the root device service");
    assert!(!component.contains("io_manager_mut"),
        "component import cannot use component-local I/O Manager state");
    let root = reachable_calls(&native, "service_set_attributes");
    for required in [
        "authenticated_hosted_device",
        "hosted_device_pointer_registration",
        "registration",
        "retain_hosted_device_projection_reference",
        "hosted_instance_pool_lock",
        "hosted_pool_allocation_exec_range",
        "plan",
        "kernel_extension_offset",
        "size_field",
        "set_attributes",
        "release",
    ] {
        assert!(root.contains(required), "root attribute effect must reach {required}");
    }
    let service = functions(&parse_native("driver_launch.rs"));
    let device = reachable_calls(&service, "service_hosted_device");
    assert!(device.contains("service_set_attributes"),
        "authenticated device service must route attribute requests to root policy");
}
