//! An IRQ-lane dispatch returns the instance's I/O-port capabilities to the ordinary dispatch it
//! interrupted (#430).

use syn::{visit::Visit, Item};

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn function(name: &str) -> syn::ItemFn {
    let file = syn::parse_file(SOURCE).expect("driver_launch.rs parses");
    file.items.into_iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(segment) = path.path.segments.last() {
            self.0.push(segment.ident.to_string());
        }
        syn::visit::visit_expr_path(self, path);
    }
}

fn calls(name: &str) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_item_fn(&function(name));
    calls.0
}

fn position(calls: &[String], name: &str) -> usize {
    calls.iter().position(|call| call == name).unwrap_or_else(|| panic!("no call to {name}"))
}

#[test]
fn the_outer_binding_is_captured_before_and_restored_after_every_irq_dispatch() {
    let calls = calls("dispatch_hosted_irq_connection");
    let captured = position(&calls, "current_hosted_device_dispatch_binding");
    let dispatched = position(&calls, "dispatch_hosted_irq_connection_on_lane");
    let restored = position(&calls, "restore_outer_port_caps_after_irq");
    assert!(captured < dispatched && dispatched < restored, "{calls:?}");
    // No early return can skip the restoration: the lane dispatch's outcome is returned after it.
    assert!(!function("dispatch_hosted_irq_connection")
        .block.stmts.iter().any(|stmt| has_early_exit(stmt)));
}

fn has_early_exit(stmt: &syn::Stmt) -> bool {
    #[derive(Default)]
    struct Try(bool);
    impl<'ast> Visit<'ast> for Try {
        fn visit_expr_try(&mut self, _: &'ast syn::ExprTry) { self.0 = true; }
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) { self.0 = true; }
    }
    let mut found = Try::default();
    found.visit_stmt(stmt);
    found.0
}

#[test]
fn restoration_follows_the_nested_port_cap_rule_and_never_keeps_the_irq_devices_ports() {
    let calls = calls("restore_outer_port_caps_after_irq");
    for required in ["port_caps_after_nested_dispatch", "hosted_device_resource_state_by_device_id",
                     "current_hosted_device_dispatch_binding", "copy_hosted_io_port_caps_to_instance",
                     "clear_hosted_io_port_caps"] {
        position(&calls, required);
    }
}
