//! #419 item 5: a Source IOCTL parent yields the win32k shared page to its nested child.
//!
//! The provider-wait resume restores the parent's page (the authority marks it Active) and then
//! parks the parent for its Source IOCTL child without running a pump, so no pump settlement
//! parks the page. Unless the parent parks it explicitly, the child's root-ingress reservation is
//! refused as busy while the parent waits for that child. The later restoration must take the
//! page back (reacquire) before writing it and acknowledge exactly what it wrote.

use syn::{visit::Visit, Item};

const SOURCE_IOCTL: &str =
    include_str!("../../../components/ntos-executive/src/component_ingress_nested_source_ioctl.rs");
const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");

fn function(source: &str, name: &str) -> syn::ItemFn {
    syn::parse_file(source).unwrap().items.into_iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("{name} not found"))
}

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

fn calls(source: &str, name: &str) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_item_fn(&function(source, name));
    calls.0
}

fn position(calls: &[String], name: &str) -> usize {
    calls.iter().position(|call| call == name).unwrap_or_else(|| panic!("no call to {name}"))
}

#[test]
fn a_resume_deferred_behind_its_source_ioctl_child_parks_its_page_once() {
    let resume = calls(GLUE, "resume_suspended_provider_wait_component");
    let select = position(&resume, "park_resuming_source_ioctl");
    let park = position(&resume, "park_deferred_source_ioctl_page");
    assert!(select < park, "the parent parks the page it restored before deferring");
    assert!(park < position(&resume, "restore_settled_source_ioctl_parent"),
        "the page is parked before a settled child restores the parent");
    assert_eq!(resume.iter().filter(|call| *call == "park_deferred_source_ioctl_page").count(), 1,
        "one park for every deferred outcome; a second would be a double park");
}

#[test]
fn the_settled_parent_reacquires_before_rewriting_its_page() {
    let restore = calls(SOURCE_IOCTL, "restore_settled_source_ioctl_parent");
    let reacquire = position(&restore, "audit_reacquire");
    let write = position(&restore, "restore_shared_resume_snapshot_effect");
    assert!(reacquire < write, "no write before the page is taken back");
    assert!(restore.iter().skip(write).any(|call| call == "audit_restored"),
        "the restoration acknowledges exactly what it wrote");
}
