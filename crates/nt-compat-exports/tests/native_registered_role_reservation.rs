//! The live foreign initial-thread path reserves role authority from a retained Section source.

use syn::{visit::Visit, Item};

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/initial_thread_creation.rs");

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn foreign_initial_thread_reserves_registered_role_before_native_effects() {
    let parsed = syn::parse_file(SOURCE).unwrap();
    let reserve = parsed.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "reserve_foreign_initial_thread_lineage" => Some(function),
        _ => None,
    }).expect("focused pre-effect reservation function");
    let mut calls = Calls::default();
    calls.visit_block(&reserve.block);
    for required in ["source_for_live_process", "registered_target_for_role", "registered_file",
        "reserve_foreign_initial_thread_role", "reserve_foreign_initial_thread_lineage"] {
        assert!(calls.0.iter().any(|call| call == required), "missing {required} in native reservation");
    }
    let body = SOURCE.find("unsafe fn reserve_foreign_initial_thread_lineage(").unwrap();
    let end = SOURCE[body..].find("\n}\n").unwrap() + body;
    let body = &SOURCE[body..end];
    assert!(body.find("source_for_live_process").unwrap()
        < body.find("registered_target_for_role").unwrap());
    assert!(body.find("registered_target_for_role").unwrap()
        < body.find("reserve_foreign_initial_thread_role").unwrap());
    assert!(body.contains("section_image: source.file()"),
        "ordinary lineage must keep the original routed Section File");
    assert!(!body.contains("get_by_leaf") && !body.contains("parent_handle_hint: Some"));
    let foreign = &SOURCE[SOURCE.find("pub(super) unsafe fn create_foreign_thread(").unwrap()..];
    assert!(foreign.find("let role_reservation = match reserve_foreign_initial_thread_lineage(self, caller, binding)").unwrap()
        < foreign.find("*slot = Some(PendingInitialThreadCreation {").unwrap(),
        "reservation must precede publication in the retained initial-thread owner");
}
