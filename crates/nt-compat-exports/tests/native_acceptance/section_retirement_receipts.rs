use std::path::PathBuf;
use syn::visit::{self, Visit};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function.clone()),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct Fields(Vec<String>);
impl<'ast> Visit<'ast> for Fields {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.0.push(name.to_string());
        }
        visit::visit_expr_field(self, field);
    }
}

fn calls(function: &syn::ItemFn) -> Vec<String> {
    let mut visitor = Calls::default();
    visitor.visit_item_fn(function);
    visitor.0
}

fn before(calls: &[String], first: &str, second: &str) {
    let left = calls.iter().position(|call| call == first).unwrap_or_else(|| panic!("missing {first}"));
    let right = calls.iter().position(|call| call == second).unwrap_or_else(|| panic!("missing {second}"));
    assert!(left < right, "{first} must precede {second}: {calls:?}");
}

#[test]
fn direct_and_redriven_unmap_receipts_follow_exact_retirement_before_row_removal() {
    let file = source("provider_mm_section_objects.rs");
    for name in ["unmap", "redrive"] {
        let calls = calls(&function(&file, name));
        before(&calls, "capture_retirement", "retire_mapping");
        before(&calls, "retire_mapping", "unmap_retired");
        before(&calls, "unmap_retired", "swap_remove");
    }
    let retirement = calls(&function(&file, "retire_mapping"));
    before(&retirement, "page_unmap_r", "unmap_provider_view_exact");
}

#[test]
fn scalar_receipt_capture_filters_unpublished_maps_and_keeps_exact_generations() {
    let file = source("provider_mm_section_objects.rs");
    let capture = function(&file, "capture_retirement");
    let mut fields = Fields::default();
    fields.visit_item_fn(&capture);
    for field in ["published", "allocation_generation", "generation", "physical", "references", "base"] {
        assert!(fields.0.iter().any(|name| name == field), "capture omits {field}");
    }
    let capture_calls = calls(&capture);
    assert!(!capture_calls.iter().any(|call| call == "unwrap" || call == "expect"),
        "an unavailable observation must not change admission/retirement");
}

#[test]
fn cleanup_observer_follows_physical_auth_and_actual_operation_result_without_new_authority() {
    let file = source("provider_section_cleanup.rs");
    let calls = calls(&function(&file, "service_win32k_section_cleanup_request"));
    before(&calls, "authenticate", "observe_cleanup_result");
    before(&calls, "physical_win32k_provider", "observe_cleanup_result");
    before(&calls, "dereference", "observe_cleanup_result");
    before(&calls, "unmap", "observe_cleanup_result");
    for forbidden in ["capture_native_handle_caller", "registry_caller", "authenticate_win32k_service_request"] {
        assert!(!calls.iter().any(|call| call == forbidden), "cleanup observation must not acquire {forbidden}");
    }
}
