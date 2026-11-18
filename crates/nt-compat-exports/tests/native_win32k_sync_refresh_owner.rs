//! A kernel-job lane that acquires a KMUTANT through a provider wait must be able to publish
//! the dispatcher header, and a refresh failure must complete the wait instead of parking.
//!
//! Boot 44229358220: win32k's thread-exit callout (kernel job, lane 43) waited for a KMUTANT.
//! The root selector made lane 43 the owner (`SuspensionCaller::Kernel`). `W32_SYNC_OP_QUERY`
//! then refused every kernel owner, `refresh_wait_header` returned false, and the lane hit
//! `park()` (win32k_subsystem.rs:6627) while it held root's running token, which stalled the
//! whole system.

use syn::visit::Visit;
use syn::{Expr, Item};

fn source(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing fn {name}"))
}

struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = call.func.as_ref() {
            self.0.push(path.path.segments.iter().map(|s| s.ident.to_string())
                .collect::<Vec<_>>().join("::"));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

/// Call paths in source order.
fn calls(block: &syn::Block) -> Vec<String> {
    let mut calls = Calls(Vec::new());
    calls.visit_block(block);
    calls.0
}

fn calls_in_expr(expr: &Expr) -> Vec<String> {
    let mut calls = Calls(Vec::new());
    calls.visit_expr(expr);
    calls.0
}

#[test]
fn root_names_a_kernel_mutant_owner_to_its_own_lane() {
    let file = syn::parse_file(&source("service_sec_image.rs")).unwrap();
    let request = function(&file, "service_win32k_provider_sync_request");
    let calls = calls(&request.block);
    assert!(calls.iter().any(|call| call.ends_with("ProviderSyncQueryOwner::select")),
        "W32_SYNC_OP_QUERY must name a kernel owner to the querying kernel lane");
}

#[test]
fn provider_resolves_a_querying_kernel_owner_to_its_current_thread() {
    let file = syn::parse_file(&source("win32k_local_sync.rs")).unwrap();
    let refresh = function(&file, "refresh_header");
    let calls = calls(&refresh.block);
    assert!(calls.iter().any(|call| call.ends_with("ProviderSyncQueryOwner::from_words")));
    assert!(calls.iter().any(|call| call == "current_ethread"),
        "a kernel lane's mutant is owned by the thread the lane executes as");
}

#[test]
fn a_failed_wait_header_refresh_completes_the_wait_instead_of_parking() {
    let file = syn::parse_file(&source("win32k_subsystem.rs")).unwrap();
    let wait = file.items.iter().filter_map(|item| match item {
        Item::Fn(function) => Some(function),
        _ => None,
    }).find(|function| calls(&function.block).iter()
        .any(|call| call.ends_with("refresh_wait_header")))
        .expect("provider wait resume refreshes sync headers");
    struct RefreshArms { parks_after_refresh: bool }
    impl<'ast> Visit<'ast> for RefreshArms {
        fn visit_expr_if(&mut self, expr: &'ast syn::ExprIf) {
            let condition = calls_in_expr(&expr.cond);
            if condition.iter().any(|call| call.ends_with("refresh_wait_header"))
                && calls(&expr.then_branch).iter().any(|call| call == "park")
            {
                self.parks_after_refresh = true;
            }
            syn::visit::visit_expr_if(self, expr);
        }
    }
    let mut arms = RefreshArms { parks_after_refresh: false };
    arms.visit_block(&wait.block);
    assert!(!arms.parks_after_refresh,
        "a refresh failure must become the wait's error completion, never park the lane");
}
