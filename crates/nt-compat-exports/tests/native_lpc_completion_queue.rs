//! Native queue and writeback integration contracts; runtime behavior is validated separately.
use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn method(file: &syn::File, name: &str) -> syn::ImplItemFn {
    file.items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            implementation.items.iter().find_map(|item| {
                let syn::ImplItem::Fn(function) = item else {
                    return None;
                };
                function.sig.ident.eq(name).then(|| function.clone())
            })
        })
        .unwrap_or_else(|| panic!("missing actual native method {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn refused_terminal_payload_stays_queued_without_publication_replay() {
    let service = source("service_sec_image.rs");
    let function = service
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Fn(function) = item else {
                return None;
            };
            (function.sig.ident == "lpc_connect_wait_complete").then_some(function)
        })
        .unwrap();
    let guard = function
        .block
        .stmts
        .iter()
        .find_map(|statement| {
            let syn::Stmt::Expr(syn::Expr::If(guard), _) = statement else {
                return None;
            };
            let syn::Expr::Field(field) = &*guard.cond else {
                return None;
            };
            matches!(&field.member, syn::Member::Named(name) if name == "retained_refusal")
                .then_some(guard)
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&guard.then_branch);
    assert!(calls
        .0
        .iter()
        .any(|name| name == "queue_lpc_connect_completion"));
    assert!(!calls.0.iter().any(|name| name == "begin_completion"
        || name == "lpc_publish_connect_completion"
        || name == "reply_parked_syscall"));
}

#[test]
fn endpoint_mapping_retirement_writes_back_before_native_unmap() {
    let mut calls = Calls::default();
    calls.visit_block(
        &method(
            &source("lpc_connection_views.rs"),
            "retire_lpc_process_views",
        )
        .block,
    );
    assert!(
        calls
            .0
            .iter()
            .position(|name| name == "service_generic_section_writeback_view")
            .unwrap()
            < calls
                .0
                .iter()
                .position(|name| name == "rollback_generic_section_view")
                .unwrap()
    );
}

#[test]
fn no_view_completed_connections_admit_canonical_owner_before_cache_publication() {
    let mut calls = Calls::default();
    calls.visit_block(&method(&source("exec_handler.rs"), "cache_lpc_connection_for_pi").block);
    assert!(
        calls
            .0
            .iter()
            .position(|name| name == "query_handle")
            .unwrap()
            < calls
                .0
                .iter()
                .position(|name| name == "admit_completed_lpc_connection_owner")
                .unwrap()
    );
    assert!(
        calls
            .0
            .iter()
            .position(|name| name == "admit_completed_lpc_connection_owner")
            .unwrap()
            < calls.0.iter().position(|name| name == "push").unwrap()
    );
}
