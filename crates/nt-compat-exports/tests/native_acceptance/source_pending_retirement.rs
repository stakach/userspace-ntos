use syn::{visit::Visit, Expr, ImplItem, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>, Vec<(String, Vec<Expr>)>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        self.1.push((call.method.to_string(), call.args.iter().cloned().collect()));
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn inspected_calls(file: &syn::File, name: &str) -> Calls {
    let mut calls = Calls::default();
    for item in &file.items {
        match item {
            Item::Fn(function) if function.sig.ident == name => calls.visit_block(&function.block),
            Item::Impl(implementation) => {
                for item in &implementation.items {
                    if let ImplItem::Fn(function) = item {
                        if function.sig.ident == name { calls.visit_block(&function.block); }
                    }
                }
            }
            _ => {}
        }
    }
    calls
}

fn calls(file: &syn::File, name: &str) -> Vec<String> {
    inspected_calls(file, name).0
}

fn expression(expr: &Expr) -> &Expr {
    match expr {
        Expr::Paren(paren) => expression(&paren.expr),
        _ => expr,
    }
}

#[test]
fn pending_source_release_retires_driver_allocation_under_both_locks() {
    let functions = calls(&source("hosted_source_irp_ledger.rs"), "release_pending_terminal");
    for required in ["lock", "hosted_instance_pool_lock", "begin_deferred_driver_retirement",
        "hosted_instance_pool_free_unlocked", "retire"] {
        assert!(functions.iter().any(|name| name == required),
            "pending terminal release must retain exact allocation retirement, missing {required}");
    }
    let position = |name: &str| functions.iter().position(|call| call == name).unwrap();
    assert!(position("hosted_instance_pool_lock") < position("begin_deferred_driver_retirement"));
    assert!(position("begin_deferred_driver_retirement") < position("hosted_instance_pool_free_unlocked"));
    assert!(position("hosted_instance_pool_free_unlocked") < position("retire"));
}

#[test]
fn caller_completion_proof_is_exact_canonical_node_not_driver_free_request() {
    let ledger = source("hosted_source_irp_ledger.rs");
    let wrapper = calls(&ledger, "caller_terminal_ready");
    assert!(wrapper.iter().any(|name| name == "caller_terminal_ready_unlocked"));
    let functions = calls(&ledger, "caller_terminal_ready_unlocked");
    assert!(functions.iter().any(|name| name == "projected_node"),
        "caller terminal proof must validate retained node generation and canonical identity");
    assert!(functions.iter().any(|name| name == "completed"),
        "caller terminal proof must observe the published completion record");
    assert!(!functions.iter().any(|name| name == "deferred_free_requested"));
    for file in ["hosted_read_capture.rs", "hosted_flush_capture.rs", "hosted_query_information_capture.rs"] {
        let functions = calls(&source(file), "completion_finished");
        assert!(functions.iter().any(|name| name == "caller_terminal_ready"),
            "{file} must distinguish authentic Caller completion from driver free intent");
    }
}

#[test]
fn pending_only_work_release_uses_exact_terminal_finalizer() {
    for (capture, work) in [
        ("hosted_read_capture.rs", "hosted_read_work.rs"),
        ("hosted_flush_capture.rs", "hosted_flush_work.rs"),
        ("hosted_query_information_capture.rs", "hosted_query_information_work.rs"),
    ] {
        let functions = calls(&source(capture), "release_pending_terminal");
        assert!(functions.iter().any(|name| name == "release_owned"));
        let owned = calls(&source(capture), "release_owned");
        assert!(owned.iter().any(|name| name == "release_pending_terminal"),
            "{capture} cannot replace pending allocation retirement with bare unpin");
        let work_source = source(work);
        let functions = inspected_calls(&work_source, "retire_after_terminal");
        let argument = &functions.1.iter().find(|(name, _)| name == "release_source")
            .unwrap_or_else(|| panic!("{work}: terminal retirement must release its exact source")).1[0];
        let Expr::Binary(guard) = expression(argument) else { panic!("{work}: guarded finalizer"); };
        assert!(matches!(guard.op, syn::BinOp::And(_)));
        assert!(matches!(expression(&guard.right), Expr::Unary(not)
            if matches!(not.op, syn::UnOp::Not(_))
                && matches!(expression(&not.expr), Expr::Path(path) if path.path.is_ident("stopped"))));
        let Expr::Binary(ownership) = expression(&guard.left) else { panic!("{work}: pending or held ownership"); };
        assert!(matches!(ownership.op, syn::BinOp::Or(_)));
        for (call, name) in [(&ownership.left, "pending"), (&ownership.right, "inline_held")] {
            assert!(matches!(expression(call), Expr::MethodCall(method)
                if method.method == name && method.args.is_empty()), "{work}: {name}");
        }
        let finalizer = calls(&work_source, "release_source");
        assert!(finalizer.iter().any(|name| name == "release_pending_terminal")
            && finalizer.iter().any(|name| name == "release"),
            "{work} must keep pending final retirement separate from ordinary unpin");
        assert!(calls(&source(capture), "release").iter().any(|name| name == "release_owned")
            && owned.iter().any(|name| name == "unpin"),
            "ordinary inline producer cleanup must remain separate");
    }
}
