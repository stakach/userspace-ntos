use syn::{visit::Visit, Expr, ImplItem, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(file: &syn::File, name: &str) -> Vec<String> {
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
    calls.0
}

#[test]
fn inline_ack_accepts_exact_caller_completion_without_driver_free_intent() {
    for name in ["hosted_read_work.rs", "hosted_flush_work.rs", "hosted_query_information_work.rs"] {
        let functions = calls(&source(name), "acknowledge");
        assert!(functions.iter().any(|name| name == "completion_finished"),
            "inline ACK must use exact owner-specific terminal proof in {name}");
        assert!(!functions.iter().any(|name| name == "callback_requested_free"),
            "Caller completion cannot be gated by Driver IoFree intent in {name}");
    }
}

#[test]
fn inline_driver_free_uses_claim_derived_completion_owner() {
    let file = source("driver_launch.rs");
    let functions = calls(&file, "s_iof_call_driver");
    assert!(functions.iter().any(|name| name == "complete_hosted_irp_with_owner"),
        "inline completion must consume a typed successful-claim owner receipt");
    assert!(!functions.iter().any(|name| name == "s_io_free_irp"),
        "forwarding cannot free canonical caller storage after inline completion");
    let typed = calls(&file, "complete_hosted_irp_with_owner");
    assert_eq!(typed.iter().filter(|name| *name == "claim_pending_irp_completion").count(), 1,
        "storage owner must derive from one exact generation-bearing completion claim");
    assert!(typed.iter().any(|name| name == "finish_driver_local_irp"),
        "only a ticketless driver-local terminal completion may reclaim its IRP");
    assert!(typed.iter().any(|name| name == "release_pending_irp_completion_claim"),
        "canonical caller completion must release the exact pending claim");
    assert!(calls(&file, "finish_driver_local_irp").iter().any(|name| name == "s_io_free_irp"),
        "driver-local completion must still reclaim its own IRP");
    assert!(calls(&file, "complete_hosted_irp").iter().any(|name| name == "complete_hosted_irp_with_owner"),
        "legacy outcome wrapper must share the same authoritative walk");
}

#[test]
fn native_completion_claim_classifies_ticketless_and_ticketed_nodes_after_exclusive_cas() {
    let file = source("driver_launch.rs");
    let claim = calls(&file, "claim_pending_irp_completion");
    let cas = claim.iter().position(|name| name == "compare_exchange")
        .expect("completion must first claim the generation-bearing node phase");
    let classify = claim.iter().position(|name| name == "completion_source_ticket")
        .expect("native completion must classify ordinary and root-ticketed IRPs");
    assert!(cas < classify, "source identity must be captured under the exclusive node claim");
    assert!(claim.iter().any(|name| name == "pending_irp_start_io_identity"),
        "root-ticketed completion must capture the exact node/source identity");
    let release = calls(&file, "release_pending_irp_completion_claim");
    assert!(release.iter().any(|name| name == "pending_irp_start_io_identity"),
        "ticketed completion must recheck source identity before releasing its claim");
}
