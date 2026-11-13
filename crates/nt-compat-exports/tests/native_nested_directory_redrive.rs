use syn::{visit::Visit, Expr, ImplItem, Item};

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/provider_directory_broker.rs");
const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");

fn calls_in(source: &str, function: &str) -> Vec<String> {
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.iter().map(|part| part.ident.to_string())
                    .collect::<Vec<_>>().join("::"));
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let file = syn::parse_file(source).expect("native source parses");
    let body = file.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == function => Some(&item.block),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {function}"));
    let mut calls = Calls(Vec::new());
    calls.visit_block(body);
    calls.0
}

fn method_calls_in(source: &str, method: &str) -> Vec<String> {
    let file = syn::parse_file(source).expect("native source parses");
    let body = file.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            ImplItem::Fn(item) if item.sig.ident == method => Some(&item.block),
            _ => None,
        }),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {method}"));
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.iter().map(|part| part.ident.to_string())
                    .collect::<Vec<_>>().join("::"));
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls(Vec::new());
    calls.visit_block(body);
    calls.0
}

#[test]
fn deferred_directory_publication_is_admitted_to_the_nested_redrive() {
    let gate = calls_in(SERVICE, "nested_hosted_file_work_ready");
    let runner = calls_in(SERVICE, "redrive_nested_hosted_file_work");
    assert!(runner.iter().any(|call| call.ends_with("provider_directory_broker::redrive_nested_ready")),
        "the nested runner must retain directory publication ownership");
    assert!(gate.iter().any(|call| call.ends_with("provider_directory_broker::nested_work_ready")),
        "a directory-only deferred PUBLISH must wake the nested runner");
    let readiness = calls_in(BROKER, "nested_work_ready");
    // nt-time's first_due tests prove the deadline boundary and the empty-owner clock gate.
    assert!(!readiness.iter().any(|call| call.ends_with("has_outstanding")),
        "uncertain or quarantined directory work must not hot-spin the pump");
}

#[test]
fn deferred_directory_publication_arms_its_own_retry_without_other_ingress() {
    let deadline = calls_in(TIMER, "next");
    assert!(deadline.iter().any(|call| call.ends_with("provider_directory_broker::next_deadline")),
        "a pending directory CQE needs a physical timer wake without another driver Call");
    let dispatch = calls_in(BROKER, "dispatch");
    assert!(dispatch.iter().any(|call| call.ends_with("rearm_registered_active_delay_timer_with_handler")),
        "deferred publication and effects must arm the timer after releasing broker ownership");
    let redrive = calls_in(BROKER, "redrive_nested_ready");
    assert!(redrive.iter().any(|call| call.ends_with("rearm_registered_active_delay_timer_with_handler")),
        "after an indeterminate CQE, the next retry must be armed before blocking receive");
}

#[test]
fn provider_ack_settles_the_exact_publish_reply_before_upload_retirement() {
    let dispatch = method_calls_in(BROKER, "dispatch");
    let redrive = calls_in(BROKER, "redrive_one");
    assert!(dispatch.iter().any(|call| call.ends_with("settle_publish_reply")),
        "same-owner op8 can arrive before the background publish reconciliation");
    assert!(redrive.iter().any(|call| call.ends_with("settle_publish_reply")),
        "background redrive and immediate ACK must share one exact retirement path");
    let settle = calls_in(BROKER, "settle_publish_reply");
    for effect in ["reconcile_retained_service_reply", "retire_stopped_acknowledged_retained_service"] {
        assert!(settle.iter().any(|call| call.ends_with(effect)),
            "publish Reply settlement must retain {effect}");
    }
}

#[test]
fn failed_publish_reply_can_be_aborted_by_its_owner_before_background_redrive() {
    // A failed PUBLISH Reply can resume win32k immediately. Its next Call is ABORT,
    // which can reach this broker before the background redrive settles the Reply.
    // Inspect the ABORT arm specifically: the ACK arm already settles its Reply.
    let file = syn::parse_file(BROKER).expect("native source parses");
    let dispatch = file.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            ImplItem::Fn(item) if item.sig.ident == "dispatch" => Some(&item.block),
            _ => None,
        }),
        _ => None,
    }).expect("Broker::dispatch exists");
    struct AckAndAbortBranches<'ast>(Option<&'ast syn::Block>);
    impl<'ast> Visit<'ast> for AckAndAbortBranches<'ast> {
        fn visit_expr_if(&mut self, expr: &'ast syn::ExprIf) {
            let ack_condition = matches!(&*expr.cond, Expr::Binary(binary)
                if matches!(&*binary.left, Expr::Path(path) if path.path.is_ident("op"))
                    && matches!(&binary.op, syn::BinOp::Eq(_))
                    && matches!(&*binary.right, Expr::Lit(lit)
                        if matches!(&lit.lit, syn::Lit::Int(value) if value.base10_parse::<u8>().is_ok_and(|n| n == 8))));
            if ack_condition {
                self.0 = expr.else_branch.as_ref().and_then(|(_, branch)| match &**branch {
                    Expr::Block(block) => Some(&block.block),
                    _ => None,
                });
            }
            syn::visit::visit_expr_if(self, expr);
        }
    }
    let mut branches = AckAndAbortBranches(None);
    branches.visit_block(dispatch);
    let abort = branches.0.expect("op 6 ABORT branch exists");
    struct AbortCalls(Vec<String>);
    impl<'ast> Visit<'ast> for AbortCalls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.iter().map(|part| part.ident.to_string())
                    .collect::<Vec<_>>().join("::"));
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut calls = AbortCalls(Vec::new());
    calls.visit_block(abort);
    assert!(calls.0.iter().any(|call| call.ends_with("settle_publish_reply")),
        "same-owner ABORT must reconcile its failed PUBLISH Reply before testing the terminal phase");
    assert_eq!(calls.0.iter().filter(|call| call.ends_with("retire_definite")).count(), 1,
        "a successful ABORT must retire the committed upload exactly once");

    // The shared settlement path must prove exact Reply acknowledgement before it
    // releases the requestor reference or transitions the pending owner to Aborted.
    let settle = calls_in(BROKER, "settle_publish_reply");
    let reconcile = settle.iter().position(|call| call.ends_with("reconcile_retained_service_reply"))
        .expect("settlement reconciles the exact Reply");
    let retire = settle.iter().position(|call| call.ends_with("retire_stopped_acknowledged_retained_service"))
        .expect("settlement retires its acknowledged Reply");
    assert!(reconcile < retire, "do not retire or reuse a PUBLISH Reply before acknowledgement");
}
