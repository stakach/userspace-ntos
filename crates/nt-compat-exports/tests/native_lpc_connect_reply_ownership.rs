//! Reply acknowledgement, not attempted delivery, retires a parked LPC connector.
use syn::visit::Visit;

fn named_function(name: &str) -> syn::ItemFn {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/service_sec_image.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    file.items
        .into_iter()
        .find_map(|item| {
            let syn::Item::Fn(function) = item else {
                return None;
            };
            function.sig.ident.eq(name).then_some(function)
        })
        .unwrap()
}

fn completion() -> syn::ItemFn {
    named_function("lpc_connect_wait_complete")
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
fn connect_wait_owner_is_not_withdrawn_before_native_reply_effect() {
    let mut calls = Calls::default();
    calls.visit_block(&completion().block);
    let reply = calls
        .0
        .iter()
        .position(|name| name == "reply_parked_syscall")
        .unwrap();
    let withdraw = calls
        .0
        .iter()
        .position(|name| name == "take" || name == "finish_reply")
        .unwrap();
    assert!(reply < withdraw,
        "taking the canonical connector before reply ACK loses its exact Reply owner on uncertainty");
}

#[derive(Default)]
struct AckBranch {
    recycles_reply: bool,
    publishes_ready: bool,
}
impl<'ast> Visit<'ast> for AckBranch {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        if matches!(&*expression.cond, syn::Expr::Path(path) if path.path.is_ident("replied")) {
            let mut calls = Calls::default();
            calls.visit_block(&expression.then_branch);
            self.recycles_reply |= calls.0.iter().any(|name| name == "release_reply_pool_cap");
            self.publishes_ready |= calls
                .0
                .iter()
                .any(|name| name == "thread_wait_state_clear_badge_ready");
        }
        syn::visit::visit_expr_if(self, expression);
    }
}

#[test]
fn connect_reply_recycle_and_ready_publication_require_actual_ack() {
    let mut ack = AckBranch::default();
    ack.visit_block(&completion().block);
    assert!(
        ack.recycles_reply && ack.publishes_ready,
        "uncertain Reply delivery must retain both the capability and parked-thread ownership"
    );
}

#[test]
fn connect_cancellation_keeps_canonical_owner_until_transport_ack() {
    let mut calls = Calls::default();
    calls.visit_block(&named_function("lpc_connect_wait_abandon_thread").block);
    let cancel = calls
        .0
        .iter()
        .position(|name| name == "cancel_parked_reply_transport")
        .unwrap();
    let withdraw = calls
        .0
        .iter()
        .position(|name| name == "take" || name == "finish_cancel")
        .unwrap();
    assert!(
        cancel < withdraw,
        "uncertain cancellation cannot discard the original connector/Reply owner"
    );
}
