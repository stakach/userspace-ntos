use syn::{visit::Visit, Expr, Item};

#[test]
fn process_terminal_receipt_requires_a_new_canonical_termination() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    #[derive(Default)]
    struct Audit { under_transition: bool, under_unstarted: bool, receipt: usize,
        ordinary_receipt: usize, unstarted_receipt: usize, guarded: bool,
        captured: bool, terminated_after_capture: bool,
        unstarted_eligible: bool, unstarted_terminated: bool, unstarted_guarded: bool }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
            let previous = self.under_unstarted;
            self.under_unstarted = method.sig.ident == "try_terminate_unstarted_process";
            syn::visit::visit_impl_item_fn(self, method);
            self.under_unstarted = previous;
        }
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "was_terminated") {
                self.captured = local.init.as_ref().is_some_and(|init|
                    matches!(&*init.expr, Expr::MethodCall(call)
                        if call.method == "is_process_signaled"
                        && call.args.len() == 1
                        && matches!(&call.args[0], Expr::Path(path) if path.path.is_ident("pid"))));
            }
            syn::visit::visit_local(self, local);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "terminate_process_at" {
                if self.under_unstarted {
                    self.unstarted_terminated = true;
                } else {
                    self.terminated_after_capture |= self.captured;
                }
            }
            if self.under_unstarted && call.method == "unstarted_process_abandonment_pending" {
                self.unstarted_eligible = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            self.visit_expr(&branch.cond);
            let previous = self.under_transition;
            self.under_transition |= matches!(&*branch.cond,
                Expr::Unary(value) if matches!(value.op, syn::UnOp::Not(_))
                && matches!(&*value.expr, Expr::Path(path) if path.path.is_ident("was_terminated")));
            self.visit_block(&branch.then_branch);
            self.under_transition = previous;
            if let Some((_, alternate)) = &branch.else_branch { self.visit_expr(alternate); }
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "note_native_process_terminal") {
                self.receipt += 1;
                if self.under_unstarted {
                    self.unstarted_receipt += 1;
                    self.unstarted_guarded &= self.unstarted_eligible && self.unstarted_terminated;
                } else {
                    self.ordinary_receipt += 1;
                    self.guarded &= self.under_transition;
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut audit = Audit { guarded: true, unstarted_guarded: true, ..Audit::default() };
    for item in &file.items {
        if let Item::Impl(value) = item { audit.visit_item_impl(value); }
    }
    assert_eq!(audit.receipt, 2);
    assert_eq!(audit.ordinary_receipt, 1);
    assert_eq!(audit.unstarted_receipt, 1);
    assert!(audit.captured && audit.terminated_after_capture,
        "capture canonical signaled/Terminated state before invoking idempotent termination");
    assert!(audit.guarded, "idempotent NtTerminateProcess must not emit another committed transition receipt");
    assert!(audit.unstarted_guarded,
        "unstarted retirement must prove abandonment and canonical termination before its receipt");
}
