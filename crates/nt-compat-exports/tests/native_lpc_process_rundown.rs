//! Broker rundown is acknowledged on the exact process-deletion owner, not repeated per event.
use syn::visit::Visit;

fn deletion_method() -> syn::ImplItemFn {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_handler.rs"
    ))
    .unwrap();
    file.items
        .into_iter()
        .find_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            implementation.items.into_iter().find_map(|item| {
                let syn::ImplItem::Fn(function) = item else {
                    return None;
                };
                (function.sig.ident == "try_delete_hosted_process_object_exact").then_some(function)
            })
        })
        .expect("actual native process-deletion method")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct UnacknowledgedGuard(bool);
impl<'ast> Visit<'ast> for UnacknowledgedGuard {
    fn visit_expr_unary(&mut self, expression: &'ast syn::ExprUnary) {
        if matches!(expression.op, syn::UnOp::Not(_)) {
            if let syn::Expr::Field(field) = &*expression.expr {
                if matches!(&field.member, syn::Member::Named(name) if name == "lpc_rundown_acknowledged")
                    && matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("candidate"))
                {
                    self.0 = true;
                }
            }
        }
        syn::visit::visit_expr_unary(self, expression);
    }
}

#[test]
fn repeated_deletion_passes_skip_acknowledged_broker_rundown() {
    #[derive(Default)]
    struct GuardedRundown(bool);
    impl<'ast> Visit<'ast> for GuardedRundown {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let mut guard = UnacknowledgedGuard::default();
            guard.visit_expr(&expression.cond);
            let mut calls = Calls::default();
            calls.visit_block(&expression.then_branch);
            if guard.0
                && calls
                    .0
                    .iter()
                    .any(|call| call == "retire_lpc_process_handles")
            {
                self.0 = true;
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut guarded = GuardedRundown::default();
    guarded.visit_block(&deletion_method().block);
    assert!(guarded.0,
        "a signaled process awaiting unrelated references must not repeat acknowledged LPC broker IPC on every event");
}

#[test]
fn broker_success_updates_the_exact_retained_deletion_candidate() {
    #[derive(Default)]
    struct Recorded(bool);
    impl<'ast> Visit<'ast> for Recorded {
        fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
            if matches!(&*expression.left, syn::Expr::Path(path) if path.path.is_ident("candidate"))
            {
                let mut calls = Calls::default();
                calls.visit_expr(&expression.right);
                self.0 |= calls
                    .0
                    .iter()
                    .any(|call| call == "acknowledge_lpc_rundown_exact");
            }
            syn::visit::visit_expr_assign(self, expression);
        }
    }
    let method = deletion_method();
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    let rundown = calls
        .0
        .iter()
        .position(|call| call == "retire_lpc_process_handles");
    let acknowledge = calls
        .0
        .iter()
        .position(|call| call == "acknowledge_lpc_rundown_exact");
    let mut recorded = Recorded::default();
    recorded.visit_block(&method.block);
    assert!(recorded.0 && rundown.is_some() && acknowledge.is_some() && rundown < acknowledge,
        "retain successful rundown on the exact candidate after broker acknowledgement, before later deletion retries");
}
