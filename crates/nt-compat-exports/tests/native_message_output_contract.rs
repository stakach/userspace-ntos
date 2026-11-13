use syn::visit::Visit;

fn called(expression: &syn::ExprCall, name: &str) -> bool {
    matches!(&*expression.func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

#[derive(Default)]
struct OutputAudit {
    validators: usize,
    published_lengths: usize,
    direct_copyouts: usize,
    callback_copyouts: usize,
    direct_guard: bool,
    callback_guard: bool,
}

impl<'ast> Visit<'ast> for OutputAudit {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        struct Guard(bool, bool);
        impl<'ast> Visit<'ast> for Guard {
            fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
                let path = |value: &syn::Expr, name: &str| {
                    matches!(value, syn::Expr::Path(path) if path.path.is_ident(name))
                        || matches!(value, syn::Expr::Cast(cast)
                            if matches!(&*cast.expr, syn::Expr::Path(path) if path.path.is_ident(name)))
                };
                self.0 |= matches!(expression.op, syn::BinOp::Eq(_))
                    && path(&expression.left, "direct_provider_output_len")
                    && path(&expression.right, "WIN32K_MSG_BYTES");
                if let syn::Expr::Binary(left) = &*expression.left {
                    let zero = matches!(&*left.right, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Int(value)
                            if matches!(value.base10_parse::<u64>(), Ok(0))));
                    self.1 |= matches!(expression.op, syn::BinOp::And(_))
                        && matches!(left.op, syn::BinOp::Ne(_))
                        && path(&left.left, "output_len")
                        && zero;
                }
            }
        }
        let mut guard = Guard(false, false);
        guard.visit_expr(&expression.cond);
        let outer = (self.direct_guard, self.callback_guard);
        self.direct_guard |= guard.0;
        self.callback_guard |= guard.1;
        // A callback copyout is on the RHS of the short-circuit output_len != 0 condition.
        self.visit_expr(&expression.cond);
        self.visit_block(&expression.then_branch);
        (self.direct_guard, self.callback_guard) = outer;
        if let Some((_, branch)) = &expression.else_branch {
            self.visit_expr(branch);
        }
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        self.validators += usize::from(called(
            expression,
            "message_dispatch_output_length_matches_result",
        ));
        self.published_lengths += usize::from(called(expression, "published_win32k_output_length"));
        if called(expression, "client_copyout_mapped") {
            self.direct_copyouts += usize::from(self.direct_guard);
            self.callback_copyouts += usize::from(self.callback_guard);
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

#[test]
fn empty_output_guard_must_short_circuit_copyout() {
    for (condition, expected) in [
        ("output_len != 0 && !client_copyout_mapped()", 1),
        ("output_len != 0 || !client_copyout_mapped()", 0),
    ] {
        let expression: syn::Expr =
            syn::parse_str(&format!("if {condition} {{ return false; }}")).unwrap();
        let mut audit = OutputAudit::default();
        audit.visit_expr(&expression);
        assert_eq!(audit.callback_copyouts, expected);
    }
}

