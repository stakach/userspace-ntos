//! Query probes return NT's actual exception status, not a boolean access result.

use syn::visit::Visit;

#[test]
fn query_information_file_preserves_output_probe_exception_status() {
    let block = super::file_transfer_admission::service_branch("NtQueryInformationFile");
    struct Probe {
        exact_status: bool,
        boolean_probe: bool,
    }
    impl<'ast> Visit<'ast> for Probe {
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            self.boolean_probe |= expression.method == "probe_user_output";
            syn::visit::visit_expr_method_call(self, expression);
        }
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*expression.cond {
                if let (syn::Pat::TupleStruct(pattern), syn::Expr::MethodCall(call)) =
                    (&*condition.pat, &*condition.expr)
                {
                    if pattern.path.is_ident("Err") && call.method == "probe_file_io_output" {
                        let Some(syn::Pat::Ident(status)) = pattern.elems.first() else {
                            panic!("probe failure must bind its exact status");
                        };
                        assert_eq!(call.args.len(), 2);
                        assert!(matches!(&call.args[1], syn::Expr::Call(output)
                            if matches!(&*output.func, syn::Expr::Path(path)
                                if path.path.is_ident("Some"))));
                        self.exact_status = expression.then_branch.stmts.iter().any(|statement|
                            matches!(statement, syn::Stmt::Expr(syn::Expr::Return(return_), _)
                                if matches!(return_.expr.as_deref(), Some(syn::Expr::Path(path))
                                    if path.path.is_ident(&status.ident))));
                    }
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut probe = Probe { exact_status: false, boolean_probe: false };
    probe.visit_block(&block);
    assert!(probe.exact_status,
        "NtQueryInformationFile must return the exact IOSB/output probe exception");
    assert!(!probe.boolean_probe, "boolean probing loses the consumed guard exception");
}
