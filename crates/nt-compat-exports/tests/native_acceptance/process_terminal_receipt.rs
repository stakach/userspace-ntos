use syn::visit::Visit;

#[test]
fn terminal_receipt_uses_the_hex_printers_single_prefix() {
    let source = include_str!(
        "../../../../components/ntos-executive/src/process_terminal_receipt.rs"
    );
    let file = syn::parse_file(source).unwrap();
    struct Labels(Vec<Vec<u8>>);
    impl<'ast> Visit<'ast> for Labels {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("print_str")) {
                if let Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::ByteStr(label), ..
                })) = call.args.first() {
                    self.0.push(label.value());
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut labels = Labels(Vec::new());
    labels.visit_file(&file);
    assert!(labels.0.iter().any(|label| label == b" exit-status="),
        "print_hex already emits 0x; the actual receipt must match the parser framing");
    assert!(!labels.0.iter().any(|label| label == b" exit-status=0x"));
}

#[test]
fn terminal_receipt_follows_canonical_commit_before_effectful_handle_rundown() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    ))
    .unwrap();
    struct Audit {
        events: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if matches!(
                call.method.to_string().as_str(),
                "terminate_process_at" | "release_process_handles"
            ) {
                self.events.push(call.method.to_string());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|name| name.ident == "note_native_process_terminal"))
            {
                self.events.push("receipt".into());
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut audit = Audit { events: Vec::new() };
    audit.visit_file(&file);
    assert!(
        audit
            .events
            .windows(3)
            .any(|events| events == ["terminate_process_at", "receipt", "release_process_handles"]),
        "observe canonical process exit status before handles can pump and retire its identity"
    );
}
