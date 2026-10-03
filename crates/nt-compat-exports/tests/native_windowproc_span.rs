use syn::visit::Visit;

fn body<'a>(source: &'a syn::File, name: &str) -> &'a syn::Block {
    for item in &source.items {
        match item {
            syn::Item::Fn(function) if function.sig.ident == name => return &function.block,
            syn::Item::Impl(implementation) => {
                for item in &implementation.items {
                    if let syn::ImplItem::Fn(function) = item {
                        if function.sig.ident == name { return &function.block; }
                    }
                }
            }
            _ => {}
        }
    }
    panic!("missing native boundary {name}");
}

fn uses_span(block: &syn::Block, retained_input: bool) -> bool {
    struct Calls { retained_input: bool, found: bool }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|name| name.ident == "windowproc_lparam_span")) {
                struct Input(bool);
                impl<'ast> Visit<'ast> for Input {
                    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                        self.0 |= matches!(&field.member, syn::Member::Named(name) if name == "input")
                            && matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("self"));
                        syn::visit::visit_expr_field(self, field);
                    }
                }
                let mut input = Input(false);
                for argument in &call.args { input.visit_expr(argument); }
                self.found |= !self.retained_input || input.0;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls { retained_input, found: false };
    calls.visit_block(block);
    calls.found
}

#[test]
fn component_producer_derives_blob_reference_from_exact_shared_span() {
    let source = syn::parse_file(include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs")).unwrap();
    assert!(uses_span(body(&source, "s_ke_user_mode_callback_rendezvous"), false),
        "producer must validate copied WINDOWPROC payload through the shared span contract");
}

#[test]
fn root_callback_contract_validates_actual_windowproc_blob_span() {
    let source = syn::parse_file(include_str!("../../../components/ntos-executive/src/win32k_glue.rs")).unwrap();
    assert!(uses_span(body(&source, "service_user_callback"), false),
        "root must validate actual payload size and exact embedded reference, not offset plus pointer width");
}

#[test]
fn pending_callback_redirect_uses_exact_windowproc_span_before_rebasing() {
    let source = syn::parse_file(include_str!("../../../components/ntos-executive/src/win32k_glue.rs")).unwrap();
    assert!(uses_span(body(&source, "redirect_pending_user_callback"), false),
        "legacy redirect must validate the retained blob before rebasing into client memory");
}

#[test]
fn retained_transfer_validates_its_owned_input_not_a_later_shared_frame() {
    let source = syn::parse_file(include_str!("../../../components/ntos-executive/src/component_callback_transfer.rs")).unwrap();
    assert!(uses_span(body(&source, "prepare_inner"), true),
        "retained transfer must derive span from self.input, preserving captured callback identity");
}

#[test]
fn retained_transfer_keeps_full_eight_byte_lparam_pointer_field_guard() {
    struct Guard(bool);
    impl<'ast> Visit<'ast> for Guard {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            if matches!(binary.op, syn::BinOp::Lt(_)) {
                if let syn::Expr::Binary(end) = &*binary.right {
                    self.0 |= matches!(end.op, syn::BinOp::Add(_))
                        && matches!(&*end.left, syn::Expr::Path(path)
                            if path.path.segments.last().is_some_and(|name| name.ident == "WINDOWPROC_LPARAM_OFFSET"))
                        && matches!(&*end.right, syn::Expr::Lit(value)
                            if matches!(&value.lit, syn::Lit::Int(value)
                                if matches!(value.base10_parse::<u64>(), Ok(8))));
                }
            }
            syn::visit::visit_expr_binary(self, binary);
        }
    }
    let source = syn::parse_file(include_str!("../../../components/ntos-executive/src/component_callback_transfer.rs")).unwrap();
    let mut guard = Guard(false);
    guard.visit_block(body(&source, "prepare_inner"));
    assert!(guard.0, "short or empty blob support must not weaken the eight-byte pointer-field bound");
}
