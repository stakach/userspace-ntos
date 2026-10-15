use syn::{parse::Parser, visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    })
}

#[derive(Default)]
struct Observe {
    calls: Vec<String>,
    fields: Vec<String>,
    paths: Vec<String>,
}
impl<'ast> Visit<'ast> for Observe {
    fn visit_macro(&mut self, expression: &'ast syn::Macro) {
        let name = expression.path.segments.last().unwrap().ident.to_string();
        let expressions = if name == "assert" || name == "assert_eq" || name == "assert_ne" {
            syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated
                .parse2(expression.tokens.clone())
                .ok()
                .map(|items| items.into_iter().collect::<Vec<_>>())
        } else if name == "matches" {
            let parser = |input: syn::parse::ParseStream<'_>| -> syn::Result<Vec<Expr>> {
                let value = input.parse::<Expr>()?;
                input.parse::<syn::Token![,]>()?;
                syn::Pat::parse_multi_with_leading_vert(input)?;
                let mut expressions = vec![value];
                if input.peek(syn::Token![if]) {
                    input.parse::<syn::Token![if]>()?;
                    expressions.push(input.parse::<Expr>()?);
                }
                if input.peek(syn::Token![,]) {
                    input.parse::<syn::Token![,]>()?;
                }
                Ok(expressions)
            };
            parser.parse2(expression.tokens.clone()).ok()
        } else {
            None
        };
        if let Some(expressions) = expressions {
            for expression in expressions {
                let mut nested = Observe::default();
                nested.visit_expr(&expression);
                self.calls.extend(nested.calls);
                self.fields.extend(nested.fields);
                self.paths.extend(nested.paths);
            }
        }
        syn::visit::visit_macro(self, expression);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths
            .push(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_expr_path(self, path);
    }
}

#[test]
fn pump_validates_actual_hosted_ready_words_before_recording_startup_receipt() {
    let file = source("spawn_hosts.rs");
    #[derive(Default)]
    struct ReadyCall {
        validated_words: bool,
        order: Vec<&'static str>,
    }
    impl<'ast> Visit<'ast> for ReadyCall {
        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "startup_stack_receipt"))
            {
                self.order.push("receipt");
            }
            syn::visit::visit_expr_assign(self, assignment);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "startup_expected"))
            {
                self.order.push("expected");
            }
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "validate_startup_ready"))
            {
                assert_eq!(call.args.len(), 2);
                let mut words = Observe::default();
                words.visit_expr(&call.args[1]);
                for required in ["m0", "m1", "m2", "m3", "m4"] {
                    assert!(
                        words.fields.iter().any(|name| name == required),
                        "startup admission must consume actual received {required}"
                    );
                }
                self.validated_words = true;
                self.order.push("validate");
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut call = ReadyCall::default();
    for item in &file.items {
        if let Item::Fn(function) = item {
            let mut fields = Observe::default();
            fields.visit_block(&function.block);
            if fields
                .fields
                .iter()
                .any(|name| name == "startup_stack_receipt")
                && fields.paths.iter().any(|name| name == "expected_info")
            {
                call.visit_block(&function.block);
            }
        }
    }
    assert!(
        call.validated_words,
        "IRP DispatchWorker bootstrap is currently rejected by the win32k-only startup gate"
    );
    assert!(
        call.order.iter().position(|event| *event == "validate")
            < call.order.iter().position(|event| *event == "receipt"),
        "validate actual READY tuple before publishing startup receipt"
    );
    assert!(
        call.order.iter().position(|event| *event == "expected")
            < call.order.iter().position(|event| *event == "validate"),
        "derive expected protocol independently of received payload before validation"
    );
}

#[test]
fn hosted_ready_admission_uses_retained_physical_bootstrap_and_current_reply() {
    let file = source("hosted_source_completion_lane.rs");
    let helper = function(&file, "validate_startup_ready")
        .expect("dedicated exact Hosted DispatchWorker startup policy must be live");
    let mut observe = Observe::default();
    observe.visit_block(&helper.block);
    assert!(observe.calls.iter().any(|name| name == "startup_expected"));
    observe.visit_block(&function(&file, "startup_expected").unwrap().block);
    for required in [
        "channel_route",
        "physical_source",
        "current_reply",
        "dispatch",
    ] {
        assert!(
            observe.calls.iter().any(|name| name == required),
            "startup admission lacks exact retained {required}"
        );
    }
    assert!(observe.paths.iter().any(|name| name == "Preparing"));
    for required in [
        "tcb",
        "pml4",
        "domain",
        "route",
        "ordinal",
        "component_shared",
        "executive_shared",
        "cnode",
        "startup_dispatch",
    ] {
        assert!(
            observe.fields.iter().any(|name| name == required),
            "startup must validate retained physical/bank identity: {required}"
        );
    }
    assert!(
        !observe.fields.iter().any(|name| name == "reply_cap"),
        "immutable channel Reply snapshot is not authority after bootstrap fault rotation"
    );
}

#[test]
fn scheduler_settles_validated_startup_with_exact_protocol_and_current_reply() {
    let file = source("component_scheduler.rs");
    let helper = function(&file, "hosted_component_pump_inner").unwrap();
    let mut observe = Observe::default();
    observe.visit_block(&helper.block);
    assert!(observe
        .fields
        .iter()
        .any(|name| name == "startup_stack_receipt"));
    for required in [
        "validate_startup_ready",
        "current_reply",
        "complete_protocol",
        "complete",
    ] {
        assert!(
            observe.calls.iter().any(|name| name == required),
            "startup settlement and ordinary zero-word completion must remain distinct: {required}"
        );
    }
    struct Protocol(bool);
    impl<'ast> Visit<'ast> for Protocol {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "complete_protocol"))
            {
                assert_eq!(call.args.len(), 5);
                assert!(
                    matches!(&call.args[4], Expr::Reference(reference)
                    if matches!(&*reference.expr, Expr::Path(path) if path.path.is_ident("words"))),
                    "settle the exact received-and-validated startup tuple"
                );
                self.0 = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut protocol = Protocol(false);
    protocol.visit_block(&helper.block);
    assert!(protocol.0);
}
