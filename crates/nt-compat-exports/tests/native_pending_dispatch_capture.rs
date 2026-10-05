use syn::{visit::Visit, Item};

struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            self.0.extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn initial_wait_snapshot_capture_has_one_policy_and_reparks_keep_saved_bytes() {
    let bridge = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    )).unwrap();
    struct InitialBranches(Vec<String>);
    impl<'ast> Visit<'ast> for InitialBranches {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            struct Capture {
                calls: usize,
                constructor: Option<String>,
                fields: Vec<(String, bool)>,
            }
            impl<'ast> Visit<'ast> for Capture {
                fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                    if matches!(call.func.as_ref(), syn::Expr::Path(path)
                        if path.path.is_ident("capture_initial_arg_snapshot"))
                    {
                        assert_eq!(call.args.len(), 2);
                        for (argument, expected) in call.args.iter().zip(["ssn", "completion_args"]) {
                            assert!(matches!(argument, syn::Expr::Path(path) if path.path.is_ident(expected)),
                                "initial capture must use the original syscall and completion arguments");
                        }
                        self.calls += 1;
                    }
                    syn::visit::visit_expr_call(self, call);
                }
                fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
                    let name = expression.path.segments.last().unwrap().ident.to_string();
                    if matches!(name.as_str(), "PendingProviderWaitDispatch" | "PendingLpcWaitDispatch" | "PendingReceiveDispatch") {
                        self.constructor = Some(name);
                        for field in &expression.fields {
                            if let syn::Member::Named(name) = &field.member {
                                if matches!(name.to_string().as_str(), "arg_snapshot_len" | "arg_snapshot") {
                                    let name = name.to_string();
                                    let canonical = matches!(&field.expr, syn::Expr::Path(path)
                                        if path.path.is_ident(name.as_str()));
                                    self.fields.push((name, canonical));
                                }
                            }
                        }
                    }
                    syn::visit::visit_expr_struct(self, expression);
                }
            }
            let mut capture = Capture { calls: 0, constructor: None, fields: Vec::new() };
            capture.visit_block(&branch.then_branch);
            if capture.calls != 0 {
                assert_eq!(capture.calls, 1, "one canonical capture per initial suspension branch");
                assert_eq!(capture.fields.len(), 2, "both original snapshot fields must be retained");
                assert!(capture.fields.iter().all(|(_, canonical)| *canonical),
                    "initial pending dispatch must store its canonical capture");
                let constructor = capture.constructor.expect("initial suspension stores a typed pending dispatch");
                struct Condition(Vec<String>);
                impl<'ast> Visit<'ast> for Condition {
                    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                        if let syn::Member::Named(name) = &field.member { self.0.push(name.to_string()); }
                        syn::visit::visit_expr_field(self, field);
                    }
                }
                let expected = match constructor.as_str() {
                    "PendingProviderWaitDispatch" => "provider_wait_suspended",
                    "PendingLpcWaitDispatch" => "lpc_wait_suspended",
                    "PendingReceiveDispatch" => "receive_yield",
                    _ => unreachable!(),
                };
                let mut condition = Condition(Vec::new());
                condition.visit_expr(&branch.cond);
                assert!(condition.0.iter().any(|field| field == expected),
                    "{constructor} capture must belong to its actual initial suspension branch");
                self.0.push(constructor);
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut initial = InitialBranches(Vec::new());
    initial.visit_file(&bridge);
    initial.0.sort();
    assert_eq!(initial.0, ["PendingLpcWaitDispatch", "PendingProviderWaitDispatch", "PendingReceiveDispatch"],
        "initial Provider/LPC/Receive suspension must each use the canonical capture policy");

    // Read at runtime so a missing module is a behavioral assertion, not a compile failure.
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/win32k_pending_dispatch.rs"))
        .expect("focused pending-dispatch capture module");
    let pending = syn::parse_file(&source).unwrap();
    let capture = pending.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "capture_initial_arg_snapshot" => Some(function),
        _ => None,
    }).expect("single initial capture policy");
    let syn::FnArg::Typed(ssn) = capture.sig.inputs.first().unwrap() else {
        panic!("explicit original service number required");
    };
    assert!(matches!(ssn.ty.as_ref(), syn::Type::Path(path) if path.path.is_ident("u64")),
        "capture must preserve the bridge's full service number without narrowing");
    for name in ["capture_provider_wait_repark", "capture_lpc_wait_repark"] {
        let function = pending.items.iter().find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }).expect("existing repark contract");
        let mut calls = Calls(Vec::new());
        calls.visit_block(&function.block);
        assert!(!calls.0.iter().any(|call| call == "capture_initial_arg_snapshot"
            || call == "copy_nonoverlapping"),
            "a repark must preserve the original captured bytes, not reread client aliases");
    }
    let receive = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_receive.rs"
    )).unwrap();
    let resume = receive.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "resume_suspended_receive_component" => Some(function),
        _ => None,
    }).expect("actual Receive repark bridge");
    let mut calls = Calls(Vec::new());
    calls.visit_block(&resume.block);
    assert!(!calls.0.iter().any(|call| call == "capture_initial_arg_snapshot" || call == "copy_nonoverlapping"),
        "Receive reparks must not reread original client aliases");
    fn saved_field(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(member) if member == name)
                && matches!(field.base.as_ref(), syn::Expr::Path(path) if path.path.is_ident("pending")))
    }
    #[derive(Default)]
    struct ReceiveReparks { receive: bool, provider: bool, lpc: bool }
    impl<'ast> Visit<'ast> for ReceiveReparks {
        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            if expression.path.is_ident("PendingReceiveDispatch") {
                self.receive |= matches!(expression.rest.as_deref(), Some(syn::Expr::Path(path)) if path.path.is_ident("pending"))
                    && !expression.fields.iter().any(|field| matches!(&field.member, syn::Member::Named(name)
                        if name == "arg_snapshot_len" || name == "arg_snapshot"));
            }
            if expression.path.is_ident("PendingProviderWaitDispatch") {
                self.provider |= ["arg_snapshot_len", "arg_snapshot"].iter().all(|name|
                    expression.fields.iter().any(|field|
                        matches!(&field.member, syn::Member::Named(member) if member == *name)
                            && saved_field(&field.expr, name)));
            }
            syn::visit::visit_expr_struct(self, expression);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.is_ident("capture_lpc_wait_repark")) {
                self.lpc |= call.args.len() == 5 && saved_field(&call.args[3], "arg_snapshot_len")
                    && saved_field(&call.args[4], "arg_snapshot");
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut reparks = ReceiveReparks::default();
    reparks.visit_block(&resume.block);
    assert!(reparks.receive && reparks.provider && reparks.lpc,
        "actual Receive, Provider and LPC reparks must preserve the saved original snapshot bytes");
}
