use syn::{visit::Visit, Expr, Item};

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn optional_gui_realization_requires_admitted_consumer_not_driver_start() {
    let source = syn::parse_file(include_str!("../../../../components/ntos-executive/src/hosted_pnp_start.rs")).unwrap();
    let publish = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "try_publish_hosted_video_route" => Some(function),
        _ => None,
    }).unwrap();
    let mut guard_index = None;
    let mut attempt_index = None;
    let mut realization_index = None;
    for (index, statement) in publish.block.stmts.iter().enumerate() {
        let mut calls = Calls::default();
        calls.visit_stmt(statement);
        if calls.0.iter().any(|call| call == "current_win32k_provider_domain") {
            let syn::Stmt::Expr(Expr::If(branch), _) = statement else {
                panic!("consumer admission must be a no-effect early return guard");
            };
            assert!(matches!(&*branch.cond, Expr::MethodCall(call) if call.method == "is_none"));
            assert!(branch.then_branch.stmts.iter().any(|statement|
                matches!(statement, syn::Stmt::Expr(Expr::Return(_), _))));
            guard_index = Some(index);
        }
        struct Attempts(bool);
        impl<'ast> Visit<'ast> for Attempts {
            fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                self.0 |= matches!(&field.member, syn::Member::Named(name) if name == "video_route_attempted_count");
                syn::visit::visit_expr_field(self, field);
            }
        }
        let mut attempts = Attempts(false);
        attempts.visit_stmt(statement);
        if attempts.0 { attempt_index = Some(index); }
        if calls.0.iter().any(|call| call == "publish_hosted_video_device_route") {
            realization_index = Some(index);
        }
    }
    let guard = guard_index.expect("driver registration is not authority to dereference an absent GUI consumer");
    assert!(guard < attempt_index.unwrap() && guard < realization_index.unwrap(),
        "absence is not a failed video attempt and must cause no projection allocation");
    let mut calls = Calls::default();
    calls.visit_item_fn(publish);
    assert!(calls.0.iter().any(|call| call == "hosted_video_route_info"),
        "admitted realization still consumes the registered canonical driver route");
    for forbidden in ["initialize_provider_pool", "start_device", "stop_device", "remove_device"] {
        assert!(!calls.0.iter().any(|call| call == forbidden),
            "optional GUI publication must not alter the independent driver lifecycle");
    }
}
