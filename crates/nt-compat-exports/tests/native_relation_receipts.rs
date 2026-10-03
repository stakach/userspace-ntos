use syn::{visit::Visit, Item};

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.0.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        self.0.push(call.method.to_string());
    }
}

fn after(calls: &Calls, effect: &str, receipt: &str) {
    let effect = calls.0.iter().position(|call| call == effect).expect("existing ownership effect");
    let receipt = calls.0.iter().position(|call| call == receipt)
        .expect("successful ownership effect needs its exact stateless receipt");
    assert!(effect < receipt, "receipts cannot precede their ownership effect");
}

#[test]
fn relation_transfer_receipt_follows_successful_exact_transfer() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_kernel_win32k_source_pnp.rs"
    )).unwrap();
    let method = source.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "commit_terminal" => Some(item),
            _ => None,
        }),
        _ => None,
    }).expect("canonical PnP terminal commit");
    let mut calls = Calls::default();
    calls.visit_impl_item_fn(method);
    after(&calls, "transfer", "record_target_relation_transfer");
}

#[test]
fn device_dereference_receipt_requires_successful_broker_reply() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_device_pointers.rs"
    )).unwrap();
    let exchange = source.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "exchange" => Some(item),
        _ => None,
    }).expect("authenticated Device broker exchange");
    let mut calls = Calls::default();
    calls.visit_item_fn(exchange);
    after(&calls, "decode", "record_device_pointer_dereference_ack");
    after(&calls, "into_result", "record_device_pointer_dereference_ack");
    struct SuccessBranch(bool);
    impl<'ast> Visit<'ast> for SuccessBranch {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            if matches!(&*branch.cond, syn::Expr::Let(condition)
                if matches!(&*condition.pat, syn::Pat::TupleStruct(pattern)
                    if pattern.path.is_ident("Ok")))
            {
                let mut calls = Calls::default();
                calls.visit_block(&branch.then_branch);
                self.0 |= calls.0.iter().any(|call| call == "record_device_pointer_dereference_ack");
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut success = SuccessBranch(false);
    success.visit_item_fn(exchange);
    assert!(success.0, "failed or ambiguous replies cannot emit successful dereference ACKs");
}

#[test]
fn canonical_dereference_receipt_follows_exact_registration_release() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_device_pointers.rs"
    )).unwrap();
    let service = source.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "service" => Some(item),
        _ => None,
    }).expect("canonical Device pointer service");
    let mut calls = Calls::default();
    calls.visit_item_fn(service);
    after(&calls, "dereference_hosted_device_pointer", "record_device_pointer_dereference_commit");
}

#[test]
fn allocation_free_receipt_uses_exact_successful_retirement() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_subsystem.rs"
    )).unwrap();
    let release = source.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "release_reserved_provider_pool" => Some(item),
        _ => None,
    }).expect("exact shared-header and private-catalog free commit");
    let mut calls = Calls::default();
    calls.visit_item_fn(release);
    after(&calls, "free", "record_provider_allocation_free");
    after(&calls, "retire", "record_provider_allocation_free");
    after(&calls, "allocation_identity", "record_provider_allocation_free");
}

fn method<'a>(source: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    source.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        }),
        _ => None,
    }).expect("native ownership method")
}

#[test]
fn video_target_relation_acquires_fresh_returned_reference() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_video_target_relation.rs"
    )).unwrap();
    let dispatch = source.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "dispatch" => Some(item),
        _ => None,
    }).unwrap();
    let mut calls = Calls::default();
    calls.visit_item_fn(dispatch);
    after(&calls, "hosted_device_pointer_registration", "retain_hosted_device_pointer_reference");
    assert!(!calls.0.iter().any(|call| call == "take_hosted_device_pointer_reference"),
        "ObReferenceObject creates ownership; it cannot steal an existing caller reference");
}

#[test]
fn normal_and_stopped_pnp_transfer_explicit_owner_or_native_driver_caller_reference() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_kernel_win32k_source_pnp.rs"
    )).unwrap();
    struct NativeDriverTransfer(usize);
    impl<'ast> Visit<'ast> for NativeDriverTransfer {
        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            for arm in &expression.arms {
                let missing_owner = match &arm.pat {
                    syn::Pat::Path(path) => path.path.is_ident("None"),
                    syn::Pat::Ident(pattern) => pattern.ident == "None"
                        && pattern.by_ref.is_none() && pattern.mutability.is_none()
                        && pattern.subpat.is_none(),
                    _ => false,
                };
                if missing_owner {
                    let mut calls = Calls::default();
                    calls.visit_expr(&arm.body);
                    self.0 += calls.0.iter().filter(|call|
                        *call == "take_hosted_device_pointer_reference").count();
                }
            }
            syn::visit::visit_expr_match(self, expression);
        }
    }
    for name in ["prepare_relation", "finish_stopped"] {
        let method = method(&source, name);
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(method);
        after(&calls, "hosted_device_pointer_registration", "take_owned_reference");
        after(&calls, "take_owned_reference", "take_hosted_device_pointer_reference");
        let mut native = NativeDriverTransfer(0);
        native.visit_impl_item_fn(method);
        assert_eq!(native.0, 1, "{name}: projected caller transfer is only for native driver results");
        assert_eq!(calls.0.iter().filter(|call|
            *call == "take_hosted_device_pointer_reference").count(), 1);
    }
}

#[test]
fn returned_owner_is_not_taken_before_exact_native_and_registration_validation() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_driver_relation_source.rs"
    )).unwrap();
    let method = method(&source, "take_owned_reference");
    let mut calls = Calls::default();
    calls.visit_impl_item_fn(method);
    for check in ["validate", "domain", "hosted_device_pointer_registration",
        "copy_device_relations_x64", "device_id"] {
        after(&calls, check, "take");
    }
    let rejecting_checks = method.block.stmts.iter().filter(|statement| {
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else { return false };
        struct ReturnsError(bool);
        impl<'ast> Visit<'ast> for ReturnsError {
            fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
                self.0 |= matches!(expression.expr.as_deref(), Some(syn::Expr::Call(call))
                    if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("Err")));
            }
        }
        let mut rejection = ReturnsError(false);
        rejection.visit_block(&branch.then_branch);
        rejection.0
    }).count();
    assert_eq!(rejecting_checks, 2, "native/registration and returned-object failures retain ownership");
}
