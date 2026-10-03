use syn::{visit::Visit, Item};

fn feature_gated(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| attribute.path().is_ident("cfg")
        && matches!(&attribute.meta, syn::Meta::List(list)
            if list.tokens.to_string().contains("source-irp-integration")))
}

#[test]
fn native_source_probe_is_feature_gated_and_retains_exact_owners() {
    let glue = syn::parse_file(include_str!("../../../components/ntos-executive/src/win32k_glue.rs")).unwrap();
    let declaration = glue.items.iter().find_map(|item| match item {
        Item::Mod(module) if module.ident == "source_irp_integration" => Some(module),
        _ => None,
    }).expect("source probe needs a focused native integration module");
    assert!(feature_gated(&declaration.attrs), "production must not compile the validation hook");
    let subsystem = syn::parse_file(include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs")).unwrap();
    let request = subsystem.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == "WIN32K_REQUEST_SOURCE_IRP_PROBE" => Some(item),
        _ => None,
    }).expect("fixture must use an explicit request, not a production syscall override");
    assert!(feature_gated(&request.attrs));

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../components/ntos-executive/src/source_irp_integration.rs");
    let module = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    #[derive(Default)]
    struct Ownership { registration: bool, reference: bool, load: bool, observed_dispatch: bool }
    impl<'ast> Visit<'ast> for Ownership {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            for segment in &path.path.segments {
                self.registration |= segment.ident == "HostedDevicePointerRegistration";
                self.reference |= segment.ident == "HostedDevicePointerReference";
            }
            syn::visit::visit_type_path(self, path);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                for segment in &path.path.segments {
                    self.load |= segment.ident == "acquire_load";
                    self.observed_dispatch |= segment.ident == "win32k_dispatch_wide_observed"
                        || segment.ident == "win32k_dispatch_kernel_job_observed";
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut ownership = Ownership::default();
    ownership.visit_file(&module);
    assert!(ownership.registration && ownership.reference, "exact canonical target ownership must survive dispatch");
    assert!(ownership.load, "checked source module must retain a load reference");
    assert!(ownership.observed_dispatch, "source must run under the genuine authenticated win32k pump");
}

#[test]
fn source_probe_binds_kernel_wait_owner_before_entering_checked_source() {
    let subsystem = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_subsystem.rs"
    )).unwrap();
    let dispatch = subsystem.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "win32k_dispatch" => Some(item),
        _ => None,
    }).expect("genuine win32k dispatch boundary");

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
    }
    struct ProbeBranch { found: bool }
    impl<'ast> Visit<'ast> for ProbeBranch {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            let selected = matches!(&*branch.cond,
                syn::Expr::Binary(condition) if matches!(condition.op, syn::BinOp::Eq(_))
                    && matches!(&*condition.right, syn::Expr::Path(path)
                        if path.path.is_ident("WIN32K_REQUEST_SOURCE_IRP_PROBE")));
            if selected {
                let mut calls = Calls::default();
                calls.visit_block(&branch.then_branch);
                if let Some(enter) = calls.0.iter().position(|call| call == "component_probe") {
                    self.found = true;
                    let capture = calls.0.iter().position(|call|
                        call == "capture_kernel_provider_stack_activation");
                    assert!(capture.is_some_and(|capture| capture < enter),
                        "the exact source-probe branch must retain a genuine kernel wait activation before invoking the source");
                    assert!(!calls.0.iter().any(|call|
                        call == "begin_provider_stack_event_activation"),
                        "a kernel probe must not layer an ownerless activation over its authenticated wait owner");
                }
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut branch = ProbeBranch { found: false };
    branch.visit_item_fn(dispatch);
    assert!(branch.found, "source-probe execution must be scoped to its explicit request branch");
}

#[test]
fn executive_source_probe_uses_owned_kernel_job_authority() {
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
    }
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/source_irp_integration.rs"
    )).unwrap();
    let mut calls = Calls::default();
    calls.visit_file(&source);
    assert!(calls.0.iter().any(|call| call == "win32k_dispatch_kernel_job_observed"),
        "a kernel source probe requires exact retained kernel-job authority, not an ownerless executive client");
    assert!(!calls.0.iter().any(|call| call == "win32k_dispatch_wide_observed"),
        "the generic hosted dispatch does not acquire kernel caller or completion ownership");

    let glue = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    )).unwrap();
    let dispatch = glue.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "win32k_dispatch_kernel_job_observed" => Some(item),
        _ => None,
    }).expect("focused owned kernel dispatch adapter");
    let mut calls = Calls::default();
    calls.visit_item_fn(dispatch);
    for name in ["capture_kernel_job", "run_kernel_job"] {
        assert!(calls.0.iter().any(|call| call == name),
            "kernel dispatch must use canonical activation capture and owned pump: {name}");
    }
    assert!(!calls.0.iter().any(|call| call == "finish_win32k_lane_return"),
        "owned kernel completion must not also run the hosted completion path");
}

#[test]
fn kernel_job_recipient_owns_the_return_status_contract() {
    let parsed = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/kernel_bootstrap.rs"
    )).unwrap();
    let method = parsed.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|method| match method {
            syn::ImplItem::Fn(method) if method.sig.ident == "return_status_offset" => Some(method),
            _ => None,
        }),
        _ => None,
    }).expect("retained recipient must own its return field, not reuse ambient DriverEntry status");
    #[derive(Default)]
    struct Fields { driver: bool, executive: bool }
    impl<'ast> Visit<'ast> for Fields {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            for segment in &path.path.segments {
                self.driver |= segment.ident == "SH_DE_STATUS";
                self.executive |= segment.ident == "SH_REQ_STATUS";
            }
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut fields = Fields::default();
    fields.visit_impl_item_fn(method);
    assert!(fields.driver && fields.executive,
        "DriverEntry and runtime executive jobs have distinct authenticated status locations");
}
