use syn::{visit::Visit, Item};

struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            self.0.extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn pre_reply_component_drain_uses_admission_bounded_resume_pass() {
    let service = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs")).unwrap();
    for item in &service.items {
        if let Item::Fn(function) = item {
            assert!(function.sig.ident != "component_suspension_resume_top"
                && function.sig.ident != "component_suspension_drain_ready",
                "legacy unrestricted resume loops must not run ahead of an ordinary caller Reply");
        }
    }
    let mut service_calls = Calls(Vec::new());
    service_calls.visit_file(&service);
    assert!(service_calls.0.iter().any(|name| name == "drain_hosted_ready"),
        "service completion must use the focused bounded drain");

    let module = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/component_resume.rs")).unwrap();
    let drain = module.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "drain_hosted_ready" => Some(function),
        _ => None,
    }).expect("focused pre-reply component drain");
    let syn::FnArg::Typed(handler) = drain.sig.inputs.first().unwrap() else {
        panic!("explicit handler ownership required");
    };
    assert!(matches!(handler.ty.as_ref(), syn::Type::Ptr(_)),
        "no handler borrow may survive a resumed native provider callback");
    let mut calls = Calls(Vec::new());
    calls.visit_block(&drain.block);
    for required in ["resume_pass", "next_in_pass", "run_hosted"] {
        assert!(calls.0.iter().any(|name| name == required),
            "pre-reply drain must use existing bounded contract: {required}");
    }
    assert!(!calls.0.iter().any(|name| name == "next_ready"),
        "fresh rearmed admissions cannot join an already executing pass");
}
