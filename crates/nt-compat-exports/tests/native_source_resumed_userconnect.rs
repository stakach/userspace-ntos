use syn::{visit::Visit, Item};

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).expect("native completion function")
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn resumed_userconnect_captures_completed_provider_output_before_releasing_stage() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    )).unwrap();
    for name in ["complete_resumed_dispatch", "resume_suspended_lpc_wait_component"] {
        let mut calls = Calls::default();
        calls.visit_block(&function(&file, name).block);
        assert!(calls.0.iter().any(|call| call == "capture_resumed_userconnect_snapshot"),
            "{name} must capture the provider's completed USERCONNECT output");
    }
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "capture_resumed_userconnect_snapshot").block);
    for required in ["staged_userconnect_has_sharedinfo", "capture_arg_snapshot", "set_arg_snapshot"] {
        assert!(calls.0.iter().any(|call| call == required),
            "resumed USERCONNECT must validate output and preserve a retained snapshot: {required}");
    }
}
