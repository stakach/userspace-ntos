use syn::visit::Visit;

#[derive(Default)]
struct CalledFunctions(Vec<String>);

impl<'ast> Visit<'ast> for CalledFunctions {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.0.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn native_filter_return_uses_status_before_provider_pointer() {
    let native = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .unwrap();
    let function = native.items.iter().find_map(|item| match item {
        syn::Item::Fn(function)
            if function.sig.ident == "retain_hosted_filter_requirements_return" =>
        {
            Some(function)
        }
        _ => None,
    }).expect("native filter terminal owner");
    let mut calls = CalledFunctions::default();
    calls.visit_block(&function.block);
    assert!(calls.0.iter().any(|name| name == "filter_requirements_return_action"),
        "native filter must classify status before treating Information as an owned output");
}
