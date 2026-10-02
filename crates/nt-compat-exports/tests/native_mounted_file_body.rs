use syn::{visit::Visit, ImplItem, Item};

fn method(name: &str) -> syn::ImplItemFn {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/mounted_volume_backend.rs"
    )).unwrap();
    source.items.into_iter().find_map(|item| match item {
        Item::Impl(item) => item.items.into_iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }),
        _ => None,
    }).unwrap()
}

#[derive(Default)]
struct Operations {
    calls: Vec<String>,
    fields: Vec<String>,
    close_depth: usize,
    io_release_outside_close: bool,
}

impl<'ast> Visit<'ast> for Operations {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let close = matches!(&*expression.cond, syn::Expr::Path(path) if path.path.is_ident("close"));
        self.visit_expr(&expression.cond);
        self.close_depth += usize::from(close);
        self.visit_block(&expression.then_branch);
        self.close_depth -= usize::from(close);
        if let Some((_, branch)) = &expression.else_branch { self.visit_expr(branch); }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        if name == "release_io" && self.close_depth == 0 {
            self.io_release_outside_close = true;
        }
        self.calls.push(name);
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member { self.fields.push(name.to_string()); }
        syn::visit::visit_expr_field(self, field);
    }
}

#[test]
fn installed_create_retains_body_independently_of_handle_sharing() {
    let mut operations = Operations::default();
    operations.visit_impl_item_fn(&method("create_installed"));
    assert!(operations.calls.iter().any(|name| name == "retain_io"),
        "CREATE must retain the installed File body before publishing its context");
}

#[test]
fn installed_cleanup_keeps_body_until_close() {
    let mut operations = Operations::default();
    operations.visit_impl_item_fn(&method("cleanup_or_close"));
    assert!(operations.fields.iter().any(|name| name == "installed_handle_open"),
        "CLEANUP releases handle sharing once, independently of the retained body");
    assert!(operations.fields.iter().any(|name| name == "installed_open"));
    assert!(operations.calls.iter().any(|name| name == "release_io"));
    assert!(!operations.io_release_outside_close, "only CLOSE may release the body reference");
}

#[test]
fn installed_read_and_query_use_retained_body_not_handle_lease() {
    for name in ["read", "query"] {
        let mut operations = Operations::default();
        operations.visit_impl_item_fn(&method(name));
        assert!(operations.fields.iter().any(|field| field == "installed_open"), "{name}");
        assert!(!operations.fields.iter().any(|field| field == "share_open"), "{name}");
    }
}
