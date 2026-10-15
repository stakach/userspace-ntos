use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expression.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

#[test]
fn mounted_file_all_preserves_manager_owned_fields_before_filesystem_encoding() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume_backend.rs"
    ))
    .unwrap();
    let query = file.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None };
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "query" => Some(function),
            _ => None,
        })
    }).expect("mounted File query implementation");
    let mut calls = Calls::default();
    calls.visit_block(&query.block);
    let capture = calls.0.iter().position(|name| name == "capture_manager_owned_query_fields")
        .expect("capture canonical Access/Mode/Alignment from the seeded FileAll buffer");
    let encode = calls.0.iter().position(|name| name == "encode_named_query_information")
        .expect("filesystem FileAll encoder");
    assert!(capture < encode, "preserve seed before filesystem encoding, not repair afterward");
    assert_eq!(calls.0.iter().filter(|name| *name == "capture_manager_owned_query_fields").count(), 1);
}
