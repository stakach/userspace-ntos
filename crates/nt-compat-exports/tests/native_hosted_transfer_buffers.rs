use syn::{visit::Visit, Item};

#[derive(Default)]
struct Calls {
    methods: Vec<String>,
    functions: Vec<String>,
    fields: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.functions.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }
}

#[test]
fn hosted_backend_projects_explicit_transfer_buffers_before_legacy_combined_storage() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .unwrap();
    let adapter = file.items.iter().find_map(|item| match item {
        Item::Impl(item)
            if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("HostedDriverBackend")) =>
        {
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "dispatch_irp" => Some(method),
                _ => None,
            })
        }
        _ => None,
    }).unwrap();
    let mut calls = Calls::default();
    calls.visit_impl_item_fn(adapter);
    assert!(calls.methods.iter().any(|name| name == "has_nonbuffered_transfer"),
        "separate MDL/User/Type3 buffers must not be interpreted as concatenated SystemBuffer");
    assert!(calls.functions.iter().any(|name| name == "hosted_irp_explicit_transfer_dispatch"),
        "the hosted adapter must enter an explicit-buffer projection boundary");

    let projection = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "hosted_irp_explicit_transfer_dispatch" => Some(function),
        _ => None,
    }).expect("explicit transfer projection must be separate from legacy combined transport");
    let mut calls = Calls::default();
    calls.visit_item_fn(projection);
    for method in ["ioctl_input_buffer", "ioctl_output_buffer_mut", "get", "get_mut"] {
        assert!(calls.methods.iter().any(|name| name == method),
            "explicit transfer projection must use authoritative buffer selection and exact extents: {method}");
    }
    for field in ["direct_buffer", "user_buffer", "input_len", "output_len"] {
        assert!(calls.fields.iter().any(|name| name == field),
            "explicit READ/WRITE and controls must preserve independently sized buffers: {field}");
    }
    assert!(!calls.functions.iter().any(|name| name == "projection_buffer_extents"),
        "explicit extents must not be clipped to SystemBuffer capacity");
}
