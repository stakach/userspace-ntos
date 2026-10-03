use syn::{visit::Visit, Item};

#[test]
fn native_source_ioctl_projects_type3_separately_from_mdl_read_pins() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_source_irp.rs"
    )).unwrap();
    let getter = source.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "type3_input_buffer_address" => Some(method),
            _ => None,
        }),
        _ => None,
    }).expect("source admission must expose Type3InputBuffer, not its generic read-pin address");
    #[derive(Default)]
    struct Projection { method_qualified: bool, wire_getter: bool, generic_pin: bool }
    impl<'ast> Visit<'ast> for Projection {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            if let syn::Expr::Binary(condition) = &*branch.cond {
                self.method_qualified |= matches!(condition.op, syn::BinOp::Eq(_))
                    && matches!(&*condition.right, syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|segment|
                            segment.ident == "METHOD_NEITHER"));
            }
            syn::visit::visit_expr_if(self, branch);
        }
        fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
            if value.path.segments.last().is_some_and(|segment| segment.ident == "SourceIrpIoctlRequest") {
                if let Some(field) = value.fields.iter().find(|field|
                    matches!(&field.member, syn::Member::Named(name) if name == "input_va"))
                {
                    struct Getter<'a>(&'a mut Projection);
                    impl<'ast> Visit<'ast> for Getter<'_> {
                        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                            self.0.wire_getter |= call.method == "type3_input_buffer_address";
                            self.0.generic_pin |= call.method == "input_target_address";
                            syn::visit::visit_expr_method_call(self, call);
                        }
                    }
                    Getter(&mut *self).visit_expr(&field.expr);
                }
            }
            syn::visit::visit_expr_struct(self, value);
        }
    }
    let mut projection = Projection::default();
    projection.visit_impl_item_fn(getter);
    assert!(projection.method_qualified, "only METHOD_NEITHER may expose a Type3InputBuffer address");
    projection.visit_file(&syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_source_irp_call.rs"
    )).unwrap());
    assert!(projection.wire_getter && !projection.generic_pin,
        "IN_DIRECT's MDL read pin must never occupy the wire Type3InputBuffer field");
}
