use syn::{visit::Visit, Expr, ImplItem, Item};

fn create_directory() -> syn::ImplItemFn {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/mounted_volume_backend.rs"
    )).unwrap();
    source.items.into_iter().find_map(|item| match item {
        Item::Impl(item) => item.items.into_iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == "create_directory" => Some(function),
            _ => None,
        }),
        _ => None,
    }).expect("canonical mounted-volume directory CREATE implementation")
}

#[derive(Default)]
struct PolicyWiring {
    decision: bool,
    create_overlay_depth: usize,
    real_create: bool,
}

impl<'ast> Visit<'ast> for PolicyWiring {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, Expr::Path(path) if path.path.segments.last()
            .is_some_and(|segment| segment.ident == "layered_directory_open_decision")) {
            self.decision = true;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        let create = matches!(&arm.pat, syn::Pat::Path(path) if path.path.segments.last()
            .is_some_and(|segment| segment.ident == "CreateOverlay"));
        self.create_overlay_depth += usize::from(create);
        syn::visit::visit_arm(self, arm);
        self.create_overlay_depth -= usize::from(create);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let true_literal = |expression: Option<&Expr>| matches!(expression,
            Some(Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(value), .. })) if value.value);
        if self.create_overlay_depth != 0 && call.method == "create_overlay" {
            assert_eq!(call.args.len(), 8, "retain the existing canonical overlay CREATE contract");
            assert!(true_literal(call.args.iter().nth(5)), "materialize the real installed parent");
            assert!(true_literal(call.args.iter().nth(6)), "publish a real directory open context");
            self.real_create = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn canonical_directory_create_consumes_layer_policy_and_creates_actual_overlay_directory() {
    let mut wiring = PolicyWiring::default();
    wiring.visit_impl_item_fn(&create_directory());
    assert!(wiring.decision, "directory absence must be handled by tested disposition policy, not NOT_SUPPORTED");
    assert!(wiring.real_create, "CreateOverlay must reach retained canonical File + actual writable directory creation");
}
