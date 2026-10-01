use syn::{visit::Visit, Item};

#[derive(Default)]
struct Effects {
    calls: Vec<String>,
    loops: usize,
}

impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.loops += 1;
        syn::visit::visit_expr_loop(self, expression);
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.loops += 1;
        syn::visit::visit_expr_while(self, expression);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.loops += 1;
        syn::visit::visit_expr_for_loop(self, expression);
    }
}

#[test]
fn root_pool_lease_revalidation_never_waits_for_an_execution_held_component() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_subsystem.rs"
    )).unwrap();
    let function = |name: &str| file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("missing pool boundary {name}"));
    let mut effects = Effects::default();
    effects.visit_item_fn(function("provider_pool_packet_lease_live"));
    assert!(effects.calls.iter().any(|name| name == "try_provider_pool_lock"),
        "root lease revalidation must defer on a busy physical pool lock");
    assert!(!effects.calls.iter().any(|name| name == "provider_pool_lock"),
        "yielding cannot release a lock held by an execution-held provider");

    let mut effects = Effects::default();
    effects.visit_item_fn(function("try_provider_pool_lock"));
    assert_eq!(effects.loops, 0, "root physical pool admission must attempt once");
    assert!(!effects.calls.iter().any(|name| name == "yield_now" || name == "provider_pool_lock"));
    assert_eq!(effects.calls.iter().filter(|name| name.as_str() == "compare_exchange").count(), 1,
        "one strong CAS must distinguish acquired from busy without a spurious retry loop");
}
