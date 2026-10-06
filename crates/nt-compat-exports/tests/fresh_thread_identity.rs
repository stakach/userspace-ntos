//! A reusable execution window is not authority to recycle its previous ETHREAD.
use syn::visit::Visit;

fn publication() -> syn::ImplItemFn {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    file.items.into_iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        implementation.items.into_iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "prepare_hosted_thread_publication" => Some(function),
            _ => None,
        })
    }).expect("actual hosted thread publication entrypoint")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() { self.0.push(segment.ident.to_string()); }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn every_hosted_creation_prepares_a_fresh_identity_before_activation() {
    let function = publication();
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    let fresh = calls.0.iter().position(|name| name == "prepare_fresh_hosted_thread")
        .expect("a free native window must allocate a fresh canonical ETHREAD, even while handles retain the old terminated identity");
    let activation = calls.0.iter().position(|name| name == "prepare_thread_activation").unwrap();
    assert!(fresh < activation);
    assert!(!calls.0.iter().any(|name| name == "pm_pool_tid_for_slot" || name == "prepare_thread_reactivation"),
        "new NT thread identity must not depend on reclaiming the previous slot's ETHREAD or body aliases");
}
