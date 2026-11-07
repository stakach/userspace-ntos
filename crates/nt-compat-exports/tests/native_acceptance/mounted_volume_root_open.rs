//! Autochk opens the volume itself, with no OBJ_CASE_INSENSITIVE flag.

use syn::{visit::Visit, ImplItem, Item};

#[derive(Default)]
struct CaseSensitivityReference(bool);

impl<'ast> Visit<'ast> for CaseSensitivityReference {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        self.0 |= matches!(&field.member, syn::Member::Named(name) if name == "create_case_sensitive");
        syn::visit::visit_expr_field(self, field);
    }
}

#[test]
fn mounted_volume_root_create_does_not_reject_autochk_case_sensitivity_before_path_resolution() {
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/mounted_volume_backend.rs"
    ))
    .unwrap();
    let create = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Impl(implementation) => implementation.items.iter().find_map(|item| match item {
                ImplItem::Fn(function) if function.sig.ident == "create" => Some(function),
                _ => None,
            }),
            _ => None,
        })
        .expect("mounted filesystem CREATE dispatch");
    let first_guard = create
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            syn::Stmt::Expr(syn::Expr::If(guard), _) => Some(guard),
            _ => None,
        })
        .expect("CREATE validates its inputs before path lookup");
    let mut guard = CaseSensitivityReference::default();
    guard.visit_expr(&first_guard.cond);
    assert!(
        !guard.0,
        "autochk's case-sensitive volume-root CREATE must reach path resolution; the empty root has no component whose spelling could be folded"
    );
}
