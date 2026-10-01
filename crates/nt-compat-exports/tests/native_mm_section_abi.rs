//! Kernel Section entry points must preserve the complete NT call contract.

use syn::{Item, ItemFn};

fn function(source: &str, name: &str) -> ItemFn {
    syn::parse_file(source).unwrap().items.into_iter().find_map(|item| {
        match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }
    }).unwrap_or_else(|| panic!("missing native function {name}"))
}

#[test]
fn mm_create_section_accepts_all_eight_native_arguments() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let create = function(source, "s_mm_create_section");
    assert_eq!(create.sig.inputs.len(), 8,
        "MmCreateSection must not discard protection, attributes, FileHandle or FileObject");
}

#[test]
fn section_metadata_dispatch_uses_kernel_transport_not_user_wait_identity() {
    use syn::visit::Visit;
    struct KernelQuery(usize);
    impl<'ast> Visit<'ast> for KernelQuery {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "build_and_dispatch_external_to_device" {
                self.0 += 1;
                assert!(matches!(&call.args[4], syn::Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_digits() == "0")),
                    "kernel metadata IRPs must not impersonate a client wait requestor");
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let source = include_str!("../../../components/ntos-executive/src/provider_section_broker.rs");
    let file = syn::parse_file(source).unwrap();
    let mut query = KernelQuery(0);
    query.visit_file(&file);
    assert_eq!(query.0, 1);
}
