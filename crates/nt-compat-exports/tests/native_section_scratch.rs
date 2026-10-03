use syn::{visit::Visit, Item};

#[test]
fn section_frame_publication_installs_scratch_paging_before_frame_acquisition() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_section_pagein.rs"
    )).unwrap();
    let publish = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "service_publish_section_frame_from_bytes" => Some(function),
        _ => None,
    }).unwrap();
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls(Vec::new());
    calls.visit_item_fn(publish);
    let acquire = calls.0.iter().position(|call| call == "vm_frame_acquire").unwrap();
    let paging = calls.0.iter().position(|call| call == "ensure_executive_paging")
        .expect("provider maps use a different scratch window than hosted process faults");
    assert!(paging < acquire,
        "cached frame zeroing already uses the scratch page table during acquisition");
}
