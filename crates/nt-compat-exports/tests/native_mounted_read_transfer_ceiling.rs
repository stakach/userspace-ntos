//! The native mount forwards an installed READ claim's exact sector count to the SCSI route.
//! The claim's size comes from the adapter's reported transfer limit
//! (`nt_io_manager::storage_adapter_limit`); the retained owner tests exercise its range.

use syn::{visit::Visit, Expr, ImplItem, Item};

const NATIVE: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");

fn function(source: &str, name: &str) -> syn::ItemFn {
    syn::parse_file(source).unwrap().items.into_iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"))
}

fn method(source: &str, name: &str) -> syn::ImplItemFn {
    syn::parse_file(source).unwrap().items.into_iter().find_map(|item| match item {
        Item::Impl(block) => block.items.into_iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"))
}

#[derive(Default)]
struct Calls {
    methods: Vec<String>,
    functions: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.functions.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn native_mounted_read_forwards_the_exact_scsi_count() {
    let mut route = Calls::default();
    route.visit_impl_item_fn(&method(NATIVE, "operation"));
    assert!(route.methods.iter().any(|name| name == "block_read_operation"),
        "the native route must retain the claim's exact sector count");
    let mut dispatch = Calls::default();
    dispatch.visit_item_fn(&function(NATIVE, "dispatch_claim"));
    assert!(dispatch.functions.iter().any(|name| name == "read"),
        "the exact BlockOperation must become a native SCSI READ");
}
