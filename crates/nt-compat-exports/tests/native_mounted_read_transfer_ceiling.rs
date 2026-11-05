//! Keep the live installed READ claim on the crate's verified 32-sector path.
//! The retained owner tests exercise the range and completion contract; this test checks that
//! the native mount actually uses it and forwards its exact sector count to the SCSI route.

use syn::{visit::Visit, Expr, ImplItem, Item};

const VOLUME: &str = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
const NATIVE: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const READS: &str = include_str!("../../nt-fs/src/mounted_installed_read.rs");

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
fn native_mounted_read_uses_verified_32_sector_claim_and_exact_scsi_count() {
    let mut owner = Calls::default();
    owner.visit_impl_item_fn(&method(READS, "claim_next"));
    assert_eq!(owner.methods, ["claim_next_bounded"]);
    let default = method(READS, "claim_next");
    assert!(matches!(default.block.stmts.as_slice(),
        [syn::Stmt::Expr(Expr::MethodCall(call), None)]
            if call.method == "claim_next_bounded"
                && matches!(call.args.first(), Some(Expr::Lit(lit))
                    if matches!(&lit.lit, syn::Lit::Int(value)
                        if value.base10_parse::<u32>().ok() == Some(32)))));

    let mut live = Calls::default();
    live.visit_item_fn(&function(VOLUME, "claim_mounted_read_sectors"));
    assert_eq!(live.methods.iter().filter(|name| *name == "claim_next").count(), 1,
        "the native mount must claim through the verified full-range owner");
    assert!(!live.methods.iter().any(|name| name == "claim_next_bounded"),
        "a separate native cap would silently narrow the proven range");

    let mut route = Calls::default();
    route.visit_impl_item_fn(&method(NATIVE, "operation"));
    assert!(route.methods.iter().any(|name| name == "block_read_operation"),
        "the native route must retain the claim's exact sector count");
    let mut dispatch = Calls::default();
    dispatch.visit_item_fn(&function(NATIVE, "dispatch_claim"));
    assert!(dispatch.functions.iter().any(|name| name == "read"),
        "the exact BlockOperation must become a native SCSI READ");
}
