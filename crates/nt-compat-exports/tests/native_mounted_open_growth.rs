use syn::{visit::Visit, Expr, ImplItem, Item};

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/mounted_volume_backend.rs"
    )).unwrap()
}

fn method(name: &str) -> syn::ImplItemFn {
    source().items.into_iter().find_map(|item| match item {
        Item::Impl(item) => item.items.into_iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }),
        _ => None,
    }).unwrap_or_else(|| panic!("missing method {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn mounted_open_limit_is_the_shared_directory_handle_index_schema_not_64() {
    let cap = source().items.into_iter().find_map(|item| match item {
        Item::Const(item) if item.ident == "OPEN_CAP" => Some(item.expr),
        _ => None,
    }).expect("explicit handle index schema bound");
    assert!(matches!(&*cap, Expr::Path(path) if path.path.segments.len() == 2
        && path.path.segments[0].ident == "nt_fs"
        && path.path.segments[1].ident == "MAX_FAT_OPEN_SLOTS"),
        "the filesystem crate must own the index-schema ceiling");
    let mut calls = Calls::default();
    calls.visit_impl_item_fn(&method("new"));
    assert!(!calls.0.iter().any(|call| matches!(call.as_str(), "resize" | "try_reserve_exact")),
        "mount construction must not preallocate descriptions for every representable handle");
}

#[test]
fn mounted_create_reserves_growing_binding_before_native_backing_effects() {
    let mut reservation = Calls::default();
    reservation.visit_impl_item_fn(&method("reserve_open_context"));
    for required in ["reserve", "try_reserve", "resize", "cancel"] {
        assert!(reservation.0.iter().any(|call| call == required),
            "fallible binding admission must reserve/rollback the exact context: {required}");
    }
    for name in ["create_installed", "create_installed_directory", "create_overlay"] {
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(&method(name));
        assert_eq!(calls.0.first().map(String::as_str), Some("reserve_open_context"),
            "{name} must admit exact context and growing binding before backing effects");
        assert!(!calls.0.iter().any(|call| call == "reserve"),
            "{name} cannot bypass binding capacity admission with direct context reservation");
    }
}
