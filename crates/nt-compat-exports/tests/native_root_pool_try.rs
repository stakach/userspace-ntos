use syn::{visit::Visit, Item, ReturnType, Type};

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.0.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn root_api(name: &str) -> syn::ItemFn {
    for source in [
        include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs"),
        include_str!("../../../components/ntos-executive/src/win32k_subsystem/root_pool.rs"),
    ] {
        let source = syn::parse_file(source).expect("native pool source must parse");
        for item in source.items {
            if let Item::Fn(function) = item {
                if function.sig.ident == name { return function; }
            }
        }
    }
    panic!("missing typed root-only pool API: {name}");
}

fn assert_nonblocking(function: &syn::ItemFn) -> Calls {
    assert!(matches!(&function.sig.output, ReturnType::Type(_, result)
        if matches!(&**result, Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Result"))),
        "Busy must remain distinguishable from stale identity and allocation failure");
    let mut calls = Calls::default();
    calls.visit_item_fn(function);
    assert_eq!(calls.0.iter().filter(|call| *call == "try_provider_pool_lock").count(), 1,
        "one physical try-lock must cover identity validation and the entire local effect");
    for blocking in ["provider_pool_lock", "provider_metadata_pool_lock",
        "capture_provider_pool_packet", "publish_provider_pool_packet",
        "retire_pinned_root_provider_pool_packet", "allocate_root_provider_pool_allocation"]
    {
        assert!(!calls.0.iter().any(|call| call == blocking),
            "root try API must not delegate to blocking helper {blocking}");
    }
    calls
}

#[test]
fn root_capture_defers_busy_without_waiting_on_held_component() {
    let function = root_api("try_capture_root_provider_pool_packet");
    assert_nonblocking(&function);
}

#[test]
fn root_publication_defers_busy_without_waiting_on_held_component() {
    let function = root_api("try_publish_root_provider_pool_packet");
    assert_nonblocking(&function);
}

#[test]
fn root_retirement_keeps_pin_until_atomic_exact_free() {
    let function = root_api("try_retire_root_provider_pool_allocation");
    let calls = assert_nonblocking(&function);
    assert!(calls.0.iter().any(|call| call == "retire_pinned"),
        "validate and free the exact retained pin under the same acquired physical lock");
    assert!(!calls.0.iter().any(|call| call == "unpin" || call == "free"),
        "never expose an unpinned gap or free a replacement allocation");
}

#[test]
fn root_allocation_publishes_owned_exclusive_pin_under_one_try_lock() {
    let function = root_api("try_allocate_root_provider_pool_allocation");
    let calls = assert_nonblocking(&function);
    assert!(calls.0.iter().any(|call| call == "allocate"));
    assert!(calls.0.iter().any(|call| call == "pin_exclusive"),
        "root packet ownership must precede publication to a component");
}
