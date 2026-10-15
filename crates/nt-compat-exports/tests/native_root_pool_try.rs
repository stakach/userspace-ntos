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

fn assert_root_admission_before_shared_access(function: &syn::ItemFn) {
    let mut calls = Calls::default();
    calls.visit_item_fn(function);
    let admission = calls.0.iter().position(|call| call == "current_win32k_provider_domain")
        .expect("root must consult its canonical provider catalog before touching optional GUI mappings");
    let shared = calls.0.iter().position(|call| matches!(call.as_str(),
        "registered_provider_wait_domain" | "provider_pool_ready" | "provider_pool_lock"
        | "try_provider_pool_lock" | "retire_pinned_root_provider_pool_packet"
        | "provider_pool_census"))
        .expect("actual shared pool access remains present after admission");
    assert!(admission < shared, "unadmitted root calls must refuse before reading shared metadata");
    struct EarlyRefusal(bool);
    impl<'ast> Visit<'ast> for EarlyRefusal {
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            let mut calls = Calls::default();
            calls.visit_expr(&expression.expr);
            self.0 |= calls.0.iter().any(|call| call == "current_win32k_provider_domain");
            syn::visit::visit_expr_try(self, expression);
        }
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let mut calls = Calls::default();
            calls.visit_expr(&expression.cond);
            struct Returns(bool);
            impl<'ast> Visit<'ast> for Returns {
                fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) { self.0 = true; }
            }
            let mut returns = Returns(false);
            returns.visit_block(&expression.then_branch);
            self.0 |= returns.0 && calls.0.iter().any(|call| call == "current_win32k_provider_domain");
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut refusal = EarlyRefusal(false);
    refusal.visit_item_fn(function);
    assert!(refusal.0, "missing canonical admission must return without native pool effects");
}

#[test]
fn root_pool_entries_refuse_unadmitted_gui_before_shared_metadata() {
    for name in ["allocate_root_provider_pool_allocation", "try_allocate_root_provider_pool_allocation",
        "validate_packet_range", "retire_root_provider_pool_allocation"] {
        assert_root_admission_before_shared_access(&root_api(name));
    }
    // Packet capture/publication/retirement share the same guarded validation boundary.
    for name in ["try_capture_root_provider_pool_packet", "try_publish_root_provider_pool_packet",
        "try_retire_root_provider_pool_allocation"] {
        let mut calls = Calls::default();
        calls.visit_item_fn(&root_api(name));
        let validate = calls.0.iter().position(|call| call == "validate_packet_range")
            .expect("packet entry retains canonical range/provider preflight");
        let lock = calls.0.iter().position(|call| call == "try_provider_pool_lock").unwrap();
        assert!(validate < lock);
    }
}

#[test]
fn root_census_does_not_probe_an_optional_unmapped_gui_pool() {
    let census = root_api("root_provider_pool_census");
    assert!(matches!(&census.sig.output, ReturnType::Type(_, result)
        if matches!(&**result, Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"))),
        "absent consumer is unavailable, not a fabricated zero pool census");
    assert_root_admission_before_shared_access(&census);
    let main = syn::parse_file(include_str!("../../../components/ntos-executive/src/main.rs")).unwrap();
    let mut calls = Calls::default();
    calls.visit_file(&main);
    assert!(calls.0.iter().any(|call| call == "root_provider_pool_census"));
    assert!(!calls.0.iter().any(|call| call == "provider_pool_census"),
        "executive census must not use the child-side shared-memory helper directly");
}
