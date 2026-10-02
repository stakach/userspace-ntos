use syn::{visit::Visit, Item};

#[test]
fn component_heap_faults_use_owned_demand_reservation_before_generic_fallback() {
    let source = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    assert!(source.contains("DemandZeroed"), "heap reservation must be declared by the generic region engine");
    let parsed = syn::parse_file(source).unwrap();
    let function = parsed.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "pump_service_vm_fault" => Some(function),
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
    calls.visit_item_fn(function);
    let owned = calls.0.iter().position(|name| name == "service_fault")
        .expect("component heap faults need retained physical mapping ownership");
    let generic = calls.0.iter().position(|name| name == "pump_service_generic_fault").unwrap();
    assert!(owned < generic);
    let runtime = include_str!("../../../components/ntos-executive/src/component_ingress_runtime.rs");
    assert!(runtime.contains("component_heap::bind_source"),
        "worker registration must bind the exact physical source generation before serving faults");
    let allocator = include_str!("../../../components/ntos-executive/src/allocator.rs");
    assert!(allocator.contains("initialize_reserved_heap"),
        "component reservation and initial page commitment are distinct");
}
