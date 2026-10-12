use syn::visit::Visit;

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .unwrap()
}

fn release() -> syn::ItemFn {
    source()
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "release_pending_irp_graph_component" =>
            {
                Some(function)
            }
            _ => None,
        })
        .unwrap()
}

#[derive(Default)]
struct Effects(Vec<String>);
impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let name = path.path.segments.last().unwrap().ident.to_string();
            if name == "call_on4_raw" {
                let Some(syn::Expr::Lit(operation)) = call.args.iter().nth(1) else {
                    panic!("literal source-ticket operation");
                };
                let syn::Lit::Int(operation) = &operation.lit else {
                    panic!("source-ticket operation integer");
                };
                self.0.push(format!(
                    "source-op{}",
                    operation.base10_parse::<u64>().unwrap()
                ));
            } else {
                self.0.push(name);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn pending_irp_release_uses_the_shared_exact_allocation_inventory() {
    let mut effects = Effects::default();
    effects.visit_block(&release().block);
    assert!(
        effects.0.iter().any(|name| name == "allocation_graph"),
        "native release must use the same ten-candidate inventory as returned-pointer exclusion"
    );
    assert!(effects.0.iter().any(|name| name == "allocations"));
    assert!(
        !effects.0.iter().any(|name| name == "contains"),
        "native must not retain a second dedup geometry"
    );
}

#[test]
fn pending_irp_inventory_reads_only_the_retained_completed_reclaim() {
    let parsed = source();
    let snapshot = parsed.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("PendingIrp")) { return None; }
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "allocation_graph" => Some(function),
            _ => None,
        })
    }).expect("native graph snapshot delegated from its actual retained owner");
    let mut effects = Effects::default();
    effects.visit_block(&snapshot.block);
    assert!(effects.0.iter().any(|name| name == "completed"));
    assert!(!effects
        .0
        .iter()
        .any(|name| matches!(name.as_str(), "read_volatile" | "read_unaligned")));
    struct Fields(Vec<String>);
    impl<'ast> Visit<'ast> for Fields {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if let syn::Member::Named(name) = &field.member {
                self.0.push(name.to_string());
            }
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut fields = Fields(Vec::new());
    fields.visit_block(&snapshot.block);
    for name in [
        "reclaim",
        "mdl",
        "aux_data",
        "data",
        "create_parameters",
        "create_access_state",
        "create_security_context",
        "pnp_resource_list",
        "irp",
        "file_object",
        "owns_fo",
    ] {
        assert!(
            fields.0.iter().any(|field| field == name),
            "exact retained {name} must enter the snapshot"
        );
    }
}

#[test]
fn source_ticket_operations_still_bracket_native_free_order() {
    let mut effects = Effects::default();
    effects.visit_block(&release().block);
    let before = effects
        .0
        .iter()
        .position(|name| name == "source-op7")
        .unwrap();
    let file = effects
        .0
        .iter()
        .position(|name| name == "free_file_storage")
        .unwrap();
    let pool = effects
        .0
        .iter()
        .position(|name| name == "pool_free")
        .unwrap();
    let after = effects
        .0
        .iter()
        .position(|name| name == "source-op8")
        .unwrap();
    assert!(before < file && before < pool && file < after && pool < after);
    assert_eq!(
        effects
            .0
            .iter()
            .filter(|name| *name == "source-op7")
            .count(),
        1
    );
    assert_eq!(
        effects
            .0
            .iter()
            .filter(|name| *name == "source-op8")
            .count(),
        1
    );
}
