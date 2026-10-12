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
            syn::ImplItem::Fn(function) if function.sig.ident == "allocation_pointers" => Some(function),
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
        .position(|name| name == "source-op9")
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
    assert_eq!(effects.0.iter().filter(|name| *name == "source-op9").count(), 1);
}

#[test]
fn ticketed_terminal_pool_members_are_released_by_the_root_broker() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    assert!(source.contains("released_members |= bit"),
        "record terminal ownership before the physical free");
    assert!(source.contains("exact_pool_identity_unlocked(inst, member_address, 1)"),
        "verify capacity and generation of the exact captured member");
    assert!(source.contains("hosted_instance_pool_free_unlocked(inst, member_address)"),
        "only the root broker may retire the verified member");
    assert!(source.contains("row.released_members != (1u16 << row.graph.initial_members().len()) - 1"),
        "op8 must wait for every captured member to settle");
}

#[test]
fn projected_irp_registration_captures_every_initial_physical_member() {
    let source = include_str!(
        "../../../components/ntos-executive/src/hosted_source_irp_ledger.rs"
    );
    let parsed = syn::parse_file(source).unwrap();
    let capture = parsed.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "capture_projected_graph_unlocked" => {
            Some(function)
        }
        _ => None,
    }).expect("caller projection must capture its graph before provider entry");
    let mut effects = Effects::default();
    effects.visit_block(&capture.block);
    assert!(effects.0.iter().any(|name| name == "allocation_graph"));
    assert!(effects.0.iter().any(|name| name == "exact_pool_identity_unlocked"));
    assert!(effects.0.iter().any(|name| name == "prepare"));

    assert!(source.contains("graph: CapturedGraph"),
        "the issued ticket must retain the non-Copy generation-bearing graph");
    assert!(source.contains("capture_projected_graph_unlocked(inst, allocation, entry)"),
        "source registration must capture the graph while its root pool lock is held");
}

#[test]
fn generic_pool_free_checks_the_captured_physical_member() {
    let parsed = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_source_irp_ledger.rs"
    )).unwrap();
    let function = |name: &str| parsed.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap();
    let mut broker = Effects::default();
    broker.visit_block(&function("caller_graph_protects_current_member_unlocked").block);
    assert!(broker.0.iter().any(|name| name == "pool_range_identity_unlocked"));
    assert!(broker.0.iter().any(|name| name == "protects_current_member"));

    let mut retirement = Effects::default();
    retirement.visit_block(&function("retire_allocation").block);
    assert!(retirement.0.iter().any(|name| name == "caller_graph_protects_current_member_unlocked"),
        "generic pool free must consult captured child generations before freeing");
}
