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
fn ticketed_release_uses_only_the_roots_immutable_inventory() {
    let native = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    let release = native.split("unsafe fn release_pending_irp_graph_component(entry: PendingIrp)")
        .nth(1).unwrap().split("unsafe fn insert_pending_irp").next().unwrap();
    let ticketed = release.split("    } else {\n        // No root ticket").next().unwrap();
    assert!(release.contains("for index in 0..member_count"),
        "a mutable completion-time PendingIrp cannot enumerate constructor allocations");
    assert!(!ticketed.contains("entry.allocation_graph()")
        && !ticketed.contains("entry.completion.completed()"),
        "ticketed release must use only the broker receipt");
    assert!(release.contains("entry.source_ticket_id != 0") && release.contains("entry.allocation_graph()"),
        "keep the independent unticketed release path");
    assert!(ledger.contains("row.graph.initial_members().get(member_index)"),
        "op9 must resolve each index from the immutable root graph");
    assert!(ledger.contains("row.graph.initial_members().len() as u64"),
        "op7 must return the immutable member count");
    assert!(ledger.contains("row.replacement.map_or(0, |identity| identity.component_address)"),
        "op7 must return its separately adopted replacement address");
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
    let member = effects
        .0
        .iter()
        .position(|name| name == "source-op9")
        .unwrap();
    let after = effects
        .0
        .iter()
        .position(|name| name == "source-op8")
        .unwrap();
    let local_pool = effects.0.iter().position(|name| name == "pool_free").unwrap();
    let file = effects.0.iter().position(|name| name == "free_file_storage").unwrap();
    assert!(before < member && member < after && after < file && after < local_pool);
    let replacement = effects
        .0
        .iter()
        .position(|name| name == "source-op10")
        .unwrap();
    assert!(before < replacement && member < replacement && replacement < after);
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
    assert_eq!(effects.0.iter().filter(|name| *name == "source-op10").count(), 1);
}

#[test]
fn bare_dispatch_return_cannot_retire_a_ticket_without_terminal_completion() {
    let native = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let consuming = native
        .split("    if let Some(consuming_state) = consuming_state {")
        .nth(1)
        .expect("native post-dispatch consuming branch")
        .split("        release_pending_irp_graph_component(completed);")
        .next()
        .expect("source-graph retirement");
    assert!(consuming.contains("completed.completion.completed().is_none()"),
        "root op7 requires a real retained IoCompleteRequest terminal; a bare return must keep its source ticket and graph");
}

#[test]
fn terminal_replacement_does_not_reject_npfs_completion_or_enter_initial_graph() {
    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    assert!(ledger.contains("capture_projected_graph_unlocked(inst, allocation, entry)"),
        "capture constructor allocations before provider dispatch");
    assert!(!ledger.contains("member.allocation.component_address == reclaim"),
        "NPFS can supply a new SystemBuffer at completion; it is not an initial member");
    let release = release();
    let mut effects = Effects::default();
    effects.visit_block(&release.block);
    assert!(effects.0.iter().any(|name| name == "source-op9"),
        "root must check exact captured generation before each initial free");
    assert!(effects.0.iter().any(|name| name == "allocation_graph"));
    let native = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(native.contains(".filter(|_| self.source_ticket_id == 0)"),
        "a provider replacement cannot enter the source ticket's original graph");
    assert!(ledger.contains("replacement: Option<SourcePoolAllocationIdentity>"),
        "retain adopted replacement generation separately from initial members");
    assert!(ledger.contains("completion.flags & IRP_DEALLOCATE_BUFFER"),
        "the completion must explicitly transfer SystemBuffer disposal");
    assert!(ledger.contains("ledger().pool_free_admission(instance_index, domain, reclaim)"),
        "a different registered source owner excludes adoption");
    assert!(ledger.contains("auxiliary().owns_pool_child_in_domain(domain, reclaim)"),
        "any retained auxiliary owner in the physical domain excludes adoption");
    assert!(ledger.contains("row.replacement = replacement"),
        "record replacement ownership before terminal retirement begins");
    assert!(native.contains("10,"),
        "native must request the exact adopted replacement release separately");
}

#[test]
fn caller_graph_release_keeps_exact_pool_generation_checks() {
    let ledger = include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
    assert!(ledger.contains("graph: CapturedGraph"));
    assert!(ledger.contains("row.graph.protects_current_member(current)"),
        "ordinary provider frees must exclude only the captured live generation");
    assert!(ledger.contains("exact_pool_identity_unlocked(inst, member_address, 1)"),
        "terminal release must revalidate the captured physical generation");
    assert!(ledger.contains("row.released_members |= bit"),
        "retain terminal ownership before physical release");
    assert!(ledger.contains("row.released_members != (1u16 << row.graph.initial_members().len()) - 1"),
        "source retirement must wait for every initial member");
}
