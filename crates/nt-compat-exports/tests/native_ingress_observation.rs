use syn::{visit::Visit, Item};

const RUNTIME: &str = include_str!("../../../components/ntos-executive/src/component_ingress_runtime.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");

fn function(source: &str, name: &str) -> syn::ItemFn {
    syn::parse_file(source)
        .unwrap()
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing read-only diagnostic function {name}"))
}

#[derive(Default)]
struct ObservationAudit {
    calls: Vec<String>,
    methods: Vec<String>,
    immutable_owners: Vec<String>,
    fields: Vec<String>,
    mutable_reference: bool,
}

impl<'ast> Visit<'ast> for ObservationAudit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_reference(&mut self, reference: &'ast syn::ExprReference) {
        self.mutable_reference |= reference.mutability.is_some();
        syn::visit::visit_expr_reference(self, reference);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        let name = value.path.segments.last().unwrap().ident.to_string();
        assert_ne!(name, "addr_of_mut", "observations must not borrow mutable owners");
        if name == "addr_of" {
            self.immutable_owners.push(value.tokens.to_string());
        }
        syn::visit::visit_macro(self, value);
    }
}

fn audit(source: &str, name: &str) -> ObservationAudit {
    let mut audit = ObservationAudit::default();
    audit.visit_item_fn(&function(source, name));
    assert!(!audit.mutable_reference, "snapshots must copy observations, not mutate owners");
    for forbidden in [
        "lanes", "owner", "resolve", "dispatch", "current_reply", "physical_source",
        "query_component_reply_binding", "take_hosted_with", "reply_hosted", "restart_hosted",
        "park_current", "restore", "pool_alloc", "receive", "admit",
    ] {
        assert!(!audit.calls.iter().any(|call| call == forbidden),
            "read-only snapshot invoked authority/effect helper {forbidden}");
    }
    audit
}

#[test]
fn component_hold_snapshot_copies_existing_exact_owners_without_native_effects() {
    let audit = audit(RUNTIME, "hold_snapshot");
    for owner in ["COMPONENT_SUSPENSIONS", "NATIVE_PEERS"] {
        assert!(audit.immutable_owners.iter().any(|value| value == owner),
            "snapshot must observe existing owner {owner}");
    }
    for method in ["running", "binding", "peer_route", "active_dispatch_identity"] {
        assert!(audit.methods.iter().any(|value| value == method),
            "snapshot omitted exact running-lane fact {method}");
    }
    assert!(audit.calls.iter().any(|value| value == "oldest_pending_snapshot"));
}

#[test]
fn pending_snapshot_uses_retained_selection_and_message_not_live_ipc_or_role_guess() {
    let audit = audit(HOSTED, "oldest_pending_snapshot");
    assert!(audit.immutable_owners.iter().any(|value| value == "CALLS"));
    assert!(audit.calls.iter().any(|value| value == "oldest_external_ingress"));
    assert!(audit.fields.iter().any(|value| value == "binding"),
        "copy the retained full caller binding, not a current role/badge lookup");
    for method in ["reply", "executor", "admission_sequence", "message", "info", "registers"] {
        assert!(audit.methods.iter().any(|value| value == method),
            "pending snapshot omitted retained fact {method}");
    }
    for forbidden in ["get_mr", "hosted_ingress_binding", "load"] {
        assert!(!audit.calls.iter().chain(audit.methods.iter()).any(|value| value == forbidden));
    }
}

#[test]
fn pump_heartbeat_observes_only_after_runtime_receive_releases_its_borrow() {
    let receive = function(PUMP, "receive");
    struct BoundaryAudit(usize);
    impl<'ast> Visit<'ast> for BoundaryAudit {
        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            let syn::Expr::Call(call) = &*expression.expr else {
                syn::visit::visit_expr_match(self, expression);
                return;
            };
            if !matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>()
                    == ["runtime", "receive"]) {
                syn::visit::visit_expr_match(self, expression);
                return;
            }
            for arm in &expression.arms {
                let syn::Pat::TupleStruct(ok) = &arm.pat else { continue; };
                let Some(syn::Pat::TupleStruct(arrival)) = ok.elems.first() else { continue; };
                if !ok.path.is_ident("Ok") || !arrival.path.segments.last()
                    .is_some_and(|segment| segment.ident == "Notification") { continue; }
                let mut audit = ObservationAudit::default();
                audit.visit_expr(&arm.body);
                let heartbeat = audit.calls.iter().position(|value| value == "census_tick_static")
                    .expect("sample the existing heartbeat after the receive borrow ends");
                let event = audit.calls.iter().position(|value| value == "pump_handle_executive_event_badge").unwrap();
                assert!(heartbeat < event, "observe before event processing may nest");
                assert_eq!(audit.calls.iter().filter(|value| *value == "census_tick_static").count(), 1);
                self.0 += 1;
            }
            syn::visit::visit_expr_match(self, expression);
        }
    }
    let mut boundaries = BoundaryAudit(0);
    boundaries.visit_item_fn(&receive);
    assert_eq!(boundaries.0, 1, "pin the actual released-borrow notification boundary");
}

#[test]
fn existing_census_prints_copied_hold_snapshot_without_new_age_ledger() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let mut calls = ObservationAudit::default();
    calls.visit_item_fn(&function(main, "print_periodic_census_heartbeat"));
    assert!(calls.calls.iter().any(|value| value == "print_hold_snapshot"),
        "the existing census timestamp must accompany the exact hold observation");
}
