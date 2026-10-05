//! Issue291 architectural regressions, not evidence that receive latency caused a boot timeout.
//! Behavioral generation/ACK tests belong beside the eventual canonical settlement owner.

use syn::{visit::Visit, Item};

const CONTINUATIONS: &str =
    include_str!("../../../components/ntos-executive/src/component_continuation.rs");
const PENDING: &str =
    include_str!("../../../components/ntos-executive/src/win32k_pending_dispatch.rs");
const HOSTED: &str =
    include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const INGRESS: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");
const RESUME: &str =
    include_str!("../../../components/ntos-executive/src/component_resume_execute.rs");
const NESTED: &str =
    include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");
const VSPACE: &str =
    include_str!("../../../components/ntos-executive/src/component_receive_vspace.rs");

#[derive(Default)]
struct Audit {
    calls: Vec<String>,
    fields: Vec<String>,
    types: Vec<String>,
    variants: Vec<String>,
}

impl<'ast> Visit<'ast> for Audit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            if let Some(last) = path.path.segments.last() {
                self.calls.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        self.types
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_type_path(self, path);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.variants
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }
}

fn function<'a>(source: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    let found = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    });
    assert!(found.is_some(), "actual native boundary must exist: {name}");
    found.unwrap()
}

fn audit(function: &syn::ItemFn) -> Audit {
    let mut audit = Audit::default();
    audit.visit_block(&function.block);
    audit
}

fn call_position(audit: &Audit, name: &str) -> usize {
    let position = audit.calls.iter().position(|call| call == name);
    assert!(position.is_some(), "actual boundary must invoke {name}");
    position.unwrap()
}

#[test]
fn receive_capacity_storage_is_durable_before_both_reservations_and_not_the_hold() {
    struct DurableReservationScope {
        found: bool,
    }
    impl<'ast> Visit<'ast> for DurableReservationScope {
        fn visit_expr_block(&mut self, expression: &'ast syn::ExprBlock) {
            let mut block = Audit::default();
            block.visit_block(&expression.block);
            let position = |name: &str| block.calls.iter().position(|call| call == name);
            if let (Some(durable), Some(first), Some(rearm)) = (
                position("enter_durable"),
                position("reserve_receive_capacity"),
                position("reserve_receive_rearm_capacity"),
            ) {
                assert!(durable < first && durable < rearm,
                    "persistent lane Vec storage must select durable allocation before either reserve");
                assert!(
                    position("park_current").is_none(),
                    "the durable capacity scope must end before physical parent parking"
                );
                self.found = true;
            }
            syn::visit::visit_expr_block(self, expression);
        }
    }
    let source = syn::parse_file(RECEIVE).unwrap();
    let prepare = function(&source, "prepare_receive_yield");
    let mut scope = DurableReservationScope { found: false };
    scope.visit_block(&prepare.block);
    assert!(scope.found,
        "both actual Receive capacity branches must share a bounded durable allocation scope; canonical Vecs cannot use an inherited transient arena");
}

#[test]
fn receive_continuation_is_distinct_from_provider_and_lpc_waits() {
    let source = syn::parse_file(CONTINUATIONS).unwrap();
    let dispatch = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Enum(item) if item.ident == "PendingComponentDispatch" => Some(item),
            _ => None,
        })
        .expect("focused component continuation enum");
    let receive = dispatch
        .variants
        .iter()
        .find(|variant| variant.ident == "Receive");
    assert!(
        receive.is_some(),
        "a receive-only pump continuation must not manufacture a ProviderWait or LPC request"
    );
    let receive = receive.unwrap();
    assert!(
        !receive.fields.is_empty(),
        "receive continuation must retain typed ownership"
    );
    let mut types = Audit::default();
    types.visit_fields(&receive.fields);
    assert!(!types
        .types
        .iter()
        .any(|name| name == "PendingProviderWaitDispatch" || name == "PendingLpcWaitDispatch"));
    let pending = syn::parse_file(PENDING).unwrap();
    let payload = pending.items.iter().find_map(|item| match item {
        Item::Struct(item) if types.types.iter().any(|name| item.ident == name.as_str()) => {
            Some(item)
        }
        _ => None,
    });
    assert!(
        payload.is_some(),
        "receive payload belongs to the focused pending dispatch owner"
    );
    let mut payload_types = Audit::default();
    payload_types.visit_item_struct(payload.unwrap());
    for required in ["PumpResult", "Win32kClientContext"] {
        assert!(
            payload_types.types.iter().any(|name| name == required),
            "receive continuation must retain original pump/accounting and client: {required}"
        );
    }
}

#[test]
fn actual_hosted_call_owns_exact_settlement_through_reply_reconciliation_and_recycle() {
    let source = syn::parse_file(HOSTED).unwrap();
    let row = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Struct(item) if item.ident == "HostedCall" => Some(item),
            _ => None,
        })
        .expect("actual hosted Call owner");
    let barrier = row.fields.iter().find(|field| {
        field
            .ident
            .as_ref()
            .is_some_and(|name| name == "receive_settlement")
    });
    assert!(barrier.is_some(),
        "the real hosted Call must retain its parent/child settlement owner, not an observation table");
    let mut barrier_type = Audit::default();
    barrier_type.visit_type(&barrier.unwrap().ty);
    assert!(barrier_type.types.iter().any(|name| name == "Option"));
    assert!(
        barrier_type
            .types
            .iter()
            .any(|name| name.contains("Settlement")),
        "a boolean or numeric reply alone is not settlement authority"
    );

    let bind = function(&source, "bind_receive_settlement");
    let mut signature = Audit::default();
    signature.visit_signature(&bind.sig);
    assert!(
        signature
            .types
            .iter()
            .any(|name| name == "LaneDispatchIdentity"),
        "binding must capture the exact parent dispatch epoch"
    );
    let bound = audit(bind);
    for required in ["admission_sequence", "reply", "bind_receive_child"] {
        call_position(&bound, required);
    }
    assert!(
        !bound
            .calls
            .iter()
            .any(|name| name == "hosted_ingress_binding"),
        "entered pump must use captured authenticated Call, not reborrow the outer handler"
    );
    assert!(
        bound.fields.iter().any(|field| field == "binding"),
        "child binding comes from the retained Call, not a caller-supplied badge"
    );

    let acknowledged = audit(function(&source, "finish_acknowledged"));
    assert!(
        call_position(&acknowledged, "finish_external_with_settlement")
            < call_position(&acknowledged, "settle_receive"),
        "Reply ACK plus checked Free reconciliation must precede settlement publication"
    );
    let recycled = audit(function(&source, "recycle_completed"));
    assert!(
        call_position(&recycled, "receive_settlement_consumed")
            < call_position(&recycled, "insert_pending"),
        "unconsumed settlement cannot disappear when its Reply or row is recycled"
    );
}

#[test]
fn settled_child_returns_typed_outer_boundary_before_receive_or_autonomous_work() {
    let source = syn::parse_file(INGRESS).unwrap();
    let receive = function(&source, "receive");
    assert!(
        matches!(&receive.sig.output, syn::ReturnType::Type(_, ty)
        if !matches!(ty.as_ref(), syn::Type::Tuple(_))),
        "internal parent restoration needs a typed outcome, not a fabricated hosted IPC tuple"
    );
    let mut returned_type = Audit::default();
    returned_type.visit_return_type(&receive.sig.output);
    let outcome = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Enum(item)
                if returned_type
                    .types
                    .iter()
                    .any(|name| item.ident == name.as_str()) =>
            {
                Some(item)
            }
            _ => None,
        })
        .expect("typed receive outcome is declared at the ingress boundary");
    let boundary = outcome
        .variants
        .iter()
        .find(|variant| variant.ident == "OuterBoundary");
    assert!(
        boundary.is_some_and(|variant| !variant.fields.is_empty()),
        "OuterBoundary must carry retained settlement authority"
    );
    let received = audit(receive);
    let settlement = call_position(&received, "take_outer_boundary");
    for later in ["take_hosted_with", "service_autonomous", "receive"] {
        assert!(
            settlement < call_position(&received, later),
            "settled parent restoration precedes {later}"
        );
    }
    assert!(
        received.variants.iter().any(|name| name == "OuterBoundary"),
        "the actual receive path must return the internal outcome"
    );
    let reply_receive = function(&source, "reply_receive");
    assert!(
        matches!(&reply_receive.sig.output, syn::ReturnType::Type(_, ty)
        if !matches!(ty.as_ref(), syn::Type::Tuple(_))),
        "reply_receive must propagate the same typed boundary after actual child ACK"
    );
}

#[test]
fn receive_resume_consumes_settlement_before_parent_restore_and_never_replays_request() {
    let source = syn::parse_file(RECEIVE).unwrap();
    let resume = function(&source, "resume_suspended_receive_component");
    let consumes_receipt = resume.sig.inputs.iter().any(|argument| {
        let syn::FnArg::Typed(argument) = argument else {
            return false;
        };
        let mut types = Audit::default();
        types.visit_type(&argument.ty);
        !matches!(argument.ty.as_ref(), syn::Type::Reference(_))
            && types.types.iter().any(|name| name.contains("Settlement"))
    });
    assert!(
        consumes_receipt,
        "resume must consume the exact child's settlement receipt"
    );
    let resumed = audit(resume);
    let restore = call_position(&resumed, "restore");
    let receive = call_position(&resumed, "component_pump_continue_receive");
    assert!(
        restore < receive,
        "restore the authenticated retained parent, then receive without sending again"
    );
    let hosted = syn::parse_file(HOSTED).unwrap();
    call_position(
        &audit(function(&hosted, "take_outer_boundary")),
        "consume_receive_settlement",
    );
    let nested = syn::parse_file(NESTED).unwrap();
    let consume = audit(function(&nested, "consume_receive_settlement"));
    call_position(&consume, "begin_restore");
    assert!(
        consume
            .fields
            .iter()
            .any(|field| field == "receive_restore"),
        "single-use permit stays in the actual Parent before outer-boundary delivery"
    );
    let restore_parent = audit(function(&nested, "restore"));
    call_position(&restore_parent, "matches_scope");
    let executor = syn::parse_file(RESUME).unwrap();
    let execute = audit(function(&executor, "run_receive"));
    assert!(
        call_position(&execute, "begin_receive_restore")
            < call_position(&execute, "resume_suspended_receive_component"),
        "the real child's sealed settlement authorizes the exact lane before native restoration"
    );
    call_position(&execute, "settlement");
    for forbidden in [
        "oldest_pending_snapshot",
        "timer_work_pending",
        "component_pump",
        "component_pump_resume_provider_wait",
        "component_pump_resume_lpc_wait",
    ] {
        assert!(!resumed.calls.iter().any(|name| name == forbidden),
            "receive resume may not use absence/timer evidence or replay an unrelated protocol: {forbidden}");
    }
}

#[test]
fn receive_admission_requires_resident_snapshot_and_actual_vspace_separation_before_park() {
    let source = syn::parse_file(RECEIVE).unwrap();
    let prepare = audit(function(&source, "prepare_receive_yield"));
    let park = call_position(&prepare, "park_current");
    for preflight in [
        "resident_read_fault_candidate",
        "peek_root",
        "validate_pair",
        "reserve_receive_capacity",
        "prepare_receive_settlement",
    ] {
        assert!(
            call_position(&prepare, preflight) < park,
            "{preflight} must precede physical parent exclusion"
        );
    }
    let source = syn::parse_file(VSPACE).unwrap();
    let peek = audit(function(&source, "peek_root"));
    call_position(&peek, "expected_child_root");
    assert!(
        !VSPACE.contains("SERVICE_DELAY_DRAIN_HANDLER") && !VSPACE.contains("SERVICE_PROCS_WORK"),
        "expected VSpace must come from shared owner observer, not hidden handler/slice alias"
    );
    let pair = audit(function(&source, "validate_pair"));
    assert_eq!(
        pair.calls
            .iter()
            .filter(|call| call.as_str() == "query")
            .count(),
        2,
        "both actual TCB bindings must match their expected roots, with physical separation"
    );
    let current = audit(function(&source, "validate_current"));
    assert!(
        call_position(&current, "capture_process_identity")
            < call_position(&current, "validate_pair")
    );
}

#[test]
fn repeated_receive_uses_exact_scope_rearm_without_disabling_the_live_invocation() {
    let source = syn::parse_file(RECEIVE).unwrap();
    call_position(
        &audit(function(&source, "prepare_receive_yield")),
        "reserve_receive_rearm_capacity",
    );
    let resumed = audit(function(&source, "resume_suspended_receive_component"));
    assert!(resumed.variants.iter().any(|variant| variant == "Reparked"));
    let executor = syn::parse_file(RESUME).unwrap();
    call_position(
        &audit(function(&executor, "run_receive")),
        "rearm_receive_owned",
    );
    assert!(!RECEIVE.contains("hosted_receive_yield = false"),
        "a receive-only continuation cannot disable all subsequent child faults of a long-lived dispatch");
}
