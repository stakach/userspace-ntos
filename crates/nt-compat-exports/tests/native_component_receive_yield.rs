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
const RESUME_OUTER: &str =
    include_str!("../../../components/ntos-executive/src/component_resume.rs");
const NESTED: &str =
    include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");
const VSPACE: &str =
    include_str!("../../../components/ntos-executive/src/component_receive_vspace.rs");
const HOSTED_RUNTIME: &str =
    include_str!("../../../components/ntos-executive/src/hosted_thread_runtime.rs");
const SERVICE_LOOP: &str =
    include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn child_created_during_unrelated_ingress_is_selected_before_fault_observation() {
    let before_admission = SERVICE_LOOP
        .split("let event_runtime = match (ingress")
        .next()
        .expect("hosted event admission");
    let late_boundary = before_admission
        .rsplit("finalize_service_loop_state(&mut nt_handler)")
        .next()
        .expect("late work checkpoint");
    assert!(late_boundary.contains("receive_child_pending()"));
    assert!(late_boundary.contains("receive_child_is_current("));
    assert!(late_boundary.contains("defer_hosted_delivery("));
    assert!(late_boundary.contains("component_recv!("));
    let defer = HOSTED.split("pub(crate) unsafe fn defer_hosted_delivery(")
        .nth(1).expect("exact unexecuted delivery handoff");
    assert!(defer.contains("receive_child_pending()"));
    assert!(defer.contains("receive_child_is_current("));
}

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

    fn visit_pat(&mut self, pat: &'ast syn::Pat) {
        let path = match pat {
            syn::Pat::Path(path) => Some(&path.path),
            syn::Pat::TupleStruct(path) => Some(&path.path),
            _ => None,
        };
        if let Some(path) = path {
            self.variants
                .extend(path.segments.iter().map(|part| part.ident.to_string()));
        }
        syn::visit::visit_pat(self, pat);
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

fn oldest_pending_selection() -> &'static str {
    HOSTED
        .split("pub(super) unsafe fn oldest_pending_snapshot()")
        .nth(1)
        .expect("Receive selection boundary")
        .split("let row = rows[index]")
        .next()
        .expect("selection must precede snapshot construction")
}

#[test]
fn sealed_receive_child_delivery_preempts_ordinary_older_call() {
    let selection = HOSTED
        .split("pub(crate) unsafe fn take_hosted_with(")
        .nth(1)
        .expect("hosted delivery selector")
        .split("/// Return an unexecuted root delivery")
        .next()
        .expect("delivery selector boundary");
    let pending = selection.find("let pending_receive = receive_child_pending();")
        .expect("snapshot sealed Receive ownership before choosing a root delivery");
    let branch = selection.find("if pending_receive {")
        .expect("a sealed child must exclude unrelated ordinary Calls");
    let child = selection.find("let receive = row.receive_settlement.as_ref()?;")
        .expect("only a row with the sealed child owner may be delivered");
    let ticket = selection.find("receive.barrier.admission_key() != call.admission_key()")
        .expect("delivery must authenticate the exact child admission ticket");
    let ordinary = selection.find("} else if row.receive_settlement.is_some() {")
        .expect("ordinary selection must exclude a prepared child");
    let selected = selection.find("Some((index, call))")
        .expect("the authenticated row is the only selected delivery");
    assert!(pending < branch && branch < child && child < ticket && ticket < ordinary
        && ordinary < selected,
        "the sealed child filter must run before oldest-admission selection");
    assert!(selection[child..ordinary].contains("receive.transferred")
        && selection[child..ordinary].contains("receive.parent.is_none()"),
        "delivery requires an untransferred child with its retained physical parent");
    let root_receive = INGRESS.split("pub(crate) unsafe fn receive(").nth(1)
        .expect("root receive delivery boundary");
    assert!(root_receive.contains("take_hosted_with("),
        "root delivery must use the sealed-child-priority selector");
}

#[test]
fn receive_selection_excludes_undelivered_prepared_child() {
    let selection = oldest_pending_selection();
    assert!(
        selection.contains("settlement_prepared: row.receive_settlement.is_some()"),
        "native selection must pass the sealed settlement state into the pure selector"
    );
}

#[test]
fn receive_selection_excludes_stop_entered_child() {
    let selection = oldest_pending_selection();
    assert!(
        selection.contains("oldest_receive_external_ingress("),
        "native selection must delegate Call park eligibility to the pure Receive selector"
    );
}

#[test]
fn selected_receive_child_excludes_pre_reply_sibling_resume() {
    let source = syn::parse_file(RESUME_OUTER).unwrap();
    let drain = function(&source, "drain_hosted_ready");
    let first = drain.block.stmts.first().expect("pre-reply resume exclusion");
    let syn::Stmt::Expr(syn::Expr::If(guard), _) = first else {
        panic!("Receive child exclusion must precede any terminal or sibling pump work");
    };
    let mut condition = Audit::default();
    condition.visit_expr(&guard.cond);
    assert!(condition.calls.iter().any(|name| name == "receive_child_pending"),
        "a selected child must settle before pre-reply drain can run another provider lane");
    assert!(matches!(guard.then_branch.stmts.last(), Some(syn::Stmt::Expr(
        syn::Expr::Return(_), _
    ))), "child exclusion must leave the drain before it selects a sibling");
}

#[test]
fn receive_child_claimed_during_resume_pass_blocks_the_next_sibling() {
    let source = syn::parse_file(RESUME_OUTER).unwrap();
    for name in ["drain_hosted_ready", "run_outer"] {
        let resume = function(&source, name);
        let loop_body = resume.block.stmts.iter().find_map(|stmt| match stmt {
            syn::Stmt::Expr(syn::Expr::Loop(loop_expr), _) => Some(&loop_expr.body),
            _ => None,
        }).unwrap_or_else(|| panic!("{name} must recheck child ownership each resume iteration"));
        let Some(syn::Stmt::Expr(syn::Expr::If(guard), _)) = loop_body.stmts.first() else {
            panic!("{name} must check the claimed child before the next candidate");
        };
        let mut condition = Audit::default();
        condition.visit_expr(&guard.cond);
        assert!(condition.calls.iter().any(|call| call == "receive_child_pending"),
            "{name} must observe a child claimed by the preceding provider resume");
        assert!(matches!(guard.then_branch.stmts.last(), Some(syn::Stmt::Expr(
            syn::Expr::Break(_), _
        ))), "{name} must leave the resume pass while the exact child is pending");
        let mut remainder = Audit::default();
        for stmt in loop_body.stmts.iter().skip(1) {
            remainder.visit_stmt(stmt);
        }
        assert!(remainder.calls.iter().any(|call| call == "next_in_pass"),
            "{name} must select its next candidate only after the child check");
    }
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
fn receive_guard_fault_uses_the_same_sealed_child_and_root_stack_policy() {
    let source = syn::parse_file(RECEIVE).unwrap();
    let prepare = audit(function(&source, "prepare_receive_yield"));
    let park = call_position(&prepare, "park_current");
    assert!(call_position(&prepare, "stack_guard_fault_candidate") < park);
    assert!(call_position(&prepare, "validate_pair") < park);
    assert!(call_position(&prepare, "prepare_receive_settlement") < park);

    let candidate = audit(function(&source, "stack_guard_fault_candidate"));
    assert!(call_position(&candidate, "hosted_thread_user_stack_for_binding")
        < call_position(&candidate, "extent_at"));
    let runtime = syn::parse_file(HOSTED_RUNTIME).unwrap();
    let stack = audit(function(&runtime, "hosted_thread_user_stack_for_binding"));
    call_position(&stack, "executable_by_badge");
    call_position(&stack, "binding");
    assert!(stack.fields.iter().any(|field| field == "user_stack_allocation_base"));
    assert!(stack.fields.iter().any(|field| field == "user_stack_base"));

    let hosted = syn::parse_file(HOSTED).unwrap();
    let settlement = audit(function(&hosted, "receive_child_observation"));
    assert!(settlement.fields.iter().any(|field| field == "observation"));
    assert!(settlement.calls.iter().any(|call| call == "admission_key"));

    let root = syn::parse_file(include_str!("../../../components/ntos-executive/src/service_sec_image.rs")).unwrap();
    let service = audit(function(&root, "service_receive_child_fault"));
    call_position(&service, "service_hosted_stack_growth");
    call_position(&service, "service_captured_private_read_fault");
    assert!(service.variants.iter().any(|variant| variant == "StackGuard"));
    assert!(service.variants.iter().any(|variant| variant == "Grown"));
}

#[test]
fn receive_native_image_read_and_execute_are_deny_only_typed_child_captures() {
    let source = syn::parse_file(RECEIVE).unwrap();
    let prepare = audit(function(&source, "prepare_receive_yield"));
    assert!(call_position(&prepare, "native_image_fault_candidate")
        < call_position(&prepare, "park_current"));
    assert!(prepare.variants.iter().any(|variant| variant == "NativeImage"));

    let candidate = audit(function(&source, "native_image_fault_candidate"));
    assert!(candidate.fields.iter().any(|field| field == "process"));
    call_position(&candidate, "x86_user_image_receive_fault");
    call_position(&candidate, "process_committed_mapping_basic_information");
    assert!(candidate.variants.iter().any(|variant| variant == "MEM_IMAGE"));
    assert!(candidate.variants.iter().any(|variant| variant == "MEM_COMMIT"));

    struct RootImageAccess(bool);
    impl<'ast> Visit<'ast> for RootImageAccess {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "service_native_image_page_residency" {
                self.0 |= call.args.iter().nth(2).is_some_and(|argument| {
                    matches!(argument, syn::Expr::Field(field)
                        if matches!(&field.member, syn::Member::Named(name) if name == "access")
                            && matches!(field.base.as_ref(), syn::Expr::Path(path)
                                if path.path.is_ident("image")))
                });
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let root = syn::parse_file(include_str!("../../../components/ntos-executive/src/service_sec_image.rs")).unwrap();
    let mut root_access = RootImageAccess(false);
    root_access.visit_item_fn(function(&root, "service_receive_child_fault"));
    assert!(root_access.0, "root must use the validated captured read or execute access");
}

#[test]
fn receive_native_image_writecopy_carries_protection_observation_to_exact_root_view() {
    let source = syn::parse_file(RECEIVE).unwrap();
    let candidate = audit(function(&source, "native_image_fault_candidate"));
    call_position(&candidate, "x86_user_image_receive_fault");
    call_position(&candidate, "process_committed_mapping_basic_information");
    let capture = source.items.iter().find_map(|item| match item {
        Item::Struct(row) if row.ident == "NativeImageFaultCapture" => Some(row),
        _ => None,
    }).expect("typed image child capture");
    assert!(capture.fields.iter().any(|field| field.ident.as_ref().is_some_and(|name| name == "observation")));

    let root = syn::parse_file(include_str!("../../../components/ntos-executive/src/service_sec_image.rs")).unwrap();
    let service = audit(function(&root, "service_receive_child_fault"));
    call_position(&service, "capture_process_identity");
    call_position(&service, "process_committed_mapping_basic_information");
    assert!(service.fields.iter().any(|field| field == "information"),
        "root must reject a mapping changed since the child capture");
    assert!(service.fields.iter().any(|field| field == "observation"),
        "root must pass the captured Protection observation to the image pager");
    call_position(&service, "service_native_image_page_residency");
}

#[test]
fn receive_image_fault_routes_exact_main_executable_after_native_view_miss() {
    let root = syn::parse_file(SERVICE_LOOP).unwrap();
    let receive = audit(function(&root, "service_receive_child_fault"));
    let native = call_position(&receive, "service_native_image_page_residency");
    let legacy = call_position(&receive, "service_legacy_image_page_residency");
    assert!(native < legacy, "a native Section view retains first ownership claim");
    assert!(receive.fields.iter().any(|field| field == "observation"));

    let legacy_service = audit(function(&root, "service_legacy_image_page_residency"));
    for required in ["for_process", "process_committed_image_allocation",
        "capture", "pe_by_pi", "legacy_image_receive_fault_status",
        "service_image_page_residency"] {
        call_position(&legacy_service, required);
    }
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
