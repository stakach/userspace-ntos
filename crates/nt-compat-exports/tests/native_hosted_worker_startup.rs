use syn::{parse::Parser, visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    })
}

#[derive(Default)]
struct Observe {
    calls: Vec<String>,
    fields: Vec<String>,
    paths: Vec<String>,
}
impl<'ast> Visit<'ast> for Observe {
    fn visit_macro(&mut self, expression: &'ast syn::Macro) {
        let name = expression.path.segments.last().unwrap().ident.to_string();
        let expressions = if name == "assert" || name == "assert_eq" || name == "assert_ne" {
            syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated
                .parse2(expression.tokens.clone())
                .ok()
                .map(|items| items.into_iter().collect::<Vec<_>>())
        } else if name == "matches" {
            let parser = |input: syn::parse::ParseStream<'_>| -> syn::Result<Vec<Expr>> {
                let value = input.parse::<Expr>()?;
                input.parse::<syn::Token![,]>()?;
                syn::Pat::parse_multi_with_leading_vert(input)?;
                let mut expressions = vec![value];
                if input.peek(syn::Token![if]) {
                    input.parse::<syn::Token![if]>()?;
                    expressions.push(input.parse::<Expr>()?);
                }
                if input.peek(syn::Token![,]) {
                    input.parse::<syn::Token![,]>()?;
                }
                Ok(expressions)
            };
            parser.parse2(expression.tokens.clone()).ok()
        } else {
            None
        };
        if let Some(expressions) = expressions {
            for expression in expressions {
                let mut nested = Observe::default();
                nested.visit_expr(&expression);
                self.calls.extend(nested.calls);
                self.fields.extend(nested.fields);
                self.paths.extend(nested.paths);
            }
        }
        syn::visit::visit_macro(self, expression);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
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
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths
            .push(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_expr_path(self, path);
    }
}

#[test]
fn pump_validates_actual_hosted_ready_words_before_recording_startup_receipt() {
    let file = source("spawn_hosts.rs");
    #[derive(Default)]
    struct ReadyCall {
        validated_words: bool,
        order: Vec<&'static str>,
    }
    impl<'ast> Visit<'ast> for ReadyCall {
        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "startup_stack_receipt"))
            {
                self.order.push("receipt");
            }
            syn::visit::visit_expr_assign(self, assignment);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "startup_expected"))
            {
                self.order.push("expected");
            }
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "validate_startup_ready"))
            {
                assert_eq!(call.args.len(), 2);
                let mut words = Observe::default();
                words.visit_expr(&call.args[1]);
                for required in ["m0", "m1", "m2", "m3", "m4"] {
                    assert!(
                        words.fields.iter().any(|name| name == required),
                        "startup admission must consume actual received {required}"
                    );
                }
                self.validated_words = true;
                self.order.push("validate");
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut call = ReadyCall::default();
    for item in &file.items {
        if let Item::Fn(function) = item {
            let mut fields = Observe::default();
            fields.visit_block(&function.block);
            if fields
                .fields
                .iter()
                .any(|name| name == "startup_stack_receipt")
                && fields.paths.iter().any(|name| name == "expected_info")
            {
                call.visit_block(&function.block);
            }
        }
    }
    assert!(
        call.validated_words,
        "IRP DispatchWorker bootstrap is currently rejected by the win32k-only startup gate"
    );
    assert!(
        call.order.iter().position(|event| *event == "validate")
            < call.order.iter().position(|event| *event == "receipt"),
        "validate actual READY tuple before publishing startup receipt"
    );
    assert!(
        call.order.iter().position(|event| *event == "expected")
            < call.order.iter().position(|event| *event == "validate"),
        "derive expected protocol independently of received payload before validation"
    );
}

#[test]
fn hosted_ready_admission_uses_retained_physical_bootstrap_and_current_reply() {
    let file = source("hosted_source_completion_lane.rs");
    let helper = function(&file, "validate_startup_ready")
        .expect("dedicated exact Hosted DispatchWorker startup policy must be live");
    let mut observe = Observe::default();
    observe.visit_block(&helper.block);
    assert!(observe.calls.iter().any(|name| name == "startup_expected"));
    observe.visit_block(&function(&file, "startup_expected").unwrap().block);
    for required in [
        "channel_route",
        "physical_source",
        "current_reply",
        "dispatch",
    ] {
        assert!(
            observe.calls.iter().any(|name| name == required),
            "startup admission lacks exact retained {required}"
        );
    }
    assert!(observe.paths.iter().any(|name| name == "Preparing"));
    for required in [
        "tcb",
        "pml4",
        "domain",
        "route",
        "ordinal",
        "component_shared",
        "executive_shared",
        "cnode",
        "startup_dispatch",
    ] {
        assert!(
            observe.fields.iter().any(|name| name == required),
            "startup must validate retained physical/bank identity: {required}"
        );
    }
    assert!(
        !observe.fields.iter().any(|name| name == "reply_cap"),
        "immutable channel Reply snapshot is not authority after bootstrap fault rotation"
    );
}

#[test]
fn scheduler_settles_validated_startup_with_exact_protocol_and_current_reply() {
    let file = source("component_scheduler.rs");
    let helper = function(&file, "hosted_component_pump_inner").unwrap();
    let mut observe = Observe::default();
    observe.visit_block(&helper.block);
    assert!(observe
        .fields
        .iter()
        .any(|name| name == "startup_stack_receipt"));
    for required in [
        "validate_startup_ready",
        "current_reply",
        "complete_protocol",
        "complete",
    ] {
        assert!(
            observe.calls.iter().any(|name| name == required),
            "startup settlement and ordinary zero-word completion must remain distinct: {required}"
        );
    }
    struct Protocol(bool);
    impl<'ast> Visit<'ast> for Protocol {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "complete_protocol"))
            {
                assert_eq!(call.args.len(), 5);
                assert!(
                    matches!(&call.args[4], Expr::Reference(reference)
                    if matches!(&*reference.expr, Expr::Path(path) if path.path.is_ident("words"))),
                    "settle the exact received-and-validated startup tuple"
                );
                self.0 = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut protocol = Protocol(false);
    protocol.visit_block(&helper.block);
    assert!(protocol.0);
}

#[test]
fn serviced_scheduler_yield_blocks_on_exact_worker_receive_despite_renewed_timer_demand() {
    // The executive runs above its priority-100 workers. A nonblocking poll alone cannot let a
    // worker execute READY while timer demand keeps the executive runnable. The first checkpoint
    // may poll; after the scheduler has serviced that demand, the retained receive must block.
    let file = source("component_shared_pump.rs");
    let receive = function(&file, "receive").expect("shared component receive boundary");
    let loop_body = receive.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Expr(Expr::Loop(loop_expr), _) = statement else { return None };
        Some(&loop_expr.body)
    }).expect("shared receive must retain its invocation across timer checkpoints");
    let calls = |statement: &syn::Stmt| {
        let mut observe = Observe::default();
        observe.visit_stmt(statement);
        observe.calls
    };
    let position = |name: &str| loop_body.stmts.iter().position(|statement|
        calls(statement).iter().any(|call| call == name))
        .unwrap_or_else(|| panic!("receive loop lacks {name}"));
    let target = position("next_message");
    let timer = position("timer_work_pending");
    let yield_guard = position("scheduler_yield");
    let owner = position("receive_owner");
    let physical = position("receive");
    assert!(target < timer && timer < yield_guard && yield_guard < owner && owner < physical,
        "inspect retained READY first, then give pending timer one physical probe before yielding");

    let syn::Stmt::Expr(Expr::If(guard), _) = &loop_body.stmts[yield_guard] else {
        panic!("scheduler yield must be guarded by the consumed timer probe");
    };
    assert!(matches!(&*guard.cond, Expr::Binary(condition)
        if matches!(&*condition.left, Expr::Path(path) if path.path.is_ident("timer_checkpoint"))
            && matches!(&*condition.right, Expr::Path(path)
                if path.path.is_ident("timer_probe_consumed"))),
        "timer work may yield only after one receive probe in this invocation");
    let armed = loop_body.stmts.iter().enumerate().any(|(index, statement)| {
        if index <= yield_guard || index >= physical { return false; }
        matches!(statement, syn::Stmt::Expr(Expr::Assign(assignment), _)
            if matches!(&*assignment.left, Expr::Path(path)
                if path.path.is_ident("timer_probe_consumed"))
                && matches!(&*assignment.right, Expr::Path(path)
                    if path.path.is_ident("timer_checkpoint")))
    });
    assert!(armed, "record the one-shot probe before entering the native receive effect");

    struct PhysicalProbe(bool);
    impl<'ast> Visit<'ast> for PhysicalProbe {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.iter().any(|part| part.ident == "runtime")
                    && path.path.segments.last().is_some_and(|part| part.ident == "receive")) {
                self.0 |= call.args.len() == 3
                    && matches!(&call.args[0], Expr::Path(path)
                        if path.path.is_ident("execution"))
                    && matches!(&call.args[1], Expr::Field(field)
                        if matches!(&field.member, syn::Member::Named(name) if name == "tcb"))
                    && matches!(&call.args[2], Expr::Binary(blocking)
                        if matches!(&blocking.op, syn::BinOp::Or(_))
                            && matches!(&*blocking.left, Expr::Path(path)
                                if path.path.is_ident("serviced_scheduler_yield"))
                            && matches!(&*blocking.right, Expr::Unary(unary)
                                if matches!(&unary.op, syn::UnOp::Not(_))
                                    && matches!(&*unary.expr, Expr::Path(path)
                                        if path.path.is_ident("timer_checkpoint"))));
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut probe = PhysicalProbe(false);
    probe.visit_stmt(&loop_body.stmts[physical]);
    assert!(probe.0,
        "initial timer demand may poll, but a serviced scheduler yield must block on the exact ingress owner despite renewed demand");
    let mut all = Observe::default();
    all.visit_block(loop_body);
    assert!(!all.calls.iter().any(|name| name == "reply" || name == "reply_seh"),
        "the fairness probe must not send or reuse the worker's retained Reply");

    let scheduler = source("component_scheduler.rs");
    let scheduler = function(&scheduler, "hosted_component_pump_inner").unwrap();
    let mut scheduler_calls = Observe::default();
    scheduler_calls.visit_block(&scheduler.block);
    let serviced = scheduler_calls.calls.iter().position(|name| name == "service_irq_yield")
        .expect("scheduler must service timer work before continuing the worker");
    let continued = scheduler_calls.calls.iter().position(|name|
        name == "component_pump_continue_receive_after_scheduler_service")
        .expect("serviced scheduler yield must propagate to the retained receive");
    assert!(serviced < continued);

    let pump = source("spawn_hosts.rs");
    let continuation = function(&pump, "component_pump_continue_receive_after_scheduler_service")
        .expect("explicit receive-only continuation after a serviced scheduler yield");
    let mut continuation_calls = Observe::default();
    continuation_calls.visit_block(&continuation.block);
    assert!(continuation_calls.calls.iter().any(|name| name == "component_pump_continue_receive_half")
        && continuation_calls.fields.iter().any(|name| name == "scheduler_yielded"),
        "the continuation must validate the retained yielded pump and avoid a second request/reply");
}

#[test]
fn scheduler_yield_hands_off_once_to_its_authenticated_component_before_receive() {
    // A bound timer may wake the priority-255 executive before its priority-100 worker has
    // published READY or completed a port CONNECT. The next retained receive must give that
    // exact component a dispatch chance; a new request or synthetic completion cannot substitute
    // for its physical Call.
    let file = source("component_scheduler.rs");
    let pump = function(&file, "hosted_component_pump_inner").unwrap();
    let mut whole = Observe::default();
    whole.visit_block(&pump.block);
    assert!(whole.calls.iter().any(|call| call == "channel_route"),
        "component handoff must use the authenticated exact physical route");

    let yield_loop = pump.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Expr(Expr::While(loop_expr), _) = statement else { return None };
        matches!(&*loop_expr.cond, Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == "scheduler_yielded"))
            .then_some(&loop_expr.body)
    }).expect("startup scheduler loop must retain the yielded pump");
    let calls = |statement: &syn::Stmt| {
        let mut observe = Observe::default();
        observe.visit_stmt(statement);
        observe.calls
    };
    let serviced = yield_loop.stmts.iter().position(|statement|
        calls(statement).iter().any(|call| call == "service_irq_yield"))
        .expect("service the timer before granting a worker dispatch chance");
    let continued = yield_loop.stmts.iter().position(|statement|
        calls(statement).iter().any(|call|
            call == "component_pump_continue_receive_after_scheduler_service"))
        .expect("retain the receive-only continuation");
    assert!(serviced < continued);

    struct Handoff {
        exact_worker: bool,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Handoff {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|part|
                    part.ident.to_string().contains("handoff"))) {
                self.count += 1;
                self.exact_worker |= call.args.iter().any(|arg|
                    matches!(arg, Expr::Field(field)
                        if matches!(&*field.base, Expr::Path(path)
                            if path.path.is_ident("channel"))
                            && matches!(&field.member, syn::Member::Named(name)
                                if name == "tcb")));
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let guarded = yield_loop.stmts.iter().enumerate().any(|(index, statement)| {
        if index <= serviced || index >= continued { return false; }
        let syn::Stmt::Expr(Expr::If(branch), _) = statement else { return false };
        if !matches!(&*branch.cond, Expr::MethodCall(call)
            if call.method == "is_some"
                && matches!(&*call.receiver, Expr::Path(path)
                    if path.path.is_ident("route"))) {
            return false;
        }
        let mut handoff = Handoff { exact_worker: false, count: 0 };
        handoff.visit_block(&branch.then_branch);
        handoff.exact_worker && handoff.count == 1
    });
    assert!(guarded,
        "after timer service, the authenticated physical route must hand off once to channel.tcb before the retained receive");
    let mut all_handoffs = Handoff { exact_worker: false, count: 0 };
    all_handoffs.visit_block(yield_loop);
    assert_eq!(all_handoffs.count, 1,
        "no unrelated or repeated handoff may escape the authenticated route guard");

    let mut loop_calls = Observe::default();
    loop_calls.visit_block(yield_loop);
    assert!(!loop_calls.calls.iter().any(|call|
        matches!(call.as_str(), "reply" | "reply_seh" | "pump_deliver_initial_request" | "component_pump")),
        "worker handoff must not replay the request, its Reply, or invent completion");
}
