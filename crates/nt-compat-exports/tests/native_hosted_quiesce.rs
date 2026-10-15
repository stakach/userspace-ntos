//! Terminal diagnostics must cover actual worker owners, not selected image/main roles.
use syn::visit::{self, Visit};

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const WAIT: &str = include_str!("../../../components/ntos-executive/src/object_wait.rs");
const QUIESCE: &str = include_str!("../../../components/ntos-executive/src/hosted_quiesce.rs");

fn block(source: &str, name: &str) -> syn::Block {
    struct Find<'a> {
        name: &'a str,
        found: Option<syn::Block>,
    }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == self.name {
                self.found = Some((*item.block).clone());
            }
            visit::visit_item_fn(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if item.sig.ident == self.name {
                self.found = Some(item.block.clone());
            }
            visit::visit_impl_item_fn(self, item);
        }
    }
    let mut find = Find { name, found: None };
    find.visit_file(&syn::parse_file(source).expect("actual native source parses"));
    find.found
        .unwrap_or_else(|| panic!("missing actual diagnostic {name}"))
}

#[derive(Default)]
struct Audit {
    names: Vec<String>,
    fields: Vec<String>,
    loops: usize,
}
impl<'ast> Visit<'ast> for Audit {
    fn visit_expr_path(&mut self, value: &'ast syn::ExprPath) {
        self.names.extend(
            value
                .path
                .segments
                .iter()
                .map(|part| part.ident.to_string()),
        );
        visit::visit_expr_path(self, value);
    }
    fn visit_expr_method_call(&mut self, value: &'ast syn::ExprMethodCall) {
        self.names.push(value.method.to_string());
        visit::visit_expr_method_call(self, value);
    }
    fn visit_expr_field(&mut self, value: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &value.member {
            self.fields.push(name.to_string());
        }
        visit::visit_expr_field(self, value);
    }
    fn visit_expr_loop(&mut self, value: &'ast syn::ExprLoop) {
        self.loops += 1;
        visit::visit_expr_loop(self, value);
    }
    fn visit_expr_while(&mut self, value: &'ast syn::ExprWhile) {
        self.loops += 1;
        visit::visit_expr_while(self, value);
    }
}
fn audit(value: &syn::Block) -> Audit {
    let mut audit = Audit::default();
    audit.visit_block(value);
    audit
}

#[test]
fn terminal_quiesce_dumps_all_runtime_threads_after_live_checkpoint() {
    struct Ordered {
        checkpoint: bool,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Ordered {
        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            self.checkpoint = false;
            visit::visit_item_fn(self, function);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "checkpoint_live" {
                self.checkpoint = true;
            }
            visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(call.func.as_ref(), syn::Expr::Path(path)
                if path.path.is_ident("dump_all_hosted_thread_quiesce"))
            {
                assert!(
                    self.checkpoint,
                    "copy exact live process state before terminal observation"
                );
                self.found = true;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut ordered = Ordered {
        checkpoint: false,
        found: false,
    };
    ordered.visit_file(&syn::parse_file(SERVICE).unwrap());
    assert!(
        ordered.found,
        "terminal diagnostics currently omit non-main, non-hot workers"
    );
}

#[test]
fn generic_quiesce_paginates_copied_executable_bindings_without_role_selection() {
    let dump = audit(&block(QUIESCE, "dump_all_hosted_thread_quiesce"));
    assert!(
        dump.loops != 0,
        "advance through all pages, not a truncated fixed snapshot"
    );
    assert!(dump
        .names
        .iter()
        .any(|name| name == "next_hosted_thread_quiesce_snapshot"));
    assert!(dump
        .names
        .iter()
        .any(|name| name == "dump_hosted_thread_quiesce"));
    for forbidden in [
        "Main",
        "hosted_thread_identity_for_role",
        "hosted_pi_for_role",
        "hosted_process_wait_snapshot",
    ] {
        assert!(
            !dump.names.iter().any(|name| name == forbidden),
            "generic dump selects {forbidden}"
        );
    }
    let snapshot = audit(&block(HANDLER, "next_hosted_thread_quiesce_snapshot"));
    for name in ["executable", "binding", "thread_lifetime"] {
        assert!(
            snapshot.names.iter().any(|actual| actual == name),
            "snapshot omits canonical {name}"
        );
    }
    assert!(snapshot.fields.iter().any(|name| name == "entries"));
    for forbidden in ["get_by_tid", "get_by_badge", "hosted_ingress_binding"] {
        assert!(!snapshot.names.iter().any(|name| name == forbidden));
    }
}

#[test]
fn parked_wait_observation_joins_the_entire_retained_logical_caller() {
    let function = block(WAIT, "object_wait_snapshot_for_caller");
    struct Exact(bool);
    impl<'ast> Visit<'ast> for Exact {
        fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
            fn caller_field(value: &syn::Expr) -> bool {
                matches!(value, syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "caller"))
            }
            fn caller_input(value: &syn::Expr) -> bool {
                matches!(value, syn::Expr::Path(path) if path.path.is_ident("caller"))
            }
            if matches!(expression.op, syn::BinOp::Eq(_)) {
                self.0 |= (caller_field(&expression.left) && caller_input(&expression.right))
                    || (caller_input(&expression.left) && caller_field(&expression.right));
            }
            visit::visit_expr_binary(self, expression);
        }
    }
    let mut exact = Exact(false);
    exact.visit_block(&function);
    assert!(
        exact.0,
        "TID/badge alone cannot join a waiter after process/thread generation reuse"
    );
    let observed = audit(&function);
    for name in ["reply_cap", "sequence", "objects", "deadline", "reply_sent"] {
        assert!(
            observed.fields.iter().any(|actual| actual == name),
            "wait snapshot omits {name}"
        );
    }
}

#[test]
fn generic_thread_debug_uses_exact_wait_reply_or_explicit_unavailable() {
    let observed = audit(&block(SERVICE, "dump_hosted_thread_quiesce"));
    assert!(
        !observed.names.iter().any(|name| name == "REPLY_MAIN_SLOT"),
        "an ambient main Reply is not the worker's retained wait Reply"
    );
    assert!(observed
        .names
        .iter()
        .any(|name| name == "object_wait_snapshot_for_caller"));
    struct Unavailable(bool);
    impl<'ast> Visit<'ast> for Unavailable {
        fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
            self.0 |= literal
                .value()
                .windows(b"unavailable".len())
                .any(|part| part == b"unavailable");
        }
    }
    let mut unavailable = Unavailable(false);
    unavailable.visit_block(&block(SERVICE, "dump_hosted_thread_quiesce"));
    assert!(
        unavailable.0,
        "missing exact Reply evidence must be reported, not substituted"
    );
}

#[test]
fn failed_register_read_does_not_interpret_an_empty_context_as_client_state() {
    let function = block(SERVICE, "dump_hosted_thread_quiesce");
    let observed = audit(&function);
    assert!(!observed.names.iter().any(|name| name == "tcb_read_regs20"));
    struct Checked {
        read: bool,
        error_returns: bool,
    }
    impl<'ast> Visit<'ast> for Checked {
        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            if matches!(expression.expr.as_ref(), syn::Expr::Call(call)
                if matches!(call.func.as_ref(), syn::Expr::Path(path)
                    if path.path.segments.iter().any(|part| part.ident == "LegacyThreadContext")
                    && path.path.segments.last().is_some_and(|part| part.ident == "read")))
            {
                self.read = true;
                for arm in &expression.arms {
                    if matches!(&arm.pat, syn::Pat::TupleStruct(pattern) if pattern.path.is_ident("Err"))
                    {
                        struct Returns(bool);
                        impl<'ast> Visit<'ast> for Returns {
                            fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
                                self.0 = true;
                            }
                        }
                        let mut returns = Returns(false);
                        returns.visit_expr(&arm.body);
                        self.error_returns = returns.0;
                    }
                }
            }
            visit::visit_expr_match(self, expression);
        }
    }
    let mut checked = Checked {
        read: false,
        error_returns: false,
    };
    checked.visit_block(&function);
    assert!(
        checked.read && checked.error_returns,
        "register observation must propagate actual read failure before interpreting RIP/stack"
    );
}

#[test]
fn unavailable_exact_caller_stops_before_register_or_stack_attribution() {
    fn calls_quiesce_caller(expression: &syn::Expr) -> bool {
        matches!(expression, syn::Expr::Call(call)
            if matches!(call.func.as_ref(), syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "quiesce_caller")))
    }
    fn returns(expression: &syn::Expr) -> bool {
        struct Returns(bool);
        impl<'ast> Visit<'ast> for Returns {
            fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
                self.0 = true;
            }
        }
        let mut found = Returns(false);
        found.visit_expr(expression);
        found.0
    }
    let function = block(SERVICE, "dump_hosted_thread_quiesce");
    let admission = function
        .stmts
        .iter()
        .position(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return false;
            };
            let Some(initializer) = &local.init else {
                return false;
            };
            // Accept either checked Option destructuring or a match that returns on None.
            if calls_quiesce_caller(&initializer.expr) {
                return matches!(&local.pat, syn::Pat::TupleStruct(pattern)
                if pattern.path.is_ident("Some"))
                    && initializer
                        .diverge
                        .as_ref()
                        .is_some_and(|(_, expression)| returns(expression));
            }
            matches!(&*initializer.expr, syn::Expr::Match(matched)
            if calls_quiesce_caller(&matched.expr)
                && matched.arms.iter().any(|arm|
                    matches!(&arm.pat, syn::Pat::Path(path) if path.path.is_ident("None"))
                        && returns(&arm.body)))
        })
        .expect(
            "exact caller refusal must return before interpreting a retained TCB or current PI",
        );
    for statement in &function.stmts[..admission] {
        let mut observed = Audit::default();
        observed.visit_stmt(statement);
        for forbidden in [
            "capture_process_identity",
            "LegacyThreadContext",
            "trace_hosted_tcb_debug_state",
            "mirror_ctx_for",
            "quiesce_copyin_process_bytes",
        ] {
            assert!(
                !observed.names.iter().any(|name| name == forbidden),
                "{forbidden} precedes exact process/thread caller admission"
            );
        }
    }
}

#[test]
fn ambiguous_exact_wait_matches_return_unavailable_before_copying_reply_metadata() {
    fn returns_none(block: &syn::Block) -> bool {
        block.stmts.iter().any(|statement| {
            matches!(statement,
            syn::Stmt::Expr(syn::Expr::Return(returned), _)
                if returned.expr.as_ref().is_some_and(|expression|
                    matches!(&**expression, syn::Expr::Path(path) if path.path.is_ident("None"))))
        })
    }
    let function = block(WAIT, "object_wait_snapshot_for_caller");
    let rejection = function.stmts.iter().position(|statement| {
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else { return false; };
        let syn::Expr::MethodCall(present) = &*branch.cond else { return false; };
        present.method == "is_some"
            && matches!(&*present.receiver, syn::Expr::MethodCall(next) if next.method == "next")
            && returns_none(&branch.then_branch)
    }).expect("a second exact matching waiter must not choose an arbitrary saved Reply");
    let copy = function
        .stmts
        .iter()
        .position(|statement| {
            struct Snapshot(bool);
            impl<'ast> Visit<'ast> for Snapshot {
                fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
                    self.0 |= expression.path.is_ident("ObjectWaitSnapshot");
                    visit::visit_expr_struct(self, expression);
                }
            }
            let mut snapshot = Snapshot(false);
            snapshot.visit_stmt(statement);
            snapshot.0
        })
        .expect("actual copied waiter snapshot");
    assert!(
        rejection < copy,
        "uniqueness refusal must precede snapshot publication"
    );
}
