use syn::visit::Visit;

fn kernel_only_cfg(expression: &syn::Expr, excluded: bool) -> bool {
    let syn::Expr::Macro(value) = expression else {
        return false;
    };
    if !value.mac.path.is_ident("cfg") {
        return false;
    }
    let expected = if excluded {
        "not(feature=\"mup-provider-kernel-only\")"
    } else {
        "feature=\"mup-provider-kernel-only\""
    };
    value.mac.tokens.to_string().replace(' ', "") == expected
}

#[test]
fn kernel_only_driver_profile_does_not_use_desktop_milestone_stall_termination() {
    struct Audit {
        candidates: usize,
        exclusions: usize,
    }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            struct Condition {
                budget: bool,
                excluded: bool,
            }
            impl<'ast> Visit<'ast> for Condition {
                fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                    self.budget |= path.path.is_ident("STALL_BUDGET_100NS");
                    syn::visit::visit_expr_path(self, path);
                }
                fn visit_expr(&mut self, expression: &'ast syn::Expr) {
                    self.excluded |= kernel_only_cfg(expression, true);
                    syn::visit::visit_expr(self, expression);
                }
            }
            let mut condition = Condition {
                budget: false,
                excluded: false,
            };
            condition.visit_expr(&branch.cond);
            if condition.budget {
                self.candidates += 1;
                self.exclusions += usize::from(condition.excluded);
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    ))
    .unwrap();
    let mut audit = Audit {
        candidates: 0,
        exclusions: 0,
    };
    audit.visit_file(&source);
    assert_eq!(
        audit.candidates, 1,
        "identify the actual desktop milestone stall policy"
    );
    assert_eq!(audit.exclusions, 1, "a GUI-free driver profile has no desktop milestones; preserve its externally bounded service pump");
}

#[test]
fn kernel_only_service_loop_exit_fail_stops_before_post_loop_observers_and_owner_drop() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    ))
    .unwrap();
    let service = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "service_sec_image" => Some(function),
            _ => None,
        })
        .expect("actual retained service loop");
    let index = service.block.stmts.iter().position(|statement| {
        let syn::Stmt::Expr(syn::Expr::Loop(value), _) = statement else { return false; };
        value.body.stmts.iter().any(|statement| matches!(statement,
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "ingress")))
    }).expect("actual admitted ingress loop");
    let syn::Stmt::Expr(syn::Expr::If(guard), _) = &service.block.stmts[index + 1] else {
        panic!("kernel-only termination must fail-stop before any post-loop effects or GUI observations");
    };
    assert!(
        kernel_only_cfg(&guard.cond, false),
        "exact test profile boundary, not image-role authority"
    );
    #[derive(Default)]
    struct Failure {
        park: usize,
        marker: usize,
        returns: usize,
    }
    impl<'ast> Visit<'ast> for Failure {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("park")) {
                self.park += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
            self.marker += usize::from(
                literal
                    .value()
                    .starts_with(b"[mup-provider-gate] terminal service-loop failure"),
            );
        }
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.returns += 1;
        }
    }
    let mut failure = Failure::default();
    failure.visit_block(&guard.then_branch);
    assert_eq!(
        failure.park, 1,
        "nonreturning park retains the live handler and exact pending owners"
    );
    assert_eq!(
        failure.marker, 1,
        "external runner must see explicit failure, never a desktop verdict"
    );
    assert_eq!(
        failure.returns, 0,
        "do not drop or abandon retained provider work"
    );
}

#[test]
fn milestone_deadline_is_not_documented_as_proof_of_impossible_progress() {
    let source = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    assert!(!source.contains("forward progress is impossible"),
        "a milestone deadline is a bounded boot-stall policy, not proof that an admitted caller or real credential paint cannot progress");
}

fn path_is(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
}

fn notification_only(condition: &syn::Expr) -> bool {
    match condition {
        syn::Expr::MethodCall(call) => {
            call.method == "is_none" && path_is(&call.receiver, "ingress")
        }
        syn::Expr::Paren(value) => notification_only(&value.expr),
        syn::Expr::Binary(value) => match value.op {
            syn::BinOp::And(_) => notification_only(&value.left) || notification_only(&value.right),
            syn::BinOp::Eq(_) => {
                (path_is(&value.left, "badge") && path_is(&value.right, "DELAY_TIMER_BADGE"))
                    || (path_is(&value.right, "badge") && path_is(&value.left, "DELAY_TIMER_BADGE"))
            }
            _ => false,
        },
        _ => false,
    }
}

struct BreakAudit {
    guarded: bool,
    candidate: bool,
    unguarded: usize,
}

fn stall_candidate(condition: &syn::Expr) -> bool {
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.0 |= path.path.segments.iter().any(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "WATCHDOG_TRIPPED"
                        | "watchdog_confirm_trip"
                        | "last_progress_t"
                        | "STALL_BUDGET_100NS"
                )
            });
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut find = Find(false);
    find.visit_expr(condition);
    find.0
}

impl<'ast> Visit<'ast> for BreakAudit {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let outer = (self.guarded, self.candidate);
        self.candidate |= stall_candidate(&expression.cond);
        self.guarded |= notification_only(&expression.cond);
        self.visit_block(&expression.then_branch);
        self.guarded = outer.0;
        if let Some((_, branch)) = &expression.else_branch {
            self.visit_expr(branch);
        }
        self.candidate = outer.1;
    }

    fn visit_expr_break(&mut self, _: &'ast syn::ExprBreak) {
        if self.candidate && !self.guarded {
            self.unguarded += 1;
        }
    }
}

#[test]
fn quiesce_and_deadman_cannot_abandon_admitted_ingress_before_dispatch() {
    struct FindLoop {
        audited: usize,
        unguarded: usize,
    }
    impl<'ast> Visit<'ast> for FindLoop {
        fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
            let admission = expression.body.stmts.iter().position(|statement| {
                matches!(statement, syn::Stmt::Local(local)
                    if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "ingress"))
            });
            if let Some(admission) = admission {
                let dispatch = expression.body.stmts.iter().enumerate().skip(admission + 1)
                    .find_map(|(index, statement)| {
                        let syn::Stmt::Expr(syn::Expr::Match(value), _) = statement else { return None; };
                        matches!(&*value.expr, syn::Expr::Binary(binary)
                            if matches!(binary.op, syn::BinOp::Shr(_)) && path_is(&binary.left, "mi"))
                            .then_some(index)
                    }).expect("admitted service ingress reaches its label dispatch");
                let mut audit = BreakAudit {
                    guarded: false,
                    candidate: false,
                    unguarded: 0,
                };
                for statement in &expression.body.stmts[admission + 1..dispatch] {
                    audit.visit_stmt(statement);
                }
                self.audited += 1;
                self.unguarded += audit.unguarded;
            }
            syn::visit::visit_expr_loop(self, expression);
        }
    }
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    ))
    .unwrap();
    let mut audit = FindLoop {
        audited: 0,
        unguarded: 0,
    };
    audit.visit_file(&source);
    assert_eq!(
        audit.audited, 1,
        "audit the actual owned service-loop admission boundary"
    );
    assert_eq!(audit.unguarded, 0,
        "milestone/deadman quiesce must not drop an admitted Call before dispatch; gate only at a notification-only or post-retirement boundary");
}

fn progress_call(expression: &syn::ExprCall, variant: &str) -> bool {
    matches!(&*expression.func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|name| name.ident == "note_boot_progress"))
        && expression.args.iter().any(|argument| {
            matches!(argument, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|name| name.ident == variant))
        })
}

#[test]
fn only_real_bounded_credential_retrieval_records_progress() {
    fn changed_retrieval(condition: &syn::Expr) -> bool {
        match condition {
            syn::Expr::Paren(value) => changed_retrieval(&value.expr),
            syn::Expr::Binary(value) if matches!(value.op, syn::BinOp::Or(_)) => {
                changed_retrieval(&value.left) && changed_retrieval(&value.right)
            }
            syn::Expr::Binary(value) if matches!(value.op, syn::BinOp::Ne(_)) => {
                matches!((&*value.left, &*value.right),
                    (syn::Expr::MethodCall(left), syn::Expr::MethodCall(right))
                        if left.method == right.method
                            && (left.method == "retrieved_chars" || left.method == "retrieved_return"))
            }
            _ => false,
        }
    }
    struct Accepted {
        inside: bool,
        changed: bool,
        found: bool,
        escaped: bool,
    }
    impl<'ast> Visit<'ast> for Accepted {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let outer = (self.inside, self.changed);
            self.inside |= matches!(&*expression.cond, syn::Expr::MethodCall(call)
                if call.method == "observe_retrieved");
            self.changed |= changed_retrieval(&expression.cond);
            self.visit_block(&expression.then_branch);
            self.inside = outer.0;
            self.changed = outer.1;
            if let Some((_, branch)) = &expression.else_branch {
                self.visit_expr(branch);
            }
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if progress_call(call, "CredentialRetrieved") {
                self.found = true;
                self.escaped |= !self.inside || !self.changed;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/main.rs"
    ))
    .unwrap();
    let function = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "winlogon_credential_observe_retrieved" => {
                Some(item)
            }
            _ => None,
        })
        .unwrap();
    let mut audit = Accepted {
        inside: false,
        changed: false,
        found: false,
        escaped: false,
    };
    audit.visit_item_fn(function);
    assert!(audit.found && !audit.escaped,
        "only a new exact accepted credential-sequence retrieval advances boot progress, not duplicate Return, queue polls or timer wakes");
}

#[test]
fn completed_and_drained_modal_frontiers_are_one_shot_progress() {
    struct Calls {
        completed: bool,
        drained: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.completed |= progress_call(call, "DialogModalCompleted");
            self.drained |= progress_call(call, "DialogModalDrained");
            syn::visit::visit_expr_call(self, call);
        }
    }
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/main.rs"
    ))
    .unwrap();
    let store = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "winlogon_dialog_modal_store" => Some(item),
            _ => None,
        })
        .unwrap();
    let mut calls = Calls {
        completed: false,
        drained: false,
    };
    calls.visit_item_fn(store);
    assert!(
        calls.completed && calls.drained,
        "real correlated modal completion/drain must publish finite boot frontiers"
    );
    let policy = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/boot_progress.rs"
    ))
    .unwrap();
    let implementation = policy
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(&*item.self_ty, syn::Type::Path(path)
            if path.path.is_ident("BootProgress")) =>
            {
                Some(item)
            }
            _ => None,
        })
        .unwrap();
    let bits = implementation
        .items
        .iter()
        .find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "one_shot_bit" => Some(item),
            _ => None,
        })
        .unwrap();
    let syn::Stmt::Expr(syn::Expr::Match(bits), _) = &bits.block.stmts[0] else {
        panic!("boot progress exposes its one-shot variant policy");
    };
    for name in ["DialogModalCompleted", "DialogModalDrained"] {
        assert!(bits.arms.iter().any(|arm| {
            matches!(&arm.pat, syn::Pat::Path(path)
                if path.path.segments.last().is_some_and(|variant| variant.ident == name))
                && !matches!(&*arm.body, syn::Expr::Lit(value)
                    if matches!(&value.lit, syn::Lit::Int(value) if matches!(value.base10_parse::<u64>(), Ok(0))))
        }), "{name} must have a nonzero one-shot milestone bit");
    }
}
