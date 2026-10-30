use syn::{visit::Visit, Expr, ImplItem, Item};

fn creation_source() -> syn::File {
    let path = std::env::var_os("NT_INITIAL_CREATION_SOURCE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/initial_thread_creation.rs"));
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn native_function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function.block.as_ref()),
        Item::Impl(implementation) => implementation.items.iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(&function.block),
            _ => None,
        }),
        _ => None,
    }).expect("native initial creation function")
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = call.func.as_ref() {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Vec<String> {
    let mut visitor = Calls::default();
    visitor.visit_block(block);
    visitor.0
}

fn count(calls: &[String], name: &str) -> usize {
    calls.iter().filter(|call| call.as_str() == name).count()
}

fn contains_path(expression: &Expr, name: &str) -> bool {
    struct Paths<'a> { name: &'a str, found: bool }
    impl<'ast> Visit<'ast> for Paths<'_> {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.found |= path.path.segments.last().is_some_and(|part| part.ident == self.name);
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut paths = Paths { name, found: false };
    paths.visit_expr(expression);
    paths.found
}

#[test]
fn every_native_completion_uses_the_retained_phase_instead_of_replaying_start() {
    let file = creation_source();
    for name in ["finish_configured_initial_thread", "finish_foreign_initial_thread"] {
        let path = calls(native_function(&file, name));
        let expected = if name == "finish_foreign_initial_thread" { 2 } else { 1 };
        assert_eq!(count(&path, "advance_initial_creation"), expected,
            "{name} must redrive the retained owner on every completion branch");
        assert_eq!(count(&path, "create_initial_thread"), 0,
            "{name} must not replay the physical Start after a Ps failure");
        assert_eq!(count(&path, "commit_initial_thread_creation"), 0,
            "{name} must not repeat Ps commit after handle delivery failure");
    }
    let foreign = calls(native_function(&file, "finish_foreign_initial_thread"));
    assert!(foreign.iter().rposition(|call| call == "advance_initial_creation").unwrap()
        < foreign.iter().position(|call| call == "publish_reserved_handle").unwrap(),
        "handle publication follows the persisted physical and Ps phases");
}

#[test]
fn native_phase_records_acknowledgment_before_fallible_ps_or_handle_effects() {
    let file = creation_source();
    let owner = file.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "PendingInitialThreadCreation" => Some(item),
        _ => None,
    }).unwrap();
    assert!(owner.fields.iter().any(|field| field.ident.as_ref().is_some_and(|id| id == "progress")),
        "the exact runtime owner must retain progress across retries");
    let advance = native_function(&file, "advance_initial_creation");
    let path = calls(advance);
    assert_eq!(count(&path, "create_initial_thread"), 1,
        "one physical invocation must be guarded by the StartPhysical phase");
    let physical = path.iter().position(|call| call == "create_initial_thread").unwrap();
    let acknowledged = path.iter().position(|call| call == "physical_started").unwrap();
    let ps = path.iter().position(|call| call == "commit_initial_thread_creation").unwrap();
    let committed = path.iter().position(|call| call == "ps_committed").unwrap();
    assert!(physical < acknowledged && acknowledged < ps && ps < committed,
        "record each acknowledged effect before attempting the next fallible effect");
    struct Guards { physical: bool, ps: bool }
    impl<'ast> Visit<'ast> for Guards {
        fn visit_expr_match(&mut self, value: &'ast syn::ExprMatch) {
            if matches!(&*value.expr, Expr::Path(path) if path.path.is_ident("step")) {
                let physical_arms: Vec<_> = value.arms.iter().filter(|arm|
                    count(&calls_in_expr(&arm.body), "create_initial_thread") != 0
                ).collect();
                self.physical = physical_arms.len() == 1 && matches!(&physical_arms[0].pat,
                    syn::Pat::Path(path) if path.path.segments.last().unwrap().ident == "StartPhysical");
            }
            syn::visit::visit_expr_match(self, value);
        }
        fn visit_expr_if(&mut self, value: &'ast syn::ExprIf) {
            if count(&calls(&value.then_branch), "commit_initial_thread_creation") != 0
                && contains_path(&value.cond, "CommitPs")
            { self.ps = true; }
            syn::visit::visit_expr_if(self, value);
        }
    }
    fn calls_in_expr(expression: &Expr) -> Vec<String> {
        let mut visitor = Calls::default();
        visitor.visit_expr(expression);
        visitor.0
    }
    let mut guards = Guards { physical: false, ps: false };
    guards.visit_block(advance);
    assert!(guards.physical && guards.ps,
        "physical Start and Ps commit must be gated by their persisted owner phases");
    let cancel = calls(native_function(&file, "cancel_creation"));
    assert!(cancel.iter().position(|call| call == "may_cancel_no_effects").unwrap()
        < cancel.iter().position(|call| call == "cancel_initial_thread_creation").unwrap(),
        "an uncertain or committed physical effect cannot be canceled as no-effects");
}

#[test]
fn uncertain_physical_reconciliation_has_no_second_native_start() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/thread_suspend.rs"
    )).unwrap();
    let resolve = calls(native_function(&file, "resolve_initial_thread_start"));
    assert_eq!(count(&resolve, "finish_control"), 1);
    assert_eq!(count(&resolve, "resume_initial"), 0,
        "reconciliation may finish an acknowledged local Ps control, never replay Start IPC");
}

#[test]
fn foreign_initial_lineage_is_reserved_before_effects_and_committed_after_ps() {
    let file = creation_source();
    let owner = file.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "PendingInitialThreadCreation" => Some(item),
        _ => None,
    }).unwrap();
    assert!(owner.fields.iter().any(|field| field.ident.as_ref().is_some_and(|id| id == "role_reservation")),
        "the same exact runtime owner must retain opaque lineage ownership through suspended callbacks");

    let prepare = calls(native_function(&file, "create_foreign_thread"));
    let reserve = prepare.iter().position(|name| name == "reserve_foreign_initial_thread_lineage")
        .expect("foreign initial creation must reserve lineage from exact caller and child before effects");
    let callout = prepare.iter().position(|name| name == "create_win32_process_before_loader")
        .expect("process-create callout");
    assert!(reserve < callout, "reservation must survive callback suspension and uncertainty");
    let evidence_path = calls(native_function(&file, "reserve_foreign_initial_thread_lineage"));
    let source = evidence_path.iter().position(|name| name == "source_for_live_process")
        .expect("lineage requires the retained exact Section source");
    let caller_role = evidence_path.iter().position(|name| name == "role")
        .expect("lineage requires the actual caller's committed ledger identity");
    let ledger_reserve = evidence_path.iter().position(|name| name == "reserve_foreign_initial_thread_lineage")
        .expect("lineage uses the ordinary reservation contract");
    assert!(source < caller_role && caller_role < ledger_reserve);
    assert_eq!(count(&evidence_path, "reserve_foreign_initial_thread_role"), 0,
        "ordinary lineage cannot promote a registered privileged role");

    let advance = calls(native_function(&file, "advance_initial_creation"));
    let ps = advance.iter().position(|name| name == "ps_committed").unwrap();
    let commit = advance.iter().position(|name| name == "commit_foreign_initial_thread")
        .expect("lineage must be committed only after physical and Ps success");
    assert!(ps < commit, "lineage cannot become visible before Ps commit");
    let foreign = calls(native_function(&file, "finish_foreign_initial_thread"));
    assert!(foreign.iter().any(|name| name == "advance_initial_creation"),
        "abandoned and ordinary delivery share the same lineage commit boundary");

    let cancel = calls(native_function(&file, "cancel_creation"));
    assert!(cancel.iter().position(|name| name == "may_cancel_no_effects").unwrap()
        < cancel.iter().position(|name| name == "cancel_foreign_initial_thread")
            .expect("no-effects cancellation must release reserved lineage"),
        "uncertain physical effects must retain their lineage token");
}

#[test]
fn exact_execution_retirement_releases_committed_lineage_and_bootstrap_role() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let deletion = native_function(&file, "try_delete_hosted_process_object_exact");
    struct Retirement<'a>(Option<&'a Expr>);
    impl<'ast> Visit<'ast> for Retirement<'ast> {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, syn::Pat::Path(path)
                if path.path.segments.last().unwrap().ident == "RetiringExecution") {
                self.0 = Some(&arm.body);
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut retirement = Retirement(None);
    retirement.visit_block(deletion);
    let mut visitor = Calls::default();
    visitor.visit_expr(retirement.0.expect("exact execution retirement branch"));
    let path = visitor.0;
    let mechanism = path.iter().position(|name| name == "release_exact")
        .expect("exact mechanism release");
    let ledger = path.iter().position(|name| name == "retire_exact")
        .expect("retirement must free the execution-role slot for the exact generation");
    let phase = path.iter().position(|name| name == "mark_execution_retired")
        .expect("retirement phase transition");
    assert!(mechanism < ledger && ledger < phase,
        "ledger retirement follows physical execution retirement and precedes phase completion");
}
