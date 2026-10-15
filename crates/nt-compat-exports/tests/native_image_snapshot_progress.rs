use syn::visit::Visit;

#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/boot_progress.rs"]
mod boot_progress;
fn explorer_chrome_runtime_milestones_reached() -> bool { false }
fn print_str(_: &[u8]) {}

fn named_path(path: &syn::Path, name: &str) -> bool {
    path.segments.last().is_some_and(|part| part.ident == name)
}

fn phase<'a>(file: &'a syn::File, name: &'a str) -> &'a syn::Arm {
    struct Find<'a> { name: &'a str, found: Option<&'a syn::Arm> }
    impl<'a> Visit<'a> for Find<'a> {
        fn visit_arm(&mut self, arm: &'a syn::Arm) {
            let path = match &arm.pat {
                syn::Pat::Path(value) => Some(&value.path),
                syn::Pat::Struct(value) => Some(&value.path),
                _ => None,
            };
            if path.is_some_and(|path| named_path(path, self.name)) { self.found = Some(arm); }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut find = Find { name, found: None };
    find.visit_file(file);
    find.found.expect("actual retained phase exists")
}

#[derive(Default)]
struct Calls { sequence: Vec<String> }
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if named_path(&path.path, "note_boot_progress") {
                assert!(call.args.iter().any(|arg| matches!(arg, syn::Expr::Path(path)
                    if named_path(&path.path, "ImageSnapshotCaptured"))),
                    "snapshot progress must use its acknowledged sealed-observer event");
                self.sequence.push("note".into());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.sequence.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}
fn source() -> syn::File {
    syn::parse_file(include_str!("../../../components/ntos-executive/src/section_metadata_work.rs")).unwrap()
}

fn not_cancelled(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::Unary(unary)
        if matches!(unary.op, syn::UnOp::Not(_))
            && matches!(&*unary.expr, syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "cancelled")))
}

fn success(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::Binary(binary)
        if matches!(binary.op, syn::BinOp::Eq(_))
            && matches!(&*binary.left, syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "status"))
            && matches!(&*binary.right, syn::Expr::Lit(lit)
                if matches!(&lit.lit, syn::Lit::Int(value)
                    if matches!(value.base10_parse::<u64>(), Ok(0)))))
}

fn assert_cancel_guard(expression: &syn::Expr) {
    struct Guard { guarded: bool, notes: usize }
    impl<'a> Visit<'a> for Guard {
        fn visit_expr_if(&mut self, expression: &'a syn::ExprIf) {
            let saved = self.guarded;
            self.guarded |= not_cancelled(&expression.cond);
            self.visit_block(&expression.then_branch);
            self.guarded = saved;
            if let Some((_, branch)) = &expression.else_branch { self.visit_expr(branch); }
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path) if named_path(&path.path, "note_boot_progress")) {
                assert!(self.guarded, "cancelled direct snapshots cannot advance progress");
                self.notes += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut guard = Guard { guarded: false, notes: 0 };
    guard.visit_expr(expression);
    assert_eq!(guard.notes, 1);
}

#[test]
fn direct_snapshot_progress_follows_full_successful_append_only() {
    struct Completed { found: bool }
    impl<'a> Visit<'a> for Completed {
        fn visit_arm(&mut self, arm: &'a syn::Arm) {
            let mut calls = Calls::default();
            calls.visit_expr(&arm.body);
            if calls.sequence.iter().any(|name| name == "extend_from_slice") {
                assert!(arm.guard.is_some(), "the direct append requires the exact successful length guard");
                assert_eq!(calls.sequence, ["extend_from_slice", "note"],
                    "only accepted full snapshot bytes advance progress after append");
                assert_cancel_guard(&arm.body);
                self.found = true;
            } else {
                assert!(!calls.sequence.iter().any(|name| name == "note"),
                    "failed and pending dispatch results cannot advance progress");
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let file = source();
    let mut audit = Completed { found: false };
    audit.visit_expr(&phase(&file, "HeaderDispatch").body);
    assert!(audit.found);
}

#[test]
fn pending_snapshot_progress_requires_strict_ack_and_success() {
    let file = source();
    for name in ["HeaderPending", "HeaderCopying"] {
        let mut calls = Calls::default();
        calls.visit_expr(&phase(&file, name).body);
        assert!(!calls.sequence.iter().any(|name| name == "note"),
            "polls and partial output copying are not acknowledged capture progress");
    }
    let arm = phase(&file, "HeaderAckPending");
    let mut calls = Calls::default();
    calls.visit_expr(&arm.body);
    let ack = calls.sequence.iter().position(|name| name == "acknowledge_completed_irp_strict").unwrap();
    let note = calls.sequence.iter().position(|name| name == "note")
        .expect("successful pending capture ACK must advance progress");
    assert!(ack < note);
    struct Success(bool);
    impl<'a> Visit<'a> for Success {
        fn visit_expr_if(&mut self, expression: &'a syn::ExprIf) {
            if matches!(&*expression.cond, syn::Expr::Binary(binary)
                if matches!(binary.op, syn::BinOp::And(_))
                    && success(&binary.left) && not_cancelled(&binary.right)) {
                let mut calls = Calls::default();
                calls.visit_block(&expression.then_branch);
                self.0 |= calls.sequence.iter().any(|name| name == "note");
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut success = Success(false);
    success.visit_expr(&arm.body);
    assert!(success.0, "failed or cancelled pending reads cannot manufacture progress after ACK");
}

#[test]
fn snapshot_event_is_present_and_actual_observer_remains_recurring_and_sealed() {
    let file = syn::parse_file(include_str!("../../../components/ntos-executive/src/boot_progress.rs")).unwrap();
    assert!(file.items.iter().any(|item| matches!(item, syn::Item::Enum(item)
        if item.ident == "BootProgress" && item.variants.iter().any(|variant| variant.ident == "ImageSnapshotCaptured"))),
        "finite acknowledged image capture uses the existing sealed observer");
    let observer = boot_progress::LocalBootProgressObserver::new();
    for expected in 1..=3 {
        observer.note(boot_progress::BootProgress::ImageSnapshotCaptured, false);
        assert_eq!(observer.epoch(), expected);
    }
    assert!(observer.note(boot_progress::BootProgress::ExplorerEndPaintObserved, true));
    observer.note(boot_progress::BootProgress::ImageSnapshotCaptured, false);
    assert_eq!(observer.epoch(), 4);
}
