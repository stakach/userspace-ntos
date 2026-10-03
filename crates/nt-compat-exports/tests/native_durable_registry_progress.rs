use syn::visit::Visit;

#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/boot_progress.rs"]
mod boot_progress;

fn explorer_chrome_runtime_milestones_reached() -> bool { false }
fn print_str(_: &[u8]) {}

fn parse(source: &str) -> syn::File {
    syn::parse_file(source).expect("native source parses")
}

fn path_ends(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

fn progress(call: &syn::ExprCall) -> bool {
    path_ends(&call.func, "note_boot_progress")
        && call.args.iter().any(|argument| path_ends(argument, "DurableRegistryPublication"))
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    for item in &file.items {
        match item {
            syn::Item::Fn(item) if item.sig.ident == name => return &item.block,
            syn::Item::Impl(item) => {
                for member in &item.items {
                    if let syn::ImplItem::Fn(method) = member {
                        if method.sig.ident == name { return &method.block; }
                    }
                }
            }
            _ => {}
        }
    }
    panic!("missing native function {name}")
}

fn nonzero_records(condition: &syn::Expr) -> bool {
    match condition {
        syn::Expr::Paren(inner) => nonzero_records(&inner.expr),
        syn::Expr::Binary(binary) => {
            path_ends(&binary.left, "records")
                && matches!(&*binary.right, syn::Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Int(value)
                        if matches!(value.base10_parse::<u64>(), Ok(0))))
                && matches!(binary.op, syn::BinOp::Ne(_) | syn::BinOp::Gt(_))
        }
        _ => false,
    }
}

#[test]
fn acknowledged_direct_journal_publication_reports_nonempty_durable_progress() {
    struct Audit { guarded: bool, found: usize, unguarded: usize }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let outer = self.guarded;
            self.guarded |= nonzero_records(&expression.cond);
            self.visit_block(&expression.then_branch);
            self.guarded = outer;
            if let Some((_, branch)) = &expression.else_branch { self.visit_expr(branch); }
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if progress(call) {
                self.found += 1;
                self.unguarded += usize::from(!self.guarded);
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let file = parse(include_str!("../../../components/ntos-executive/src/exec_handler.rs"));
    let mut audit = Audit { guarded: false, found: 0, unguarded: 0 };
    audit.visit_block(function(&file, "note_durable_hive_journal_records"));
    assert_eq!(audit.found, 1,
        "successful flushed/live-applied journal records must reach the sealed boot-progress observer");
    assert_eq!(audit.unguarded, 0, "zero records must not manufacture durable progress");
}

#[test]
fn cm_publication_reports_progress_only_after_acknowledged_commit() {
    struct Audit { acknowledged: bool, found: usize, premature: usize }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            if matches!(&*expression.expr, syn::Expr::Call(call)
                if matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.iter().map(|part| part.ident.to_string()).collect::<Vec<_>>()
                        == ["cm_mutation_transport", "commit"]))
            { self.acknowledged = true; }
            syn::visit::visit_expr_try(self, expression);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if progress(call) {
                self.found += 1;
                self.premature += usize::from(!self.acknowledged);
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    struct CommitArm { found: bool }
    impl<'ast> Visit<'ast> for CommitArm {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, syn::Pat::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "Commit"))
            {
                let mut audit = Audit { acknowledged: false, found: 0, premature: 0 };
                audit.visit_expr(&arm.body);
                assert_eq!(audit.found, 1, "acknowledged CM publication must report sealed progress");
                assert_eq!(audit.premature, 0, "prepare, durability and uncertain COMMIT are not publication ACKs");
                self.found = true;
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let file = parse(include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs"));
    let mut audit = CommitArm { found: false };
    audit.visit_block(function(&file, "advance"));
    assert!(audit.found, "audit the actual retained CM Commit phase");
}

#[test]
fn stall_epoch_reads_only_the_sealed_progress_observer() {
    struct Audit { closures: usize, epoch: usize, unsealed: usize }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "progress_epoch") {
                self.closures += 1;
                if let Some(initializer) = &local.init {
                    self.epoch += usize::from(path_ends(&initializer.expr, "boot_progress_epoch"));
                    self.visit_expr(&initializer.expr);
                }
            }
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.epoch += usize::from(path_ends(&call.func, "boot_progress_epoch"));
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.unsealed += usize::from(path.path.segments.iter()
                .any(|segment| segment.ident == "CM_RUNTIME_SYSTEM_MUTATION_COMMITS"));
        }
    }
    // Visit each local initializer, but inspect only the named watchdog epoch closure.
    struct Locals(Audit);
    impl<'ast> Visit<'ast> for Locals {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            self.0.visit_local(local);
            syn::visit::visit_local(self, local);
        }
    }
    let file = parse(include_str!("../../../components/ntos-executive/src/service_sec_image.rs"));
    let mut audit = Locals(Audit { closures: 0, epoch: 0, unsealed: 0 });
    audit.visit_file(&file);
    assert_eq!(audit.0.closures, 1);
    assert_eq!(audit.0.epoch, 1);
    assert_eq!(audit.0.unsealed, 0,
        "raw CM census counters must not bypass Explorer's sealed boot-progress epoch");
}

#[test]
fn durable_registry_progress_is_recurring_not_a_one_shot_milestone() {
    let file = parse(include_str!("../../../components/ntos-executive/src/boot_progress.rs"));
    let progress_enum = file.items.iter().find_map(|item| match item {
        syn::Item::Enum(item) if item.ident == "BootProgress" => Some(item),
        _ => None,
    }).unwrap();
    assert!(progress_enum.variants.iter().any(|variant| variant.ident == "DurableRegistryPublication"),
        "durable publication must use the existing sealed BootProgress authority");
    struct Audit(bool);
    impl<'ast> Visit<'ast> for Audit {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            struct Pattern(bool);
            impl<'ast> Visit<'ast> for Pattern {
                fn visit_path(&mut self, path: &'ast syn::Path) {
                    self.0 |= path.segments.last().is_some_and(|part| part.ident == "DurableRegistryPublication");
                }
            }
            let mut pattern = Pattern(false);
            pattern.visit_pat(&arm.pat);
            if pattern.0 {
                self.0 |= matches!(&*arm.body, syn::Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Int(value)
                        if matches!(value.base10_parse::<u64>(), Ok(0))));
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut audit = Audit(false);
    audit.visit_block(function(&file, "one_shot_bit"));
    assert!(audit.0, "each acknowledged registry publication may advance progress until sealing");
}

#[test]
fn actual_observer_counts_each_durable_publication_until_sealed() {
    use boot_progress::{BootProgress, LocalBootProgressObserver};
    let observer = LocalBootProgressObserver::new();
    assert_eq!(observer.epoch(), 0);
    for expected in 1..=3 {
        assert!(!observer.note(BootProgress::DurableRegistryPublication, false));
        assert_eq!(observer.epoch(), expected);
    }
    assert!(observer.note(BootProgress::ExplorerEndPaintObserved, true));
    assert_eq!(observer.epoch(), 4);
    for progress in [BootProgress::DurableRegistryPublication, BootProgress::ImageActivated,
        BootProgress::CredentialRetrieved, BootProgress::DialogModalCompleted] {
        assert!(!observer.note(progress, false));
        assert!(!observer.note(progress, true));
        assert_eq!(observer.epoch(), 4, "sealed observers reject recurring and one-shot events");
    }
}

#[test]
fn actual_observer_deduplicates_one_shots_without_suppressing_registry_publication() {
    use boot_progress::{BootProgress, LocalBootProgressObserver};
    let observer = LocalBootProgressObserver::new();
    for progress in [BootProgress::DialogModalCompleted, BootProgress::DialogModalDrained,
        BootProgress::UserShellImageAttempted, BootProgress::ExplorerMessageRegistrationObserved,
        BootProgress::ExplorerDirectDrawObserved, BootProgress::ExplorerBeginPaintObserved,
        BootProgress::ExplorerEndPaintObserved, BootProgress::ExplorerGdiBatchObserved] {
        let before = observer.epoch();
        assert!(!observer.note(progress, false));
        assert_eq!(observer.epoch(), before + 1);
        assert!(!observer.note(progress, false));
        assert_eq!(observer.epoch(), before + 1, "duplicate milestones are not progress");
        assert!(!observer.note(BootProgress::DurableRegistryPublication, false));
        assert_eq!(observer.epoch(), before + 2);
    }
}

#[test]
fn actual_observer_has_no_poll_or_wake_driven_epoch_effect() {
    use boot_progress::{BootProgress, LocalBootProgressObserver};
    let observer = LocalBootProgressObserver::new();
    // Queries and externally observed completion alone do not publish an event.
    for _ in 0..32 { assert_eq!(observer.epoch(), 0); }
    assert!(!observer.note(BootProgress::ExplorerBeginPaintObserved, false));
    let before = observer.epoch();
    assert!(!observer.note(BootProgress::ExplorerBeginPaintObserved, true));
    assert_eq!(observer.epoch(), before, "a duplicate event cannot fabricate a seal or progress");
    assert!(observer.note(BootProgress::ExplorerEndPaintObserved, true));
    assert_eq!(observer.epoch(), before + 1);
    assert!(!observer.note(BootProgress::ExplorerEndPaintObserved, true));
    assert_eq!(observer.epoch(), before + 1, "seal acknowledgement is one-shot");
}
