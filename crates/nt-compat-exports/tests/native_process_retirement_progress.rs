use syn::visit::Visit;

#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/boot_progress.rs"]
mod boot_progress;

fn explorer_chrome_runtime_milestones_reached() -> bool {
    false
}
fn print_str(_: &[u8]) {}

#[test]
fn completed_process_retirements_recur_until_the_real_observer_is_sealed() {
    use boot_progress::{BootProgress, LocalBootProgressObserver};
    let observer = LocalBootProgressObserver::new();
    assert!(!observer.note(BootProgress::ProcessRetired, false));
    assert_eq!(observer.epoch(), 1);
    assert!(!observer.note(BootProgress::ProcessRetired, false));
    assert_eq!(observer.epoch(), 2);
    assert!(observer.note(BootProgress::ProcessRetired, true));
    assert_eq!(observer.epoch(), 3);
    assert!(!observer.note(BootProgress::ProcessRetired, false));
    assert!(!observer.note(BootProgress::ImageSnapshotCaptured, true));
    assert_eq!(
        observer.epoch(),
        3,
        "retirement cannot reopen genuine Explorer completion"
    );
}

fn named(path: &syn::Path, name: &str) -> bool {
    path.segments.last().is_some_and(|part| part.ident == name)
}

#[derive(Default)]
struct Events(Vec<&'static str>);

impl<'ast> Visit<'ast> for Events {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, syn::Expr::Path(path) if named(&path.path, "note_boot_progress")) {
            assert_eq!(call.args.len(), 1);
            assert!(
                matches!(&call.args[0], syn::Expr::Path(path)
                if path.path.segments.len() >= 2 && named(&path.path, "ProcessRetired")),
                "retirement must use the sealed observer's exact event"
            );
            self.0.push("note");
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "release_exact"
            && matches!(&*call.receiver, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == "process_mechanisms"))
        {
            assert!(matches!(call.args.first(), Some(syn::Expr::Path(path))
                if named(&path.path, "process_mechanism")));
            self.0.push("release_mechanism");
        }
        if call.method == "release_native_process_image" {
            assert_eq!(call.args.len(), 3);
            assert!(matches!(&call.args[0], syn::Expr::Path(path) if named(&path.path, "pi")));
            assert!(matches!(&call.args[1], syn::Expr::Path(path) if named(&path.path, "pid")));
            assert!(matches!(&call.args[2], syn::Expr::Field(field)
                if matches!(&*field.base, syn::Expr::Path(path) if named(&path.path, "candidate"))
                && matches!(&field.member, syn::Member::Named(name) if name == "generation")));
            self.0.push("release_image");
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        if matches!(expression.expr.as_deref(), Some(syn::Expr::Path(path))
            if named(&path.path, "Complete"))
        {
            self.0.push("complete");
        }
        syn::visit::visit_expr_return(self, expression);
    }
}

#[test]
fn process_retirement_progress_follows_exact_release_and_never_pending_attempts() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_handler.rs"
    ))
    .unwrap();
    let function = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(function)
                if function.sig.ident == "try_delete_hosted_process_object_exact" =>
            {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    struct Phases {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Phases {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            let mut events = Events::default();
            events.visit_expr(&arm.body);
            if matches!(&arm.pat, syn::Pat::Path(path) if named(&path.path, "RetiringMechanism")) {
                assert_eq!(
                    events.0,
                    ["release_mechanism", "release_image", "note", "complete"],
                    "only completed exact mechanism/image retirement may refresh progress"
                );
                self.found = true;
            } else {
                assert!(
                    !events.0.contains(&"note"),
                    "pending phases do not publish retirement progress"
                );
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut phases = Phases { found: false };
    phases.visit_block(&function.block);
    assert!(phases.found);
    let mut all = Events::default();
    all.visit_block(&function.block);
    assert_eq!(
        all.0.iter().filter(|event| **event == "note").count(),
        1,
        "no early/stale/pending exit advances the observer"
    );
}
