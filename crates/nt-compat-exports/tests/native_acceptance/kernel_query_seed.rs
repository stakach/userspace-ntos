//! Kernel targets must receive the same complete FileAll seed as driver-peer targets.

use syn::visit::Visit;

#[derive(Default)]
struct Paths(Vec<String>);
impl<'ast> Visit<'ast> for Paths {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(segment) = path.segments.last() {
            self.0.push(segment.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }
}

fn kernel_branch() -> syn::Block {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/driver_launch.rs"),
    ).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function)
            if function.sig.ident == "dispatch_external_irp_to_device_record_result_exact" =>
                Some(function),
        _ => None,
    }).expect("exact external File dispatch boundary");
    struct Find(Option<syn::Block>);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let mut paths = Paths::default();
            paths.visit_expr(&expression.cond);
            if paths.0.iter().any(|path| path == "registered_file_target")
                && paths.0.iter().any(|path| path == "Kernel")
            {
                assert!(self.0.is_none(), "kernel target selection must be unique");
                self.0 = Some(expression.then_branch.clone());
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut find = Find(None);
    find.visit_block(&function.block);
    find.0.expect("registered kernel target branch")
}

#[test]
fn kernel_target_preserves_whole_output_seed_and_initial_information() {
    let branch = kernel_branch();
    #[derive(Default)]
    struct Boundary {
        seed_policy: bool,
        copied_seed: bool,
        seeded_dispatch: bool,
        rejects_seed_as_unsupported: bool,
    }
    impl<'ast> Visit<'ast> for Boundary {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let mut condition = Paths::default();
            condition.visit_expr(&expression.cond);
            let mut effects = Paths::default();
            effects.visit_block(&expression.then_branch);
            self.rejects_seed_as_unsupported |=
                condition.0.iter().any(|path| path == "initial_information")
                && effects.0.iter().any(|path| path == "NOT_SUPPORTED");
            syn::visit::visit_expr_if(self, expression);
        }

        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*expression.func {
                self.seed_policy |= path.path.segments.last()
                    .is_some_and(|part| part.ident == "initial_output_required");
            }
            syn::visit::visit_expr_call(self, expression);
        }

        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.method == "copy_from_slice"
                && expression.args.len() == 1
                && matches!(expression.args.first(), Some(syn::Expr::Path(path))
                    if path.path.is_ident("out"))
            {
                assert!(!self.seeded_dispatch, "seed copying must precede backend entry");
                let syn::Expr::Index(destination) = &*expression.receiver else {
                    panic!("seed must populate the canonical transfer buffer");
                };
                assert!(matches!(&*destination.expr, syn::Expr::Path(path)
                    if path.path.is_ident("buffer")));
                let syn::Expr::Range(range) = &*destination.index else {
                    panic!("the whole seed needs a complete output slice");
                };
                assert!(range.start.is_none());
                assert!(matches!(range.end.as_deref(), Some(syn::Expr::MethodCall(end))
                    if end.method == "len" && end.args.is_empty()
                    && matches!(&*end.receiver, syn::Expr::Path(path) if path.path.is_ident("out"))));
                self.copied_seed = true;
            }
            if expression.method ==
                "build_and_dispatch_external_to_device_with_stack_flags_and_initial_information"
            {
                assert!(self.copied_seed, "canonical dispatch must see the original output seed");
                assert!(matches!(expression.args.iter().nth(expression.args.len() - 2),
                    Some(syn::Expr::Path(path)) if path.path.is_ident("initial_information")),
                    "initial IoStatus.Information must reach canonical IRP construction unchanged");
                self.seeded_dispatch = true;
            }
            syn::visit::visit_expr_method_call(self, expression);
        }
    }
    let mut boundary = Boundary::default();
    boundary.visit_block(&branch);
    assert!(!boundary.rejects_seed_as_unsupported,
        "a valid seeded query is not an unsupported kernel operation");
    assert!(boundary.seed_policy, "output seeding must use the shared admission policy");
    assert!(boundary.copied_seed, "all discontiguous manager fields must reach the backend");
    assert!(boundary.seeded_dispatch, "canonical IRP construction must retain the initial scalar");
}
