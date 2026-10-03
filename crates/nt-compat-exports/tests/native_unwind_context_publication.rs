use syn::visit::Visit;

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(&*function.block),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native unwind function {name}"))
}

#[derive(Default)]
struct Calls {
    paths: Vec<Vec<String>>,
    breaks: usize,
    continues: usize,
}

impl Calls {
    fn has(&self, name: &str) -> bool {
        self.paths
            .iter()
            .any(|path| path.last().is_some_and(|part| part == name))
    }
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths.push(
            path.segments
                .iter()
                .map(|part| part.ident.to_string())
                .collect(),
        );
        syn::visit::visit_path(self, path);
    }
    fn visit_expr_break(&mut self, value: &'ast syn::ExprBreak) {
        self.breaks += 1;
        syn::visit::visit_expr_break(self, value);
    }
    fn visit_expr_continue(&mut self, value: &'ast syn::ExprContinue) {
        self.continues += 1;
        syn::visit::visit_expr_continue(self, value);
    }
}

fn expression(statement: &syn::Stmt) -> Option<&syn::Expr> {
    match statement {
        syn::Stmt::Expr(expression, _) => Some(expression),
        _ => None,
    }
}

#[test]
fn native_unwind_publishes_completed_frames_but_not_target_caller() {
    let source = syn::parse_file(include_str!("../../nt-ntdll-dll/src/seh.rs")).unwrap();
    let body = function(&source, "rtl_unwind_ex_from_context");
    let walk = body
        .stmts
        .iter()
        .find_map(|statement| match expression(statement) {
            Some(syn::Expr::Loop(walk)) => Some(&walk.body),
            _ => None,
        })
        .expect("native unwind owns a frame walk");
    let mut leaf = None;
    let mut target = None;
    let mut publication = None;
    for (index, statement) in walk.stmts.iter().enumerate() {
        if let Some(syn::Expr::If(branch)) = expression(statement) {
            if matches!(&*branch.cond, syn::Expr::MethodCall(call)
                if call.method == "is_null" && matches!(&*call.receiver,
                    syn::Expr::Path(path) if path.path.is_ident("func")))
            {
                leaf = Some(&branch.then_branch);
            }
            if matches!(&*branch.cond, syn::Expr::Binary(condition)
                if matches!(&condition.op, syn::BinOp::Eq(_))
                    && matches!(&*condition.left, syn::Expr::Path(path) if path.path.is_ident("establisher"))
                    && matches!(&*condition.right, syn::Expr::Path(path) if path.path.is_ident("target_frame")))
            {
                let mut audit = Calls::default();
                audit.visit_block(&branch.then_branch);
                assert!(audit.breaks > 0, "target establisher ends the walk");
                assert!(
                    !audit.has("publish_completed_unwind_frame"),
                    "target virtual unwind describes its caller, not target restoration"
                );
                target = Some(index);
            }
        }
        let mut audit = Calls::default();
        audit.visit_stmt(statement);
        if audit.has("publish_completed_unwind_frame")
            && !matches!(expression(statement), Some(syn::Expr::If(_)))
        {
            publication = Some(index);
        }
    }
    let mut leaf_audit = Calls::default();
    leaf_audit.visit_block(leaf.expect("leaf frames have an explicit pop path"));
    assert!(
        leaf_audit.has("publish_completed_unwind_frame"),
        "completed leaf pop must update the retained restoration context"
    );
    assert!(leaf_audit.continues > 0);
    assert!(
        target.expect("target frame boundary") < publication.expect("non-target publication"),
        "non-target publication must follow the target establisher break"
    );
    assert_eq!(
        publication,
        Some(walk.stmts.len() - 1),
        "publish only after the non-target termination-handler outcome has been accepted"
    );
}

#[test]
fn native_publication_uses_shared_byte_exact_context_policy() {
    let source = syn::parse_file(include_str!("../../nt-ntdll-dll/src/seh.rs")).unwrap();
    let mut audit = Calls::default();
    audit.visit_block(function(&source, "publish_completed_unwind_frame"));
    assert!(
        audit.has("RawContext"),
        "native publication must preserve the full raw CONTEXT ABI"
    );
    assert!(audit.has("read_unaligned") && audit.has("write_unaligned"));
    assert!(
        audit.paths.iter().any(|path| path
            == &[
                "nt_ntdll",
                "rtl",
                "unwind_context",
                "publish_completed_frame"
            ]),
        "native publication must invoke the functionally tested shared policy"
    );
    for model_only in ["Context", "raw_to_context", "context_to_raw"] {
        assert!(
            !audit.has(model_only),
            "model-only publication loses raw CONTEXT fields: {model_only}"
        );
    }
}
