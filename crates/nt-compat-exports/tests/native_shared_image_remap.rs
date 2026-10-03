use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("native image residency function")
}

#[derive(Default)]
struct Calls {
    names: Vec<String>,
    paths: Vec<String>,
    checked_page_end: bool,
    retirement_propagates: bool,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            let name = path.path.segments.last().unwrap().ident.to_string();
            if name == "shared_image_mapping_unmap_range" {
                assert_eq!(call.args.len(), 4, "retire an exact page range");
                for (argument, expected) in
                    call.args.iter().skip(1).take(2).zip(["process", "page"])
                {
                    assert!(
                        matches!(argument, Expr::Path(path) if path.path.is_ident(expected)),
                        "retain the exact captured process and fault page identity"
                    );
                }
            }
            self.names.push(name);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "checked_add"
            && matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("page"))
        {
            self.checked_page_end |= matches!(call.args.first(), Some(Expr::Lit(literal))
                if matches!(&literal.lit, syn::Lit::Int(value)
                    if matches!(value.base10_parse::<u64>(), Ok(4096))));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        let mut inner = Calls::default();
        inner.visit_expr(&expression.expr);
        self.retirement_propagates |= inner
            .names
            .iter()
            .any(|name| name == "shared_image_mapping_unmap_range");
        syn::visit::visit_expr_try(self, expression);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths
            .push(path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_path(self, path);
    }
}

#[test]
fn exact_old_shared_mapping_retirement_precedes_new_page_map() {
    let file = source("service_sec_image.rs");
    let residency = function(&file, "service_image_page_residency");
    let mut calls = Calls::default();
    calls.visit_block(&residency.block);
    let retirement = calls
        .names
        .iter()
        .position(|name| name == "shared_image_mapping_unmap_range")
        .expect("acknowledge exact old shared mapping retirement before replacing its leaf");
    let mapping = calls
        .names
        .iter()
        .position(|name| name == "page_map_r")
        .expect("actual native page mapping effect");
    assert!(
        retirement < mapping,
        "deleting an old same-frame mapping after PageMap removes the new leaf"
    );
    assert!(
        calls.retirement_propagates,
        "a failed old-cap retirement must prevent the new mapping effect"
    );
    assert!(
        calls.checked_page_end,
        "retire exactly one page with checked end arithmetic"
    );
    assert!(
        calls
            .names
            .iter()
            .any(|name| name == "shared_image_mapping_put_banked"),
        "publish the newly mapped cap without post-map old-cap deletion"
    );
    assert!(!calls
        .names
        .iter()
        .any(|name| name == "shared_image_mapping_replace_banked_after_map"));
}

fn positive_conjunction(expression: &Expr, names: &mut Vec<String>) -> bool {
    match expression {
        Expr::Path(path) if path.path.segments.len() == 1 => {
            names.push(path.path.segments[0].ident.to_string());
            true
        }
        Expr::Binary(binary) if matches!(binary.op, syn::BinOp::And(_)) => {
            positive_conjunction(&binary.left, names) && positive_conjunction(&binary.right, names)
        }
        Expr::Paren(paren) => positive_conjunction(&paren.expr, names),
        _ => false,
    }
}

#[derive(Default)]
struct RetirementGuard {
    guarded: bool,
    calls: usize,
    exact_conditions: Vec<String>,
}

impl<'ast> Visit<'ast> for RetirementGuard {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (syn::Pat::Ident(binding), Some(initializer)) = (&local.pat, &local.init) {
            let mut names = Vec::new();
            let exact = positive_conjunction(&initializer.expr, &mut names);
            names.sort();
            if binding.mutability.is_none()
                && exact
                && names == ["fault_observed", "shareable", "shared_mapping_registered"]
            {
                self.exact_conditions.push(binding.ident.to_string());
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        let mut names = Vec::new();
        let exact = positive_conjunction(&branch.cond, &mut names);
        names.sort();
        let prior = self.guarded;
        let captured_exact_condition = matches!(&*branch.cond, Expr::Path(path)
            if path.path.segments.len() == 1
                && self.exact_conditions.contains(&path.path.segments[0].ident.to_string()));
        self.guarded |= captured_exact_condition
            || (exact && names == ["fault_observed", "shareable", "shared_mapping_registered"]);
        self.visit_block(&branch.then_branch);
        self.guarded = prior;
        if let Some((_, otherwise)) = &branch.else_branch {
            self.visit_expr(otherwise);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, Expr::Path(path)
            if path.path.segments.last().unwrap().ident == "shared_image_mapping_unmap_range")
        {
            self.calls += 1;
            assert!(self.guarded,
                "do not retire private, fresh, or non-observed mappings while making a page resident");
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn old_mapping_retirement_is_only_for_observed_registered_shared_faults() {
    let file = source("service_sec_image.rs");
    let mut guard = RetirementGuard::default();
    guard.visit_block(&function(&file, "service_image_page_residency").block);
    assert_eq!(guard.calls, 1, "one exact shared fault retirement boundary");
}

#[derive(Default)]
struct DeleteAcknowledgement {
    found: bool,
}

impl<'ast> Visit<'ast> for DeleteAcknowledgement {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        let mut condition = Calls::default();
        condition.visit_expr(&branch.cond);
        if condition
            .names
            .iter()
            .any(|name| name == "shared_image_mapping_delete_cap")
        {
            self.found = true;
            let mut success = Calls::default();
            success.visit_block(&branch.then_branch);
            assert!(
                success
                    .names
                    .iter()
                    .any(|name| name == "shared_image_mapping_remove_at"),
                "remove the exact owned row only after acknowledged cap deletion"
            );
            let mut failure = Calls::default();
            failure.visit_expr(
                &branch
                    .else_branch
                    .as_ref()
                    .expect("deletion failure is explicit")
                    .1,
            );
            assert!(
                failure.names.iter().any(|name| name == "Err"),
                "failed deletion must propagate failure"
            );
            assert!(
                !failure
                    .names
                    .iter()
                    .any(|name| name == "shared_image_mapping_remove_at"),
                "failed deletion retains the original ownership row for retry"
            );
        }
        syn::visit::visit_expr_if(self, branch);
    }
}

#[test]
fn range_retirement_validates_generation_before_effect_and_retains_failed_rows() {
    let file = source("main.rs");
    let retirement = function(&file, "shared_image_mapping_unmap_range");
    let mut first = Calls::default();
    first.visit_stmt(
        retirement
            .block
            .stmts
            .first()
            .expect("range validation before mutation"),
    );
    assert!(
        first
            .names
            .iter()
            .any(|name| name == "shared_image_mapping_validate_range_for"),
        "prevalidate every matching ProcessIdentity before any native cap deletion"
    );
    assert!(
        matches!(
            retirement.block.stmts.first(),
            Some(syn::Stmt::Expr(Expr::Try(_), _))
        ),
        "generation validation failure must propagate before effects"
    );
    let mut acknowledgement = DeleteAcknowledgement::default();
    acknowledgement.visit_block(&retirement.block);
    assert!(
        acknowledgement.found,
        "native deletion acknowledgement boundary"
    );
}

#[derive(Default)]
struct UnprovenSuccess {
    found: bool,
}

impl<'ast> Visit<'ast> for UnprovenSuccess {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        let mut condition = Calls::default();
        condition.visit_expr(&branch.cond);
        let mut body = Calls::default();
        body.visit_block(&branch.then_branch);
        self.found |= condition
            .paths
            .iter()
            .any(|name| name == "duplicate_shared_fault")
            && body.names.iter().any(|name| name == "Ok");
        syn::visit::visit_expr_if(self, branch);
    }
}

#[test]
fn delete_first_is_not_a_successful_shared_mapping_receipt() {
    let file = source("service_sec_image.rs");
    let residency = function(&file, "service_image_page_residency");
    let mut visitor = UnprovenSuccess::default();
    visitor.visit_block(&residency.block);
    assert!(
        !visitor.found,
        "cached frame/catalog membership cannot prove a leaf exists after failed PageMap"
    );
}

#[test]
fn obsolete_post_map_cap_deletion_helper_is_removed() {
    let file = source("main.rs");
    assert!(
        !file
            .items
            .iter()
            .any(|item| matches!(item, Item::Fn(function)
        if function.sig.ident == "shared_image_mapping_replace_banked_after_map")),
        "remove the sole-caller helper that deletes the freshly replaced same-frame leaf"
    );
}
