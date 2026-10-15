//! Native wiring for the mixed-owner and retained-progress cases in client_frame_reclaim_tests.
use syn::{visit::Visit, Expr, Item, ItemFn, Stmt};

fn functions() -> Vec<ItemFn> {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/client_frame_retirement.rs"
    ))
    .unwrap()
    .items
    .into_iter()
    .filter_map(|item| match item {
        Item::Fn(function) => Some(function),
        _ => None,
    })
    .collect()
}

fn path(expression: &Expr, name: &str) -> bool {
    match expression {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name),
        Expr::Reference(reference) => path(&reference.expr, name),
        _ => false,
    }
}

fn field(expression: &Expr, member: &str) -> bool {
    matches!(expression, Expr::Field(field) if path(&field.base, "record") && matches!(&field.member, syn::Member::Named(name) if name == member))
}

#[derive(Default)]
struct Control {
    continues: usize,
    advances: usize,
    returns: usize,
    methods: Vec<String>,
    calls: Vec<String>,
}

impl<'ast> Visit<'ast> for Control {
    fn visit_expr_continue(&mut self, _: &'ast syn::ExprContinue) {
        self.continues += 1;
    }
    fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
        self.returns += 1;
    }
    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if path(&binary.left, "index") && matches!(binary.op, syn::BinOp::AddAssign(_)) {
            assert!(
                matches!(&*binary.right, Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Int(value) if matches!(value.base10_parse::<u64>(), Ok(1))))
            );
            self.advances += 1;
        }
        syn::visit::visit_expr_binary(self, binary);
    }
    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        assert!(
            !path(&assignment.left, "index"),
            "never change cursor after swap removal"
        );
        syn::visit::visit_expr_assign(self, assignment);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.calls.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn both_native_process_walks_are_owner_inclusive_and_swap_aware() {
    let functions = functions();
    assert_eq!(functions.len(), 2);
    for function in functions {
        let walk = function
            .block
            .stmts
            .iter()
            .find_map(|statement| match statement {
                Stmt::Expr(Expr::While(walk), _) => Some(walk),
                _ => None,
            })
            .expect("indexed registry walk");
        let Expr::Let(binding) = &*walk.cond else {
            panic!("retain selected row")
        };
        assert!(
            matches!(&*binding.pat, syn::Pat::TupleStruct(pattern) if pattern.path.is_ident("Some") && pattern.elems.len() == 1 && matches!(&pattern.elems[0], syn::Pat::Ident(record) if record.ident == "record"))
        );
        let Expr::MethodCall(selection) = &*binding.expr else {
            panic!("direct indexed selection")
        };
        assert_eq!(selection.method, "record_at");
        assert_eq!(selection.args.len(), 1);
        assert!(path(&selection.args[0], "index"));
        let Stmt::Expr(Expr::If(unrelated), _) = &walk.body.stmts[0] else {
            panic!("owner check first")
        };
        let Expr::Binary(owner) = &*unrelated.cond else {
            panic!("exact PI comparison")
        };
        assert!(
            matches!(owner.op, syn::BinOp::Ne(_))
                && field(&owner.left, "pi")
                && path(&owner.right, "pi")
        );
        let mut skipped = Control::default();
        skipped.visit_block(&unrelated.then_branch);
        assert_eq!((skipped.advances, skipped.continues), (1, 1));
        let mut all = Control::default();
        all.visit_block(&walk.body);
        assert_eq!(
            (all.advances, all.continues),
            (1, 1),
            "only unrelated owners may advance/skip"
        );
        assert!(!all.methods.iter().any(|name| name == "is_resident"
            || name == "is_reclaiming"
            || name == "first_page_for_process"));
        let lifetime = walk
            .body
            .stmts
            .iter()
            .position(|statement| match statement {
                Stmt::Expr(Expr::If(branch), _) => {
                    let Expr::Binary(condition) = &*branch.cond else {
                        return false;
                    };
                    if !field(&condition.left, "lifetime")
                        || !path(&condition.right, "lifetime")
                        || !matches!(condition.op, syn::BinOp::Ne(_))
                    {
                        return false;
                    }
                    let mut denied = Control::default();
                    denied.visit_block(&branch.then_branch);
                    assert_eq!(denied.returns, 1, "stale generations refuse, never skip");
                    true
                }
                _ => false,
            })
            .expect("lifetime refusal");
        let cleanup = walk
            .body
            .stmts
            .iter()
            .enumerate()
            .find_map(|(index, statement)| {
                let Stmt::Expr(Expr::Try(propagated), _) = statement else {
                    return None;
                };
                let Expr::Call(call) = &*propagated.expr else {
                    return None;
                };
                path(&call.func, "release_at_exact_with_access").then_some((index, call))
            })
            .expect("failure propagates without cursor advance");
        assert!(cleanup.0 > lifetime);
        let locked = walk
            .body
            .stmts
            .iter()
            .position(|statement| {
                let Stmt::Expr(Expr::If(branch), _) = statement else {
                    return false;
                };
                let mut condition = Control::default();
                condition.visit_expr(&branch.cond);
                if !condition
                    .calls
                    .iter()
                    .any(|name| name == "vm_page_lock_is_locked")
                {
                    return false;
                }
                let mut denied = Control::default();
                denied.visit_block(&branch.then_branch);
                assert_eq!(denied.returns, 1);
                true
            })
            .expect("locked backing refuses before cleanup");
        assert!(locked < cleanup.0);
        assert_eq!(cleanup.1.args.len(), 3);
        assert!(path(&cleanup.1.args[0], "index") && path(&cleanup.1.args[1], "record"));
    }
}

#[test]
fn native_indexed_release_uses_only_indexed_reclaim_transitions() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/client_frame_cleanup.rs"
    ))
    .unwrap();
    let function = source
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "release_at_exact_with_access" => {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    let mut calls = Control::default();
    calls.visit_block(&function.block);
    for method in [
        "record_at",
        "has_pending_transfer",
        "cancel_pageout_to_release_at_exact",
        "begin_reclaim_at_exact",
        "cleanup_reclaim_at_exact",
        "commit_reclaim_at_exact",
    ] {
        assert!(
            calls.methods.iter().any(|actual| actual == method),
            "missing {method}"
        );
    }
    for method in [
        "get",
        "get_with_index",
        "cancel_pageout_to_release_exact",
        "begin_reclaim_exact",
        "cleanup_reclaim_exact",
        "commit_reclaim_exact",
    ] {
        assert!(
            !calls.methods.iter().any(|actual| actual == method),
            "linear fallback {method}"
        );
    }
}
