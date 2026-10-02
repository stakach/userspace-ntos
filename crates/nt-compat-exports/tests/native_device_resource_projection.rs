use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, Pat, Stmt};

#[derive(Default)]
struct Facts {
    calls: Vec<String>,
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for Facts {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths
            .push(path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_path(self, path);
    }
}

fn facts(expression: &Expr) -> Facts {
    let mut result = Facts::default();
    result.visit_expr(expression);
    result
}

fn statement_facts(statement: &Stmt) -> Facts {
    let mut result = Facts::default();
    result.visit_stmt(statement);
    result
}

fn tuple_pattern(pat: &Pat, name: &str) -> bool {
    matches!(pat, Pat::TupleStruct(pat) if pat.path.segments.last().unwrap().ident == name)
}

#[derive(Default)]
struct RestoreContract {
    selected_binding: bool,
    errors_return_not_dispatched: bool,
}

impl<'ast> Visit<'ast> for RestoreContract {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, Expr::Path(path)
            if path.path.segments.last().unwrap().ident == "restore_hosted_device_resource_state")
        {
            self.selected_binding |= matches!(call.args.first(), Some(Expr::Path(path))
                if path.path.is_ident("binding"));
            assert!(
                matches!(call.args.iter().nth(1), Some(Expr::Path(path))
                if path.path.is_ident("sh")),
                "restore the actual selected dispatch bank"
            );
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        if let Expr::Let(condition) = &*branch.cond {
            if tuple_pattern(&condition.pat, "Err")
                && facts(&*condition.expr)
                    .calls
                    .iter()
                    .any(|call| call == "restore_hosted_device_resource_state")
            {
                let mut body = Facts::default();
                body.visit_block(&branch.then_branch);
                self.errors_return_not_dispatched |=
                    body.paths.iter().any(|path| path == "NotDispatched")
                        && body.paths.iter().any(|path| path == "status");
            }
        }
        syn::visit::visit_expr_if(self, branch);
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        if facts(&*expression.expr)
            .calls
            .iter()
            .any(|call| call == "restore_hosted_device_resource_state")
        {
            for arm in &expression.arms {
                if tuple_pattern(&arm.pat, "Err") {
                    let body = facts(&*arm.body);
                    self.errors_return_not_dispatched |=
                        body.paths.iter().any(|path| path == "NotDispatched")
                            && body.paths.iter().any(|path| path == "status");
                }
            }
        }
        syn::visit::visit_expr_match(self, expression);
    }
}

#[test]
fn ordinary_dispatch_restores_selected_device_resources_before_native_entry() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/driver_launch.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let dispatch = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "dispatch_irp_for_instance_exact" => {
                Some(function)
            }
            _ => None,
        })
        .expect("exact native device dispatch engine");
    let (position, ordinary) = dispatch.block.stmts.iter().enumerate().find_map(|(position, statement)| {
        let Stmt::Expr(Expr::If(branch), _) = statement else { return None };
        let Expr::Let(condition) = &*branch.cond else { return None };
        if !matches!(&*condition.expr, Expr::Path(path) if path.path.is_ident("provider_binding")) {
            return None;
        }
        let mut redirected = Facts::default();
        redirected.visit_block(&branch.then_branch);
        assert!(redirected.calls.iter().any(|call| call == "project_provider_device_dispatch_state"),
            "retain the real selected provider redirection projection");
        Some((position, branch.else_branch.as_ref().expect(
            "ordinary dispatch must restore its selected canonical device resources, not retain a stale singleton bank").1.as_ref()))
    }).expect("selected provider/ordinary projection boundary");
    let ordinary_facts = facts(ordinary);
    assert!(
        ordinary_facts
            .paths
            .iter()
            .any(|path| path == "dispatch_binding"),
        "ordinary restoration must use the already authenticated exact dispatch binding"
    );
    let mut contract = RestoreContract::default();
    contract.visit_expr(ordinary);
    assert!(
        contract.selected_binding,
        "restore the selected binding's canonical resource state"
    );
    assert!(
        contract.errors_return_not_dispatched,
        "propagate restoration failure as NotDispatched with its actual status"
    );
    for statement in &dispatch.block.stmts[..position] {
        assert!(
            !statement_facts(statement)
                .calls
                .iter()
                .any(|call| call == "enter_active_hosted_irp_transfer" || call == "component_pump"),
            "resource restoration must precede native dispatch effects"
        );
    }
    assert!(
        dispatch.block.stmts[position + 1..]
            .iter()
            .any(|statement| statement_facts(statement)
                .calls
                .iter()
                .any(|call| call == "enter_active_hosted_irp_transfer")),
        "check ordering against the actual owned dispatch entry"
    );
}
