//! IopCreateFile probes outputs before opening and publishes Handle before IOSB.
use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.0.push(expression.method.to_string());
        syn::visit::visit_expr_method_call(self, expression);
    }
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expression.func {
            if let Some(name) = path.path.segments.last() {
                self.0.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

fn handler_function(name: &str) -> syn::ImplItemFn {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    file.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == name =>
                Some(function.clone()),
            _ => None,
        })
    }).expect("native OpenFile boundary")
}

fn open_service() -> syn::ImplItemFn {
    handler_function("nt_open_file_service")
}

#[test]
fn open_file_outputs_are_probed_before_object_attributes_or_loader_effects() {
    let function = open_service();
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    let probe = calls.0.iter().position(|name| name == "probe_file_io_output")
        .expect("typed IOSB output probe");
    let handle_probe = calls.0.iter().position(|name| name == "probe_copy_output")
        .expect("typed Handle output probe");
    assert!(handle_probe < probe, "Handle probe precedes IOSB probe");
    for effect in ["capture_file_object_attributes", "demand_load_dll_result", "mint_disk_file_handle"] {
        assert!(probe < calls.0.iter().position(|name| name == effect).unwrap(),
            "output fault precedes {effect}");
    }
}

#[test]
fn checked_loader_publication_commits_handle_before_iosb_without_late_rollback() {
    let function = handler_function("publish_loader_file_open_result");
    let Some(syn::Stmt::Expr(syn::Expr::Try(first), _)) = function.block.stmts.first() else {
        panic!("Handle copy must propagate its exact fault before IOSB publication");
    };
    let syn::Expr::MethodCall(handle) = &*first.expr else { panic!("checked Handle copy"); };
    assert_eq!(handle.method, "process_memory_write_status");
    assert!(matches!(handle.args.iter().nth(1), Some(syn::Expr::Path(path))
        if path.path.is_ident("file_handle_out")));
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    let handle = calls.0.iter().position(|name| name == "process_memory_write_status").unwrap();
    let iosb = calls.0.iter().position(|name| name == "publish_file_io_status").unwrap();
    assert!(handle < iosb, "canonical IOSB publisher orders Information then Status after Handle");
    assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
        "close_current_handle" | "close_process_handle" | "release_handle" | "queue_write")),
        "a late fault must not invalidate the already committed handle or discard publication errors");
    assert!(calls.0.iter().any(|name| name == "map_err"),
        "IOSB copy failure preserves its typed fault status");
}

#[test]
fn loader_open_result_uses_checked_publication_not_fire_and_forget_writes() {
    struct LoaderArm(Option<syn::Block>);
    impl<'ast> Visit<'ast> for LoaderArm {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*expression.cond {
                if matches!(&*condition.expr, syn::Expr::Path(path)
                    if path.path.is_ident("loader_open"))
                {
                    assert!(self.0.is_none());
                    self.0 = Some(expression.then_branch.clone());
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut arm = LoaderArm(None);
    arm.visit_block(&open_service().block);
    let arm = arm.0.expect("successful canonical loader File branch");
    let mut calls = Calls::default();
    calls.visit_block(&arm);
    assert!(calls.0.iter().any(|name| name == "publish_loader_file_open_result"),
        "loader branch uses checked Handle then IOSB publication");
    assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
        "smss_stack_write" | "smss_stack_write32" | "queue_write"
        | "write_nt_open_file_handle_out")),
        "loader output cannot discard a copy fault or defer an unchecked write");
    struct ExactFault(bool);
    impl<'ast> Visit<'ast> for ExactFault {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*expression.cond {
                if let (syn::Pat::TupleStruct(pattern), syn::Expr::MethodCall(call)) =
                    (&*condition.pat, &*condition.expr)
                {
                    if pattern.path.is_ident("Err") && call.method == "publish_loader_file_open_result" {
                        let Some(syn::Pat::Ident(status)) = pattern.elems.first() else { panic!("fault binding"); };
                        self.0 = expression.then_branch.stmts.iter().any(|statement|
                            matches!(statement, syn::Stmt::Expr(syn::Expr::Return(return_), _)
                                if matches!(return_.expr.as_deref(), Some(syn::Expr::Path(path))
                                    if path.path.is_ident(&status.ident))));
                    }
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut fault = ExactFault(false);
    fault.visit_block(&arm);
    assert!(fault.0, "publication fault returns its original exception status");
}

#[test]
fn internal_loader_record_failure_retires_only_its_unpublished_minted_handle() {
    struct RecordFailure(bool);
    impl<'ast> Visit<'ast> for RecordFailure {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*expression.cond {
                if matches!(&*condition.expr, syn::Expr::Call(call)
                    if matches!(&*call.func, syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|part|
                            part.ident == "record_hosted_child_exe_open")))
                {
                    struct CheckedClose(bool);
                    impl<'ast> Visit<'ast> for CheckedClose {
                        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                            if call.method == "close_process_handle_checked" {
                                assert!(matches!(call.args.iter().nth(1), Some(syn::Expr::Path(path))
                                    if path.path.is_ident("h")),
                                    "rollback closes the exact newly minted handle");
                                self.0 = true;
                            }
                            syn::visit::visit_expr_method_call(self, call);
                        }
                    }
                    let mut close = CheckedClose(false);
                    close.visit_block(&expression.then_branch);
                    assert!(close.0, "internal prepublication failure must retire its acquired handle");
                    let mut calls = Calls::default();
                    calls.visit_block(&expression.then_branch);
                    assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
                        "close_current_handle" | "close_process_handle" | "publish_loader_file_open_result")),
                        "rollback is checked and cannot publish the failed open");
                    self.0 = true;
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut failure = RecordFailure(false);
    failure.visit_block(&open_service().block);
    assert!(failure.0, "loader record admission failure boundary exists");
}
