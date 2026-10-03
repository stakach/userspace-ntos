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
fn file_object_attributes_preserve_all_three_checked_read_faults() {
    let function = handler_function("capture_file_object_attributes");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    assert!(!calls.0.iter().any(|name| name == "xas_read"));
    struct CheckedReads(Vec<String>);
    impl<'ast> Visit<'ast> for CheckedReads {
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            if let syn::Expr::MethodCall(call) = &*expression.expr {
                if call.method == "process_memory_read_status" {
                    assert_eq!(call.args.len(), 3);
                    assert!(matches!(call.args.first(), Some(syn::Expr::Field(field))
                        if matches!(&field.member, syn::Member::Named(name) if name == "pi")));
                    let Some(syn::Expr::Path(address)) = call.args.iter().nth(1) else {
                        panic!("captured address must remain exact");
                    };
                    self.0.push(address.path.segments.last().unwrap().ident.to_string());
                }
            }
            syn::visit::visit_expr_try(self, expression);
        }
    }
    let mut checked = CheckedReads(Vec::new());
    checked.visit_block(&function.block);
    assert_eq!(checked.0, ["oa_va", "object_name", "buffer"]);
}

fn create_service() -> syn::ImplItemFn {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_file_create.rs");
    let source = std::fs::read_to_string(path).expect("focused native create boundary");
    let file = syn::parse_file(&source).unwrap();
    file.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "nt_create_file_service" =>
                Some(function.clone()),
            _ => None,
        })
    }).expect("extracted create service")
}

#[test]
fn create_file_typed_output_probes_precede_object_attribute_capture() {
    let mut calls = Calls::default();
    calls.visit_block(&create_service().block);
    let handle = calls.0.iter().position(|name| name == "probe_copy_output")
        .expect("typed Handle probe");
    let iosb = calls.0.iter().position(|name| name == "probe_file_io_output")
        .expect("typed IOSB probe");
    let attributes = calls.0.iter().position(|name| name == "capture_file_object_attributes")
        .expect("object attributes capture");
    assert!(handle < iosb && iosb < attributes);
    assert!(!calls.0.iter().any(|name| name == "probe_user_output"));
}

#[test]
fn create_file_parameter_validation_precedes_output_probes() {
    let mut calls = Calls::default();
    calls.visit_block(&create_service().block);
    let parameters = calls.0.iter().position(|name| name == "validate_file_create_parameters")
        .expect("authoritative create parameter validation");
    let handle = calls.0.iter().position(|name| name == "probe_copy_output")
        .expect("typed Handle probe");
    assert!(parameters < handle, "invalid create flags must not consume output GUARD");
}

#[test]
fn create_file_pointed_inputs_are_captured_before_object_attributes() {
    struct InputOrder {
        ordinal: usize,
        reads: Vec<(usize, usize)>,
        attributes: Option<usize>,
    }
    impl<'ast> Visit<'ast> for InputOrder {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            let ordinal = self.ordinal;
            self.ordinal += 1;
            if call.method == "capture_file_object_attributes" {
                assert!(self.attributes.replace(ordinal).is_none());
            }
            if call.method == "process_memory_read_status" {
                let Some(syn::Expr::Index(address)) = call.args.iter().nth(1) else {
                    panic!("pointed input retains its exact argument address");
                };
                assert!(matches!(&*address.expr, syn::Expr::Path(path) if path.path.is_ident("args")));
                let syn::Expr::Lit(index) = &*address.index else { panic!("argument index"); };
                let syn::Lit::Int(index) = &index.lit else { panic!("integer index"); };
                self.reads.push((index.base10_parse().unwrap(), ordinal));
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut order = InputOrder { ordinal: 0, reads: Vec::new(), attributes: None };
    order.visit_block(&create_service().block);
    assert_eq!(order.reads.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [4, 9]);
    let attributes = order.attributes.expect("OA capture");
    assert!(order.reads.iter().all(|(_, ordinal)| *ordinal < attributes),
        "AllocationSize and EA faults must precede object-attribute resolution");
}

#[test]
fn direct_create_final_results_use_common_checked_publisher() {
    let mut calls = Calls::default();
    calls.visit_block(&create_service().block);
    assert!(calls.0.iter().any(|name| name == "publish_file_create_result"));
    for obsolete in ["queue_write", "smss_stack_write", "xas_write_buf",
                     "xas_try_write_buf", "write_nt_open_file_handle_out"] {
        assert!(!calls.0.iter().any(|name| name == obsolete),
            "final create results must not bypass checked publication through {obsolete}");
    }
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
    let function = handler_function("publish_file_create_result");
    struct CheckedPublisher(bool);
    impl<'ast> Visit<'ast> for CheckedPublisher {
        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if matches!(&*expression.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part|
                    part.ident == "publish_file_create_result_checked"))
            {
                assert_eq!(expression.args.len(), 6);
                for (index, expected) in ["file_handle_out", "iosb", "handle", "status", "information"]
                    .iter().enumerate()
                {
                    assert!(matches!(expression.args.iter().nth(index), Some(syn::Expr::Path(path))
                        if path.path.is_ident(*expected)), "preserved {expected} publication argument");
                }
                let Some(syn::Expr::Closure(copy)) = expression.args.last() else {
                    panic!("shared publisher requires the actual checked memory-copy boundary");
                };
                assert!(matches!(&*copy.body, syn::Expr::MethodCall(call)
                    if call.method == "process_memory_write_checked"
                        && matches!(call.args.first(), Some(syn::Expr::Field(field))
                            if matches!(&field.member, syn::Member::Named(name) if name == "pi"))),
                    "publication callback preserves target process identity and typed failure");
                self.0 = true;
            }
            syn::visit::visit_expr_call(self, expression);
        }
    }
    let mut checked = CheckedPublisher(false);
    checked.visit_block(&function.block);
    assert!(checked.0, "live native helper delegates to the tested status-aware checked publisher");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
        "close_current_handle" | "close_process_handle" | "close_process_handle_checked"
        | "release_handle" | "queue_write" | "process_memory_write_status" | "publish_file_io_status")),
        "a late fault must not invalidate the already committed handle or discard publication errors");
    assert!(calls.0.iter().any(|name| name == "map_err"),
        "IOSB copy failure preserves its typed fault status");
    struct FaultStatus(bool);
    impl<'ast> Visit<'ast> for FaultStatus {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "map_err" {
                self.0 |= matches!(call.args.first(), Some(syn::Expr::Path(path))
                    if path.path.segments.len() >= 2
                        && path.path.segments[path.path.segments.len() - 2].ident == "MemoryCopyFailure"
                        && path.path.segments.last().unwrap().ident == "status");
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut fault = FaultStatus(false);
    fault.visit_block(&function.block);
    assert!(fault.0, "the returned copy exception is not collapsed or replaced");
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
    assert!(calls.0.iter().any(|name| name == "publish_file_create_result"),
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
                    if pattern.path.is_ident("Err") && call.method == "publish_file_create_result" {
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
                        "close_current_handle" | "close_process_handle" | "publish_file_create_result")),
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

#[test]
fn finalized_open_routes_share_checked_publication_without_error_output_stores() {
    for name in ["nt_open_file_service", "create_registered_kernel_file"] {
        let function = handler_function(name);
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        assert!(calls.0.iter().any(|name| name == "publish_file_create_result"),
            "{name} must use the common status-aware publication boundary");
        assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
            "queue_write" | "xas_write_buf" | "xas_try_write_buf"
            | "smss_stack_write" | "smss_stack_write32" | "write_nt_open_file_handle_out"
            | "publish_loader_file_open_result")),
            "{name} cannot retain a private unchecked or unconditional final-output path");
    }
}
