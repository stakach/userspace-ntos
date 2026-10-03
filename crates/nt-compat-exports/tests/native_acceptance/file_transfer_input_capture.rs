//! NT5 validates input extents early; buffered write copy follows Event/File acquisition.
use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<(String, Option<String>)>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expression.func {
            if let Some(name) = path.path.segments.last() {
                let input = expression.args.first().and_then(|argument| {
                    let syn::Expr::Path(path) = argument else { return None; };
                    path.path.segments.last().map(|part| part.ident.to_string())
                });
                self.0.push((name.ident.to_string(), input));
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }
    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        let input = expression.args.iter().nth(1).and_then(|argument| {
            let syn::Expr::Path(path) = argument else { return None; };
            path.path.segments.last().map(|part| part.ident.to_string())
        });
        self.0.push((expression.method.to_string(), input));
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn assert_checked_scalars(service: &str) -> Calls {
    let block = super::file_transfer_admission::service_branch(service);
    let mut calls = Calls::default();
    calls.visit_block(&block);
    assert!(!calls.0.iter().any(|(method, _)| method == "xas_read"),
        "{service} must not bypass canonical protections");
    let event = calls.0.iter().position(|(method, _)| method == "prepare_transfer_event")
        .expect("File operation prepares its Event");
    for scalar in ["byte_offset", "key"] {
        let capture = calls.0.iter().position(|(method, input)|
            method == "process_memory_read_status" && input.as_deref() == Some(scalar))
            .expect("optional scalar uses canonical checked capture");
        assert!(capture < event, "{scalar} capture precedes Event reset");
    }
    struct ExactErrors(usize);
    impl<'ast> Visit<'ast> for ExactErrors {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*expression.cond {
                if let (syn::Pat::TupleStruct(pattern), syn::Expr::MethodCall(call)) =
                    (&*condition.pat, &*condition.expr)
                {
                    if pattern.path.is_ident("Err") && call.method == "process_memory_read_status" {
                        let Some(syn::Pat::Ident(status)) = pattern.elems.first() else {
                            panic!("capture binds exact fault status");
                        };
                        assert!(expression.then_branch.stmts.iter().any(|statement|
                            matches!(statement, syn::Stmt::Expr(syn::Expr::Return(return_), _)
                                if matches!(return_.expr.as_deref(), Some(syn::Expr::Path(path))
                                    if path.path.is_ident(&status.ident)))),
                            "capture returns original exception without IOSB publication");
                        if matches!(call.args.iter().nth(1), Some(syn::Expr::Path(path))
                            if path.path.is_ident("buffer"))
                        {
                            let mut cleanup = Calls::default();
                            cleanup.visit_block(&expression.then_branch);
                            assert!(cleanup.0.iter().any(|(method, _)| matches!(method.as_str(),
                                "release_local_file_io_reference" | "release_file_reference")),
                                "late payload exception releases its acquired operation ownership");
                            assert!(!cleanup.0.iter().any(|(method, _)| matches!(method.as_str(),
                                "signal_file_completion" | "write_current_iosb"
                                | "stage_terminal_local_file_io" | "complete_terminal_file_io")),
                                "late exception must not become an I/O terminal completion");
                        }
                        self.0 += 1;
                    }
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut errors = ExactErrors(0);
    errors.visit_block(&block);
    assert!(errors.0 >= 2);
    calls
}

#[test]
fn read_offset_and_key_use_checked_capture_before_event_reset() {
    assert_checked_scalars("NtReadFile");
}

#[test]
fn promoted_transfer_restores_original_arguments_without_fresh_tail_capture() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/service_sec_image.rs"
    )).unwrap();
    struct Restore(bool);
    impl<'ast> Visit<'ast> for Restore {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*expression.cond {
                if matches!(&*condition.expr, syn::Expr::Path(path)
                    if path.path.is_ident("retained_arguments"))
                {
                    let mut retained = Calls::default();
                    retained.visit_block(&expression.then_branch);
                    assert!(retained.0.iter().any(|(name, _)| name == "copy_from_slice"),
                        "retained original arguments replace the retry transport vector");
                    assert!(!retained.0.iter().any(|(name, _)| matches!(name.as_str(),
                        "client_copyin_mapped" | "get_recv_mr" | "xas_read")),
                        "a promoted request cannot reread the original user stack or retry tail");
                    let mut fresh = Calls::default();
                    fresh.visit_expr(&expression.else_branch.as_ref()
                        .expect("fresh admission retains its ordinary argument capture").1);
                    assert!(fresh.0.iter().any(|(name, _)| name == "client_copyin_mapped"));
                    assert!(fresh.0.iter().any(|(name, _)| name == "get_recv_mr"));
                    struct CountGuard(bool);
                    impl<'ast> Visit<'ast> for CountGuard {
                        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
                            if matches!(&*expression.cond, syn::Expr::Binary(binary)
                                if matches!(binary.op, syn::BinOp::Ne(_))
                                    && matches!(&*binary.left, syn::Expr::Path(path) if path.path.is_ident("n"))
                                    && matches!(&*binary.right, syn::Expr::MethodCall(call)
                                        if call.method == "len" && matches!(&*call.receiver,
                                            syn::Expr::Path(path) if path.path.is_ident("arguments"))))
                            {
                                self.0 = expression.then_branch.stmts.iter().any(|statement|
                                    matches!(statement, syn::Stmt::Expr(syn::Expr::Assign(assign), _)
                                        if matches!(&*assign.left, syn::Expr::Path(path)
                                            if path.path.is_ident("stack_args_valid"))
                                        && matches!(&*assign.right, syn::Expr::Lit(literal)
                                            if matches!(&literal.lit, syn::Lit::Bool(value) if !value.value))));
                            }
                            syn::visit::visit_expr_if(self, expression);
                        }
                    }
                    let mut guard = CountGuard(false);
                    guard.visit_block(&expression.then_branch);
                    assert!(guard.0, "wrong argument-count metadata rejects retained restoration");
                    assert!(!self.0, "one argument restoration boundary");
                    self.0 = true;
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut restore = Restore(false);
    restore.visit_file(&file);
    assert!(restore.0, "exact admitted retry arguments precede fresh stack-tail decoding");
}

#[test]
fn buffered_write_copy_follows_event_and_file_acquisition_before_dispatch() {
    let calls = assert_checked_scalars("NtWriteFile");
    let event = calls.0.iter().position(|(method, _)| method == "prepare_transfer_event").unwrap();
    let copies: Vec<_> = calls.0.iter().enumerate().filter_map(|(index, (method, input))|
        (method == "process_memory_read_status" && input.as_deref() == Some("buffer"))
            .then_some(index)).collect();
    assert_eq!(copies.len(), 2, "local and hosted buffered writes each capture once");
    let local = calls.0.iter().position(|(method, _)| method == "begin_referenced_local_file_io").unwrap();
    let provider = calls.0.iter().position(|(method, _)| method == "dispatch_hosted_file_read_write_for").unwrap();
    let hosted = calls.0.iter().position(|(method, _)| method == "prepare_hosted_file_io").unwrap();
    assert!(event < local && local < copies[0]);
    assert!(hosted < copies[1] && copies[1] < provider);
    assert!(calls.0[hosted..copies[1]].iter().any(|(method, _)| method == "set_signaled"),
        "hosted File signal is cleared before buffered copy");
    let block = super::file_transfer_admission::service_branch("NtWriteFile");
    let mut extent = None;
    let mut scalar = None;
    for (index, statement) in block.stmts.iter().enumerate() {
        let mut calls = Calls::default();
        calls.visit_stmt(statement);
        if calls.0.iter().any(|(method, input)| method == "validate_transfer_input_extent"
            && input.as_deref() == Some("buffer")) { extent.get_or_insert(index); }
        if calls.0.iter().any(|(method, input)|
            method == "process_memory_read_status" && input.as_deref() == Some("byte_offset"))
        { scalar.get_or_insert(index); }
    }
    assert!(extent.expect("early extent-only bounds validation") < scalar.unwrap());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = std::fs::read_to_string(
        root.join("components/ntos-executive/src/exec_file_transfer.rs"),
    ).unwrap();
    let file = syn::parse_file(&source).unwrap();
    let validator = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "validate_transfer_input_extent" =>
            Some(&function.block),
        _ => None,
    }).expect("focused transfer extent validator");
    let mut validation_calls = Calls::default();
    validation_calls.visit_block(validator);
    assert!(validation_calls.0.iter().any(|(name, _)| name == "validate_user_probe"),
        "extent admission uses the authoritative user-range/alignment contract");
    assert!(!validation_calls.0.iter().any(|(name, _)| matches!(name.as_str(),
        "xas_read" | "process_memory_read_status" | "probe_copy_output")),
        "early extent admission must not touch payload pages");
}
