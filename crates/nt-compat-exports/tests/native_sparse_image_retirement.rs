use syn::{visit::Visit, Expr, Stmt};

fn source() -> syn::ItemFn {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/image_range_retirement.rs"
    ))
    .unwrap()
    .items
    .into_iter()
    .find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "vm_unmap_shared_image_mapping_range" => {
            Some(function)
        }
        _ => None,
    })
    .expect("image range retirement entrypoint")
}

fn path(expression: &Expr, name: &str) -> bool {
    match expression {
        Expr::Cast(cast) => path(&cast.expr, name),
        Expr::Paren(paren) => path(&paren.expr, name),
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name),
        _ => false,
    }
}

#[derive(Default)]
struct Calls {
    calls: Vec<syn::ExprCall>,
    methods: Vec<syn::ExprMethodCall>,
    returns: bool,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.calls.push(call.clone());
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.clone());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        self.returns = true;
        syn::visit::visit_expr_return(self, expression);
    }
}

fn calls(statement: &Stmt) -> Calls {
    let mut calls = Calls::default();
    calls.visit_stmt(statement);
    calls
}

fn contains(statement: &Stmt, name: &str) -> bool {
    calls(statement)
        .calls
        .iter()
        .any(|call| path(&call.func, name))
}

fn registry_reference(expression: &Expr, name: &str) -> bool {
    match expression {
        Expr::Reference(reference) => registry_reference(&reference.expr, name),
        Expr::Unary(unary) => registry_reference(&unary.expr, name),
        Expr::Macro(expression) => syn::parse2::<Expr>(expression.mac.tokens.clone())
            .is_ok_and(|argument| path(&argument, name)),
        _ => false,
    }
}

#[test]
fn range_admission_precedes_sparse_selection_even_with_no_candidates() {
    let function = source();
    let statements = &function.block.stmts;
    let selection = statements
        .iter()
        .position(|statement| contains(statement, "next_private_page_in_range"))
        .expect("range retirement must select recorded backing, not walk virtual pages");
    for preflight in [
        "hosted_thread_memory_retirement_access",
        "vm_page_lock_range_is_locked",
        "shared_image_mapping_validate_range_for",
    ] {
        let position = statements
            .iter()
            .position(|statement| contains(statement, preflight))
            .unwrap_or_else(|| panic!("missing range preflight {preflight}"));
        assert!(
            position < selection,
            "{preflight} must precede sparse selection"
        );
        let observation = calls(&statements[position]);
        let call = observation
            .calls
            .iter()
            .find(|call| path(&call.func, preflight))
            .unwrap();
        let expected: &[&str] = match preflight {
            "hosted_thread_memory_retirement_access" => &["pi", "base", "size"],
            "vm_page_lock_range_is_locked" => &["pi", "base", "end"],
            _ => &["pi", "process", "base", "end"],
        };
        assert_eq!(call.args.len(), expected.len());
        for (argument, expected) in call.args.iter().zip(expected.iter()) {
            assert!(
                path(argument, expected),
                "preflight must cover full range identity"
            );
        }
    }
    let mut identity_checks = 0;
    for statement in &statements[..selection] {
        let Stmt::Expr(Expr::If(branch), _) = statement else {
            continue;
        };
        let mut condition = Calls::default();
        condition.visit_expr(&branch.cond);
        if condition
            .methods
            .iter()
            .any(|call| call.method == "capture_process_identity")
        {
            identity_checks += 1;
            assert!(condition
                .methods
                .iter()
                .any(|call| call.method == "is_valid" && path(&call.receiver, "process")));
            assert!(condition
                .methods
                .iter()
                .any(|call| call.method == "capture_process_identity"
                    && path(&call.receiver, "handler")
                    && call.args.len() == 1
                    && path(&call.args[0], "pi")));
            assert!(condition.calls.iter().any(|call| path(&call.func, "Some")
                && call.args.len() == 1
                && path(&call.args[0], "process")));
            let mut denied = Calls::default();
            denied.visit_block(&branch.then_branch);
            assert!(
                denied.returns,
                "invalid/current generation must refuse before selection"
            );
        }
    }
    assert_eq!(
        identity_checks, 1,
        "validate process once outside the sparse loop"
    );
}

#[test]
fn sparse_selection_retains_exact_cleanup_and_advances_only_after_success() {
    let function = source();
    let loop_expression = function
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            Stmt::Expr(Expr::While(loop_expression), _)
                if contains(statement, "next_private_page_in_range") =>
            {
                Some(loop_expression)
            }
            _ => None,
        })
        .expect("sparse candidate loop");
    let Expr::Let(binding) = &*loop_expression.cond else {
        panic!("candidate must be retained by while-let")
    };
    let syn::Pat::TupleStruct(pattern) = &*binding.pat else {
        panic!("selected Some(page) pattern")
    };
    let Some(syn::Pat::Ident(page)) = pattern.elems.first() else {
        panic!("selected page binding")
    };
    let page = page.ident.to_string();
    let Expr::Try(selection) = &*binding.expr else {
        panic!("invalid selector geometry must propagate")
    };
    let Expr::Call(selection) = &*selection.expr else {
        panic!("direct sparse selector")
    };
    assert!(path(&selection.func, "next_private_page_in_range"));
    assert_eq!(selection.args.len(), 5);
    for (argument, expected) in selection.args.iter().take(3).zip(["pi", "cursor", "end"]) {
        assert!(path(argument, expected));
    }
    assert!(registry_reference(
        &selection.args[3],
        "CLIENT_FRAME_REGISTRY"
    ));
    assert!(registry_reference(&selection.args[4], "PROCESS_PAGEFILE"));
    let cleanup = loop_expression
        .body
        .stmts
        .iter()
        .position(|statement| contains(statement, "vm_unmap_private_page"))
        .expect("existing per-page cleanup owner");
    let Stmt::Expr(Expr::Try(cleanup_expression), _) = &loop_expression.body.stmts[cleanup] else {
        panic!("cleanup refusal must propagate before cursor advancement")
    };
    let Expr::Call(cleanup_call) = &*cleanup_expression.expr else {
        panic!("direct cleanup call")
    };
    assert!(path(&cleanup_call.func, "vm_unmap_private_page"));
    assert_eq!(cleanup_call.args.len(), 4);
    for (argument, expected) in cleanup_call
        .args
        .iter()
        .zip(["pi", "process", &page, "handler"])
    {
        assert!(
            path(argument, expected),
            "cleanup must retain exact {expected}"
        );
    }
    let cursor = loop_expression
        .body
        .stmts
        .iter()
        .enumerate()
        .find_map(|(index, statement)| {
            let Stmt::Expr(Expr::Assign(assignment), _) = statement else {
                return None;
            };
            Some((index, assignment))
        })
        .expect("advance sparse cursor after successful cleanup");
    assert!(cursor.0 > cleanup);
    assert!(path(&cursor.1.left, "cursor"));
    let Expr::Binary(advance) = &*cursor.1.right else {
        panic!("selected-page cursor advance")
    };
    assert!(
        matches!(advance.op, syn::BinOp::Add(_))
            && path(&advance.left, &page)
            && path(&advance.right, "PAGE_SIZE"),
        "aligned selected page must advance by exactly one page"
    );
    let Stmt::Expr(Expr::Call(final_unmap), None) = function.block.stmts.last().unwrap() else {
        panic!("shared mapping retirement must be the final fallible result")
    };
    assert!(path(&final_unmap.func, "shared_image_mapping_unmap_range"));
    assert_eq!(final_unmap.args.len(), 4);
    for (argument, expected) in final_unmap
        .args
        .iter()
        .zip(["pi", "process", "base", "end"])
    {
        assert!(path(argument, expected));
    }
}
