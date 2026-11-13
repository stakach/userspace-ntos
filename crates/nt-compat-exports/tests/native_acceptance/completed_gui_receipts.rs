use std::path::PathBuf;
use syn::visit::{self, Visit};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(item.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing actual completion helper {name}"))
}

fn call_name(call: &syn::ExprCall) -> Option<String> {
    match &*call.func {
        syn::Expr::Path(path) => Some(path.path.segments.last()?.ident.to_string()),
        _ => None,
    }
}

#[derive(Default)]
struct Names(Vec<String>);
impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0.push(ident.to_string());
    }
}

fn names(expression: &syn::Expr) -> Vec<String> {
    let mut names = Names::default();
    names.visit_expr(expression);
    names.0
}

fn is_path(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
}

fn real_return(statement: &syn::Stmt) -> bool {
    matches!(statement, syn::Stmt::Expr(syn::Expr::MethodCall(call), _)
        if call.method == "fetch_add" && is_path(&call.receiver, "USER_CALLBACK_REAL_RETURNS"))
}

#[test]
fn completed_gui_receipts_are_recorded_at_all_six_real_callback_returns() {
    let complete = function(
        &source("win32k_glue.rs"),
        "complete_controlled_user_callback",
    );
    struct Returns(usize);
    impl<'ast> Visit<'ast> for Returns {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            for (index, statement) in block.stmts.iter().enumerate() {
                if !real_return(statement) {
                    continue;
                }
                let hooks: Vec<_> = block.stmts[..index]
                    .iter()
                    .filter_map(|statement| match statement {
                        syn::Stmt::Expr(syn::Expr::Call(call), _)
                            if call_name(call).as_deref()
                                == Some("record_completed_user_callback") =>
                        {
                            Some(call)
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(hooks.len(), 1,
                    "each real-return branch needs one completed-frame receipt, not redirect intent");
                let hook = hooks[0];
                assert_eq!(hook.args.len(), 3);
                for (argument, expected) in
                    hook.args
                        .iter()
                        .zip(["completed_client", "request", "callback_status"])
                {
                    assert!(
                        is_path(argument, expected),
                        "receipt must use retained {expected}"
                    );
                }
                struct Acks(Vec<String>);
                impl<'ast> Visit<'ast> for Acks {
                    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                        if let Some(name) = call_name(call) {
                            self.0.push(name);
                        }
                        visit::visit_expr_call(self, call);
                    }
                }
                let hook_index = block.stmts[..index]
                    .iter()
                    .position(|statement| {
                        matches!(statement,
                    syn::Stmt::Expr(syn::Expr::Call(call), _)
                        if call_name(call).as_deref() == Some("record_completed_user_callback"))
                    })
                    .unwrap();
                let mut acks = Acks(Vec::new());
                for statement in &block.stmts[..hook_index] {
                    acks.visit_stmt(statement);
                }
                assert!(
                    acks.0.iter().any(|name| matches!(
                        name.as_str(),
                        "stage_returned_user_callback_context" | "redirect_pending_user_callback"
                    )),
                    "receipt follows the acknowledged outer continuation transfer"
                );
                self.0 += 1;
            }
            visit::visit_block(self, block);
        }
    }
    let mut returns = Returns(0);
    returns.visit_item_fn(&complete);
    assert_eq!(
        returns.0, 6,
        "cover chained, Receive, service, provider and LPC waits, and completed outer return"
    );
    struct Hooks(usize);
    impl<'ast> Visit<'ast> for Hooks {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.0 +=
                usize::from(call_name(call).as_deref() == Some("record_completed_user_callback"));
            visit::visit_expr_call(self, call);
        }
    }
    let mut hooks = Hooks(0);
    hooks.visit_file(&source("win32k_glue.rs"));
    assert_eq!(
        hooks.0, 6,
        "no extra callback receipts at redirect or retry intent"
    );
}

#[test]
fn completed_gui_receipts_callback_status_uses_original_caller_and_nt_success() {
    let helper = function(&source("win32k_glue.rs"), "record_completed_user_callback");
    struct Forward(bool);
    impl<'ast> Visit<'ast> for Forward {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if call_name(call).as_deref() == Some("service_observe_desktop_callback_return") {
                assert_eq!(call.args.len(), 3);
                assert!(is_path(&call.args[0], "caller"));
                assert!(matches!(&call.args[1], syn::Expr::Field(field)
                    if is_path(&field.base, "request") && matches!(&field.member,
                        syn::Member::Named(name) if name == "api_index")));
                assert!(is_path(&call.args[2], "callback_status"));
                self.0 = true;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut forward = Forward(false);
    forward.visit_item_fn(&helper);
    assert!(
        forward.0,
        "forward genuine frame completion to the exact caller observer"
    );
    let mut fields = Names::default();
    fields.visit_item_fn(&helper);
    assert!(fields.0.iter().any(|name| name == "logical_caller"));
    assert!(!fields
        .0
        .iter()
        .any(|name| name == "USER_CALLBACK_CURRENT_DISPATCH"));
    let service = function(
        &source("service_sec_image.rs"),
        "service_observe_desktop_callback_return",
    );
    struct Status {
        success: bool,
        api_zero: bool,
    }
    impl<'ast> Visit<'ast> for Status {
        fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
            if matches!(expression.op, syn::BinOp::Ge(_)) {
                self.success |= matches!(&*expression.left, syn::Expr::Cast(cast)
                    if is_path(&cast.expr, "callback_status") && matches!(&*cast.ty,
                        syn::Type::Path(path) if path.path.is_ident("i32")))
                    && matches!(&*expression.right, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().ok() == Some(0)));
            }
            if matches!(expression.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
                self.api_zero |= is_path(&expression.left, "api_index")
                    && matches!(&*expression.right, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().ok() == Some(0)));
            }
            visit::visit_expr_binary(self, expression);
        }
    }
    let mut status = Status {
        success: false,
        api_zero: false,
    };
    status.visit_item_fn(&service);
    assert!(
        status.success,
        "NT_SUCCESS includes zero even when WM_NCCREATE returns FALSE"
    );
    assert!(
        status.api_zero,
        "only genuine API0 callback completions enter these facts"
    );
    let mut fields = Names::default();
    fields.visit_item_fn(&service);
    for required in [
        "api_index",
        "CallbackCompleted",
        "CallbackFailed",
        "service_observe_desktop_gui_for",
    ] {
        assert!(
            fields.0.iter().any(|name| name == required),
            "missing {required}"
        );
    }
    assert!(
        !fields.0.iter().any(|name| name == "result_pointer"),
        "callback LRESULT is not callback transport status"
    );
}

#[test]
fn completed_gui_receipts_do_not_accept_unproduced_replay_flags() {
    for file in ["win32k_glue.rs", "win32k_subsystem.rs"] {
        let mut identifiers = Names::default();
        identifiers.visit_file(&source(file));
        for obsolete in [
            "WIN32K_NEXT_DISPATCH_DEBUG_FLAGS",
            "SH_REQ_DEBUG_ATL_REPLAY",
            "SH_REQ_DEBUG_FLAGS",
            "WIN32K_EXPLORER_SETWNDPROC_REPLAY_CALLS",
        ] {
            assert!(
                !identifiers.0.iter().any(|name| name == obsolete),
                "{file}: unproduced {obsolete} cannot stand in for authentic WndProc completion"
            );
        }
    }
}
