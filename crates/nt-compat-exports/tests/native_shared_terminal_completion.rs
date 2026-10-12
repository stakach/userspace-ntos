//! Native wiring for the shared hosted terminal's separately authenticated final Call.

use syn::visit::{self, Visit};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    }).unwrap_or_else(|| panic!("missing native function {name}"))
}

fn path_is(expr: &syn::Expr, name: &str) -> bool {
    matches!(expr, syn::Expr::Path(path) if path.path.is_ident(name))
}

fn field_is(expr: &syn::Expr, base: &str, member: &str) -> bool {
    matches!(expr, syn::Expr::Field(field)
        if path_is(&field.base, base)
            && matches!(&field.member, syn::Member::Named(name) if name == member))
}

fn call_is(call: &syn::ExprCall, name: &str) -> bool {
    matches!(&*call.func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

#[test]
fn shared_hosted_terminal_keeps_exact_owner_until_final_call_completion() {
    let file = source("component_terminal.rs");
    let row = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "PendingSharedReturn" => Some(item),
        _ => None,
    }).expect("shared completion needs a retained owner row");
    for (field, owner_type) in [
        ("route", "PeerRoute"),
        ("dispatch", "LaneDispatchIdentity"),
        ("reply", "u64"),
    ] {
        assert!(row.fields.iter().any(|item| {
            item.ident.as_ref().is_some_and(|ident| ident == field)
                && matches!(&item.ty, syn::Type::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident == owner_type))
        }), "pending completion must retain exact {field} owner");
    }

    #[derive(Default)]
    struct TerminalWiring { shared: bool, pending: bool }
    impl<'ast> Visit<'ast> for TerminalWiring {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "finish_shared_terminal" {
                let args: Vec<_> = call.args.iter().collect();
                self.shared |= args.len() == 5
                    && ["route", "dispatch", "identity", "reply_object", "local"]
                        .iter().zip(args).all(|(expected, argument)| path_is(argument, expected));
            }
            visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
            if item.path.is_ident("PendingSharedReturn") {
                self.pending |= ["route", "dispatch", "reply"].iter().all(|name| {
                    item.fields.iter().any(|field| {
                        matches!(&field.member, syn::Member::Named(member) if member == *name)
                            && if *name == "reply" {
                                path_is(&field.expr, "reply_object")
                            } else {
                                path_is(&field.expr, name)
                            }
                    })
                });
            }
            visit::visit_expr_struct(self, item);
        }
    }
    let mut wiring = TerminalWiring::default();
    wiring.visit_item_fn(function(&file, "drain"));
    assert!(wiring.shared, "hosted ACK must use exact shared semantic retirement");
    assert!(wiring.pending, "semantic retirement must retain its original route, epoch and Reply");

    #[derive(Default)]
    struct CompletionWiring { entered: bool, complete: bool, wrong_order: bool }
    impl<'ast> Visit<'ast> for CompletionWiring {
        fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
            if field_is(&assign.left, "pending", "entered")
                && matches!(&*assign.right, syn::Expr::Lit(lit)
                    if matches!(&lit.lit, syn::Lit::Bool(value) if value.value))
            {
                self.entered = true;
            }
            visit::visit_expr_assign(self, assign);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if call_is(call, "complete") {
                let args: Vec<_> = call.args.iter().collect();
                if args.len() == 4
                    && field_is(args[0], "pending", "route")
                    && field_is(args[1], "pending", "dispatch")
                    && field_is(args[2], "pending", "reply")
                {
                    self.complete = true;
                    self.wrong_order |= !self.entered;
                }
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut completion = CompletionWiring::default();
    completion.visit_item_fn(function(&file, "drain_shared_returns"));
    assert!(completion.entered && completion.complete && !completion.wrong_order,
        "final Call completion must retain the exact attempt before using its original owners");
}

#[test]
fn shared_return_redrive_precedes_the_busy_lane_gate() {
    let file = source("component_resume.rs");
    let run = function(&file, "run_outer");
    #[derive(Default)]
    struct Calls { redrive: bool, busy: bool }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.redrive |= call_is(call, "drain_shared_returns");
            self.busy |= call_is(call, "component_execution_is_busy");
            visit::visit_expr_call(self, call);
        }
    }
    let mut redrive = None;
    let mut busy = None;
    for (index, statement) in run.block.stmts.iter().enumerate() {
        let mut calls = Calls::default();
        calls.visit_stmt(statement);
        if calls.redrive { redrive = Some(index); }
        if calls.busy { busy = Some(index); }
    }
    assert!(matches!((redrive, busy), (Some(redrive), Some(busy)) if redrive < busy),
        "a retained final Call must be processed before the running lane suppresses scheduling");
}
