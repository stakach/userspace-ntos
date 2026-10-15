//! Pending CREATE owns separate table/Handle/Information/Status publication receipts.
use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn pending_create_uses_retained_per_store_delivery_not_whole_publisher_replay() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = std::fs::read_to_string(root.join(
        "components/ntos-executive/src/pending_file_create.rs",
    )).expect("focused retained pending-CREATE delivery adapter");
    let source = syn::parse_file(&source).unwrap();
    let deliver = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "deliver" => Some(function),
        _ => None,
    }).expect("exact pending-CREATE delivery entry");
    let mut calls = Calls::default();
    calls.visit_block(&deliver.block);
    let table = calls.0.iter().position(|name| name == "publish_bound_file_handle")
        .expect("canonical table publication has its own stage");
    let user = calls.0.iter().position(|name| name == "process_memory_write_checked")
        .expect("user publication preserves typed fault/retry disposition");
    assert!(table < user, "table commit precedes user Handle copy");
    let next = calls.0.iter().position(|name| name == "create_output_action_exact")
        .expect("exact retained output action");
    let receipt = calls.0.iter().position(|name| name == "observe_create_output_exact")
        .expect("exact output-stage receipt");
    assert!(next < table && table < receipt && receipt < user,
        "table publication is acknowledged before any user store");
    assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
        "xas_try_write_buf" | "xas_write_buf" | "queue_write" | "smss_stack_write"
        | "publish_file_create_result" | "publish_file_create_result_checked")),
        "per-store redrive cannot use boolean faults or replay a whole accepted prefix");

    struct Stages { observation: usize, retry: bool, uncertain_stop: bool }
    impl<'ast> Visit<'ast> for Stages {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "observe_create_output_exact" {
                assert_eq!(call.args.len(), 4);
                assert!(matches!(call.args.first(), Some(syn::Expr::Path(path))
                    if path.path.is_ident("identity")));
                assert!(matches!(call.args.iter().nth(1), Some(syn::Expr::Field(field))
                    if matches!(&field.member, syn::Member::Named(name) if name == "irp_id")));
                assert!(matches!(call.args.iter().nth(2), Some(syn::Expr::Path(path))
                    if path.path.is_ident("action")), "observation consumes only the selected exact stage");
                self.observation += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            for arm in &expression.arms {
                if matches!(&arm.pat, syn::Pat::TupleStruct(error)
                    if error.path.is_ident("Err") && matches!(error.elems.first(),
                        Some(syn::Pat::TupleStruct(failure))
                            if failure.path.segments.last().is_some_and(|name| name.ident == "Retry")))
                {
                    assert!(matches!(&*arm.body, syn::Expr::Call(call)
                        if matches!(&*call.func, syn::Expr::Path(path)
                            if path.path.segments.last().is_some_and(|name| name.ident == "Uncertain"))),
                        "a checked-copy Retry cannot prove no stores or authorize replay");
                    self.retry = true;
                }
                if matches!(&arm.pat, syn::Pat::Path(path)
                    if path.path.segments.last().is_some_and(|name| name.ident == "Uncertain"))
                {
                    assert!(matches!(&*arm.body, syn::Expr::Return(_)),
                        "uncertain output remains retained without another attempt");
                    self.uncertain_stop = true;
                }
            }
            syn::visit::visit_expr_match(self, expression);
        }
    }
    let mut stages = Stages { observation: 0, retry: false, uncertain_stop: false };
    stages.visit_block(&deliver.block);
    assert!(stages.observation >= 2 && stages.retry && stages.uncertain_stop,
        "native adapter settles exact stages and quarantines uncertain copies");

    let service = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/service_sec_image.rs"
    )).unwrap();
    struct Hook(bool);
    impl<'ast> Visit<'ast> for Hook {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.len() >= 2
                    && path.path.segments[path.path.segments.len() - 2].ident == "pending_file_create"
                    && path.path.segments.last().unwrap().ident == "deliver")
            {
                assert_eq!(call.args.len(), 2, "retained delivery receives only handler and exact owner identity");
                assert!(matches!(call.args.last(), Some(syn::Expr::Path(path))
                    if path.path.is_ident("identity")));
                self.0 = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut hook = Hook(false);
    hook.visit_file(&service);
    assert!(hook.0, "actual File drain invokes the staged CREATE adapter");

    let handler = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    let release = handler.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "release_unpublished_hosted_create" =>
                Some(function),
            _ => None,
        })
    }).expect("unpublished CREATE reservation release boundary");
    let guard = release.block.stmts.iter().position(|statement|
        matches!(statement, syn::Stmt::Expr(syn::Expr::If(expression), _)
            if matches!(&*expression.cond, syn::Expr::MethodCall(call)
                if call.method == "table_handle_committed")
            && expression.then_branch.stmts.iter().any(|statement|
                matches!(statement, syn::Stmt::Expr(syn::Expr::Return(_), _)))))
        .expect("accepted table commitment cannot be cancelled as an unpublished reservation");
    let retirement = release.block.stmts.iter().position(|statement| {
        let mut calls = Calls::default();
        calls.visit_stmt(statement);
        calls.0.iter().any(|name| name == "release_hosted_create_reservation")
    }).unwrap();
    assert!(guard < retirement, "table commitment receipt fences irreversible release");
}
