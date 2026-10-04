use syn::visit::Visit;

fn named(path: &syn::Path, name: &str) -> bool {
    path.segments.last().is_some_and(|part| part.ident == name)
}

fn mapping_function() -> syn::ItemFn {
    let file = syn::parse_file(include_str!("../../nt-ntdll-dll/src/on_target.rs")).unwrap();
    file.items.into_iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "rtlp_map_file" => Some(function),
        _ => None,
    }).expect("the actual file-to-Section loader function exists")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn assert_failure_branch(stage: &str, syscall: &str) {
    let function = mapping_function();
    let mut last_syscall = None;
    for statement in &function.block.stmts {
        let mut calls = Calls::default();
        calls.visit_stmt(statement);
        if calls.0.iter().any(|name| name == syscall) {
            last_syscall = Some(syscall);
        } else if calls.0.iter().any(|name| name == "syscall6" || name == "syscall8") {
            last_syscall = None;
        }
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else { continue; };
        if last_syscall != Some(syscall) { continue; }
        struct NegativeStatus(bool);
        impl<'a> Visit<'a> for NegativeStatus {
            fn visit_expr_binary(&mut self, expression: &'a syn::ExprBinary) {
                self.0 |= matches!(expression.op, syn::BinOp::Lt(_));
                syn::visit::visit_expr_binary(self, expression);
            }
        }
        let mut negative = NegativeStatus(false);
        negative.visit_expr(&branch.cond);
        if !negative.0 { continue; }
        let mut body_calls = Calls::default();
        body_calls.visit_block(&branch.then_branch);
        assert_eq!(body_calls.0, ["report_file_map_failure"],
            "a negative syscall result must report once, without extra NT calls or pointer reads");
        let mut report_index = None;
        let mut return_index = None;
        for (index, statement) in branch.then_branch.stmts.iter().enumerate() {
            if let syn::Stmt::Expr(syn::Expr::Call(call), _) = statement {
                if matches!(&*call.func, syn::Expr::Path(path)
                    if named(&path.path, "report_file_map_failure")) {
                    assert_eq!(call.args.len(), 2);
                    assert!(matches!(&call.args[0], syn::Expr::Path(path)
                        if named(&path.path, stage)), "the diagnostic must identify the actual failed stage");
                    assert!(matches!(&call.args[1], syn::Expr::Path(path)
                        if named(&path.path, "st")), "the diagnostic must preserve the actual status");
                    report_index = Some(index);
                }
            }
            if let syn::Stmt::Expr(syn::Expr::Return(value), _) = statement {
                assert!(matches!(value.expr.as_deref(), Some(syn::Expr::Path(path))
                    if named(&path.path, "st")), "failure must return the original syscall status");
                return_index = Some(index);
            }
        }
        assert!(report_index.zip(return_index).is_some_and(|(report, ret)| report < ret),
            "report the negative result before returning its unchanged status");
        let mut all_calls = Calls::default();
        all_calls.visit_block(&function.block);
        assert_eq!(all_calls.0.iter().filter(|name| *name == "report_file_map_failure").count(), 2,
            "only the two negative syscall-result branches may emit failure records");
        return;
    }
    panic!("{stage} requires its own actual negative-result diagnostic branch");
}

#[test]
fn open_file_failure_reports_actual_stage_and_unchanged_status_without_more_effects() {
    assert_failure_branch("Open", "syscall6");
}

#[test]
fn create_section_failure_reports_actual_stage_and_unchanged_status_without_more_effects() {
    assert_failure_branch("CreateSection", "syscall8");
}

#[test]
fn map_view_failure_reports_actual_status_after_section_close_without_replay() {
    let file = syn::parse_file(include_str!("../../nt-ntdll-dll/src/on_target.rs")).unwrap();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "load_dependent_dll" => Some(function),
        _ => None,
    }).expect("actual dependency loader");
    let mut map_index = None;
    let mut close_index = None;
    let mut report_index = None;
    for (index, statement) in function.block.stmts.iter().enumerate() {
        let mut calls = Calls::default();
        calls.visit_stmt(statement);
        if calls.0.iter().any(|name| name == "syscall_map_view") { map_index = Some(index); }
        if calls.0.iter().any(|name| name == "syscall4") { close_index = Some(index); }
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else { continue; };
        if !calls.0.iter().any(|name| name == "report_file_map_failure") { continue; }
        let mut body = Calls::default();
        body.visit_block(&branch.then_branch);
        assert_eq!(body.0, ["report_file_map_failure"], "failure reporting adds no calls or reads");
        assert!(matches!(&*branch.cond, syn::Expr::Binary(binary)
            if matches!(binary.op, syn::BinOp::Lt(_))
            && matches!(&*binary.left, syn::Expr::Paren(paren)
                if matches!(&*paren.expr, syn::Expr::Cast(cast)
                    if matches!(&*cast.expr, syn::Expr::Path(path) if named(&path.path, "st"))))));
        let syn::Stmt::Expr(syn::Expr::Call(report), _) = &branch.then_branch.stmts[0] else {
            panic!("report the actual negative MapView result first");
        };
        assert_eq!(report.args.len(), 2);
        assert!(matches!(&report.args[0], syn::Expr::Path(path) if named(&path.path, "MapView")));
        assert!(matches!(&report.args[1], syn::Expr::Cast(cast)
            if matches!(&*cast.expr, syn::Expr::Path(path) if named(&path.path, "st"))
            && matches!(&*cast.ty, syn::Type::Path(path) if named(&path.path, "u32"))),
            "capture the unchanged 32-bit NTSTATUS from the syscall return register");
        assert!(matches!(&branch.then_branch.stmts[1], syn::Stmt::Expr(syn::Expr::Return(ret), _)
            if matches!(ret.expr.as_deref(), Some(syn::Expr::Lit(lit))
                if matches!(&lit.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().unwrap() == 0))),
            "preserve the loader's existing failed-map return value");
        report_index = Some(index);
    }
    assert!(map_index.zip(close_index).zip(report_index)
        .is_some_and(|((map, close), report)| map < close && close < report),
        "a failed MapView must report its actual status after the existing Section close");
}
