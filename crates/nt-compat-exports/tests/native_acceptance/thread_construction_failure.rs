use syn::visit::Visit;

fn activation_source() -> syn::File {
    let parent = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/ps_object_backing.rs"
    )).unwrap();
    assert!(parent.items.iter().any(|item| matches!(item, syn::Item::Mod(module)
        if module.ident == "thread_activation" && module.attrs.iter().any(|attribute|
            matches!(&attribute.meta, syn::Meta::NameValue(value)
                if value.path.is_ident("path") && matches!(&value.value, syn::Expr::Lit(value)
                    if matches!(&value.lit, syn::Lit::Str(path)
                        if path.value() == "ps_object_backing/thread_activation.rs")))))),
        "activation proof must follow the registered native module");
    syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/ps_object_backing/thread_activation.rs"
    )).unwrap()
}

#[test]
fn native_reactivation_fences_old_lifetime_before_alias_retirement() {
    let file = activation_source();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "prepare_thread_reactivation" => Some(function),
        _ => None,
    }).unwrap();
    #[derive(Default)]
    struct Sequence { calls: Vec<String>, fence: Option<usize>, reopened: bool }
    impl<'ast> Visit<'ast> for Sequence {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.calls.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "phase")) {
                match &*assignment.right {
                    syn::Expr::Struct(value) if value.path.segments.last().unwrap().ident == "Reactivating" => {
                        assert!(value.fields.iter().any(|field|
                            matches!(&field.member, syn::Member::Named(name) if name == "lifetime")));
                        self.fence = Some(self.calls.len());
                    }
                    syn::Expr::Path(value) if value.path.segments.last().unwrap().ident == "Published" => self.reopened = true,
                    _ => {}
                }
            }
            syn::visit::visit_expr_assign(self, assignment);
        }
    }
    let mut sequence = Sequence::default();
    sequence.visit_block(&function.block);
    let fence = sequence.fence.expect("old body grants must close durably for the exact held lifetime");
    for validation in ["expected_lifetime", "thread_lifetime", "can_reclaim_thread", "thread_kernel_object", "live_alias"] {
        assert!(sequence.calls.iter().position(|call| call == validation).unwrap() < fence);
    }
    assert!(fence <= sequence.calls.iter().position(|call| call == "retire_non_root_aliases").unwrap());
    assert!(!sequence.reopened, "a refused cleanup cannot reopen old-body grants");
}

#[test]
fn native_activation_keeps_drain_guard_and_reopens_only_after_pm_commit() {
    let file = activation_source();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "commit_thread_activation" => Some(function),
        _ => None,
    }).unwrap();
    #[derive(Default)]
    struct Publication { drained: bool, commits: usize, refresh: bool, reopened: bool }
    impl<'ast> Visit<'ast> for Publication {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "non_root_aliases_drained" { self.drained = true; }
            if call.method == "commit_thread_activation_with_handle_and_object" {
                assert!(self.drained);
                self.commits += 1;
            }
            if call.method == "commit_thread_activation_with_handle" && self.drained {
                self.commits += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "refresh_thread_activation") {
                assert_eq!(self.commits, 2);
                self.refresh = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "phase"))
                && matches!(&*assignment.right, syn::Expr::Path(path)
                    if path.path.segments.last().unwrap().ident == "Published") {
                assert!(self.refresh && self.drained);
                self.reopened = true;
            }
            syn::visit::visit_expr_assign(self, assignment);
        }
    }
    let mut publication = Publication::default();
    publication.visit_block(&function.block);
    assert!(publication.reopened);
}

#[test]
fn native_thread_reuse_drains_exact_body_aliases_before_admitting_construction() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "prepare_hosted_thread_publication" => Some(function),
            _ => None,
        }),
        _ => None,
    }).unwrap();
    #[derive(Default)]
    struct Admission { drain: bool, bind: bool }
    impl<'ast> Visit<'ast> for Admission {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "prepare_thread_reactivation")) {
                self.drain = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "bind_reserved_handle" {
                assert!(self.drain, "exact old body alias admission precedes a new caller handle");
                self.bind = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut admission = Admission::default();
    admission.visit_block(&function.block);
    assert!(admission.drain && admission.bind,
        "PM reuse admission must include the retained native ETHREAD alias owner");
}

#[test]
fn activation_failure_is_recorded_before_completed_construction_is_retained() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "finish_hosted_thread_publication" => Some(function),
            _ => None,
        }),
        _ => None,
    }).unwrap();
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    let record = calls.0.iter().position(|name| name == "record_hosted_thread_construction_failure")
        .expect("successful construction can fail during ETHREAD activation: record its actual status");
    assert!(record < calls.0.iter().position(|name| name == "into_failed").unwrap());
}

#[test]
fn native_thread_construction_captures_failure_before_retained_cleanup() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/main.rs"
    )).unwrap();
    let constructor = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "spawn_hosted_thread_mechanism" => Some(function),
        _ => None,
    }).unwrap();
    let failure = constructor.block.stmts.iter().find_map(|statement| match statement {
        syn::Stmt::Item(syn::Item::Macro(item))
            if item.ident.as_ref().is_some_and(|name| name == "failed") => Some(item),
        _ => None,
    }).unwrap();
    let tokens = failure.mac.tokens.to_string();
    let capture = tokens.find("record_hosted_thread_construction_failure")
        .expect("construction failure must record the actual operation before returning its owner");
    assert!(capture < tokens.find("RetainedHostedThreadConstruction").unwrap());
    assert!(tokens.contains("$ phase") && tokens.contains("$ error") && tokens.contains("$ target"),
        "the failure boundary cannot accept an unattributed failure");

    struct Failures(usize);
    impl<'ast> Visit<'ast> for Failures {
        fn visit_macro(&mut self, item: &'ast syn::Macro) {
            if item.path.is_ident("failed") {
                let arguments = item.parse_body_with(
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                ).expect("every native failure carries phase, actual error and target");
                assert_eq!(arguments.len(), 3);
                self.0 += 1;
            }
            syn::visit::visit_macro(self, item);
        }
    }
    let mut failures = Failures(0);
    failures.visit_block(&constructor.block);
    assert!(failures.0 > 20, "all construction failure boundaries remain observable");
}

fn constructor_source() -> syn::File {
    syn::parse_file(include_str!("../../../../components/ntos-executive/src/main.rs")).unwrap()
}

fn native_error(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Call(call)
        if matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "Native"))
            && call.args.len() == 1
            && matches!(&call.args[0], syn::Expr::Path(path) if path.path.is_ident(name)))
}

#[test]
fn context_write_failure_forwards_the_actual_backend_error() {
    struct ContextFailure(bool);
    impl<'ast> Visit<'ast> for ContextFailure {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            if let syn::Expr::Let(condition) = &*branch.cond {
                if let syn::Expr::Call(call) = &*condition.expr {
                    if matches!(&*call.func, syn::Expr::Path(path)
                        if path.path.segments.len() == 2
                            && path.path.segments[0].ident == "thread_context"
                            && path.path.segments[1].ident == "write")
                    {
                        let syn::Pat::TupleStruct(pattern) = &*condition.pat else { panic!("write error pattern"); };
                        let syn::Pat::Ident(error) = &pattern.elems[0] else { panic!("captured backend error"); };
                        struct Forward<'a> { name: &'a str, found: bool }
                        impl<'ast> Visit<'ast> for Forward<'_> {
                            fn visit_macro(&mut self, item: &'ast syn::Macro) {
                                if item.path.is_ident("failed") {
                                    let arguments = item.parse_body_with(
                                        syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                                    ).unwrap();
                                    self.found |= arguments.len() == 3 && native_error(&arguments[1], self.name);
                                }
                            }
                        }
                        let name = error.ident.to_string();
                        let mut forward = Forward { name: &name, found: false };
                        forward.visit_block(&branch.then_branch);
                        self.0 |= forward.found;
                    }
                }
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut check = ContextFailure(false);
    check.visit_file(&constructor_source());
    assert!(check.0, "thread_context::write Err must retain its actual native error, not zero/status sentinel");
}

#[test]
fn endpoint_backend_error_is_not_replaced_by_an_admission_or_zero_code() {
    struct EndpointFailure(bool);
    impl<'ast> Visit<'ast> for EndpointFailure {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if let syn::Pat::TupleStruct(pattern) = &arm.pat {
                if pattern.path.segments.last().is_some_and(|part| part.ident == "Backend") {
                    if let Some(syn::Pat::Ident(error)) = pattern.elems.first() {
                        self.0 |= native_error(&arm.body, &error.ident.to_string());
                    }
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut check = EndpointFailure(false);
    check.visit_file(&constructor_source());
    assert!(check.0, "endpoint Backend(error) must preserve the same native error");
}

#[test]
fn failure_record_uses_only_captured_identity_and_diagnostic_effects() {
    use syn::parse::Parser;
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/hosted_thread_failure.rs"
    )).unwrap();
    let formatter = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "record_hosted_thread_construction_failure" => Some(function),
        _ => None,
    }).unwrap();
    #[derive(Default)]
    struct Record { fields: Vec<String>, calls: Vec<String> }
    impl<'ast> Visit<'ast> for Record {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            fn path(expr: &syn::Expr) -> Option<String> {
                match expr {
                    syn::Expr::Path(value) if value.path.is_ident("binding") => Some("binding".into()),
                    syn::Expr::Field(value) => {
                        let syn::Member::Named(member) = &value.member else { return None; };
                        Some(format!("{}.{}", path(&value.base)?, member))
                    }
                    _ => None,
                }
            }
            if let Some(path) = path(&syn::Expr::Field(field.clone())) { self.fields.push(path); }
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.calls.push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.calls.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_macro(&mut self, item: &'ast syn::Macro) {
            let expressions = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(item.tokens.clone()).expect("diagnostic record has structured arguments");
            for expression in &expressions { self.visit_expr(expression); }
        }
    }
    let mut record = Record::default();
    record.visit_block(&formatter.block);
    for field in ["binding.pi", "binding.process.pid", "binding.process.generation", "binding.tid", "binding.badge"] {
        assert!(record.fields.iter().any(|actual| actual == field), "record must preserve {field}");
    }
    for call in &record.calls {
        assert!(["new", "from_utf8", "expect", "status", "overflowed", "bytes", "print_record"].contains(&call.as_str()),
            "formatter cannot perform fresh identity lookup or native resource effects: {call}");
    }
    assert_eq!(record.calls.iter().filter(|call| *call == "print_record").count(), 1,
        "emit one bounded record without native IPC/effect retries");
}
