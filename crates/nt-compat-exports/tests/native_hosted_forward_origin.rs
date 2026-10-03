use syn::visit::Visit;

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    for item in &file.items {
        if let syn::Item::Impl(item) = item {
            for member in &item.items {
                if let syn::ImplItem::Fn(member) = member {
                    if member.sig.ident == name {
                        return &member.block;
                    }
                }
            }
        }
        if let syn::Item::Fn(item) = item {
            if item.sig.ident == name {
                return &item.block;
            }
        }
    }
    panic!("missing native function {name}");
}

#[derive(Default)]
struct Calls {
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.names
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.names.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn read_source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).expect("native source exists")).unwrap()
}

#[test]
fn forwarding_work_uses_common_origin_instead_of_waiting_for_terminal_to_return_pending() {
    for name in [
        "hosted_read_work.rs",
        "hosted_flush_work.rs",
        "hosted_query_information_work.rs",
    ] {
        let source = read_source(name);
        let mut calls = Calls::default();
        calls.visit_block(function(&source, "advance"));
        assert!(calls.names.iter().any(|name| name == "reply_dispatch"),
            "{name}: original dispatch Reply must use common origin disposition, including genuine Pending before completion");
    }
}

#[test]
fn common_origin_uses_shared_pending_readiness_and_armed_terminal_admission() {
    let source = read_source("hosted_forward_origin.rs");
    let mut calls = Calls::default();
    calls.visit_block(function(&source, "reply_dispatch"));
    assert!(
        calls
            .names
            .iter()
            .any(|name| name == "hosted_forward_dispatch_reply_ready"),
        "native dispatch-return readiness must use the executable shared policy"
    );
    let mut terminal = Calls::default();
    terminal.visit_block(function(&source, "begin_terminal"));
    let admission = terminal
        .names
        .iter()
        .position(|name| name == "admit")
        .expect(
            "exact lifecycle must deny terminal delivery until the source arms pending ownership",
        );
    let dispatch = terminal
        .names
        .iter()
        .position(|name| name == "dispatch")
        .expect("terminal completion must execute in the independent hosted completion lane");
    assert!(
        admission < dispatch,
        "record exact completion ownership before native dispatch"
    );
}

#[test]
fn source_pending_return_does_not_inline_complete_its_irp() {
    let source = read_source("driver_launch.rs");
    #[derive(Default)]
    struct PendingBranch {
        found: bool,
    }
    impl<'ast> Visit<'ast> for PendingBranch {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            struct PendingPath(bool);
            impl<'ast> Visit<'ast> for PendingPath {
                fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                    self.0 |= path
                        .path
                        .segments
                        .iter()
                        .any(|segment| segment.ident == "STATUS_PENDING");
                    syn::visit::visit_expr_path(self, path);
                }
            }
            let mut pending = PendingPath(false);
            pending.visit_expr(&branch.cond);
            if pending.0 {
                let mut calls = Calls::default();
                calls.visit_block(&branch.then_branch);
                if calls.names.iter().any(|name| name == "arm_pending") {
                    assert!(
                        !calls.names.iter().any(|name| name == "complete_hosted_irp"),
                        "Pending must return without invoking completion on the source stack"
                    );
                    self.found = true;
                }
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut pending = PendingBranch::default();
    pending.visit_block(function(&source, "s_iof_call_driver"));
    assert!(
        pending.found,
        "forwarded Pending needs an explicit exact arm branch before inline completion"
    );
}

#[test]
fn completion_wait_resume_preserves_the_original_dispatch_accounting() {
    let source = read_source("spawn_hosts.rs");
    let mut calls = Calls::default();
    calls.visit_block(function(&source, "component_pump_resume_hosted_wait"));
    assert!(
        calls.names.iter().any(|name| name == "resume_suspended"),
        "completion waits must resume the retained accounting snapshot"
    );
    assert!(calls
        .names
        .iter()
        .any(|name| name == "component_pump_enter"));
    for forbidden in [
        "component_pump_inner",
        "pump_enter_depth",
        "admit",
        "finish_autonomous",
    ] {
        assert!(!calls.names.iter().any(|name| name == forbidden),
            "an ordinary completion continuation must not create or finish another dispatch: {forbidden}");
    }
    let source = read_source("component_shared_pump.rs");
    let mut calls = Calls::default();
    calls.visit_block(function(&source, "service_wait_yields"));
    assert!(
        !calls.names.iter().any(|name| name == "finish_autonomous"),
        "DispatchWorker waits preserve their active dispatch, unlike autonomous thread exit"
    );
    #[derive(Default)]
    struct Paths(Vec<String>);
    impl<'ast> Visit<'ast> for Paths {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.0.extend(
                path.segments
                    .iter()
                    .map(|segment| segment.ident.to_string()),
            );
            syn::visit::visit_path(self, path);
        }
        fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
            if !invocation.path.is_ident("matches") {
                return;
            }
            let parse = |input: syn::parse::ParseStream<'_>| {
                let value = input.parse::<syn::Expr>()?;
                input.parse::<syn::Token![,]>()?;
                let pattern = syn::Pat::parse_multi(input)?;
                let guard = if input.peek(syn::Token![if]) {
                    input.parse::<syn::Token![if]>()?;
                    Some(input.parse::<syn::Expr>()?)
                } else {
                    None
                };
                Ok((value, pattern, guard))
            };
            let (value, pattern, guard) =
                syn::parse::Parser::parse2(parse, invocation.tokens.clone())
                    .expect("structured matches invocation");
            let mut nested = Paths::default();
            nested.visit_expr(&value);
            nested.visit_pat(&pattern);
            if let Some(guard) = guard {
                nested.visit_expr(&guard);
            }
            self.0.extend(nested.0);
        }
    }
    let mut paths = Paths::default();
    paths.visit_block(function(&source, "service_wait_yields"));
    for boundary in ["Hosted", "Irp"] {
        assert!(paths.0.iter().any(|name| name == boundary),
            "new ordinary completion wait behavior must be scoped to {boundary}; win32k also has dispatch workers");
    }
}
