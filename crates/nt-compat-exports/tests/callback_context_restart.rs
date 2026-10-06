use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn staged_callback_completion_atomically_restarts_its_retained_reply() {
    let file = source("win32k_glue.rs");
    let completion = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "restart_staged_user_callback_context" =>
            {
                Some(function)
            }
            _ => None,
        })
        .expect("context-restored callback must not resume through ordinary IPC Reply");
    let mut calls = Calls::default();
    calls.visit_block(&completion.block);
    assert!(
        calls.0.iter().any(|name| name == "restart_hosted"),
        "use retained exact physical Call binding and atomic context/reply restart"
    );
    for name in ["client_reply_on", "reply_on", "tcb_resume"] {
        assert!(
            !calls.0.iter().any(|call| call == name),
            "{name} can clobber saved parent state or lose reply ownership"
        );
    }
}

#[test]
fn callback_terminal_reply_uses_context_restart_not_zero_length_ipc() {
    struct CallbackReply(usize);
    impl<'a> Visit<'a> for CallbackReply {
        fn visit_arm(&mut self, arm: &'a syn::Arm) {
            if let syn::Pat::Struct(pattern) = &arm.pat {
                if pattern.path.segments.last().unwrap().ident == "Callback" {
                    let mut calls = Calls::default();
                    calls.visit_expr(&arm.body);
                    assert!(
                        !calls.0.iter().any(|name| name == "client_reply_on"),
                        "normal Reply installs stale message registers over the staged parent"
                    );
                    if calls
                        .0
                        .iter()
                        .any(|name| name == "restart_staged_user_callback_context")
                    {
                        self.0 += 1;
                    }
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut replies = CallbackReply(0);
    replies.visit_file(&source("component_terminal.rs"));
    assert_eq!(
        replies.0, 1,
        "inspect the actual callback terminal Reply stage"
    );
}

#[test]
fn deferred_callback_restoration_never_uses_normal_ipc_reply() {
    let file = source("service_sec_image.rs");
    let drain = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "drain_deferred_user_callback_returns" =>
            {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&drain.block);
    assert!(
        !calls.0.iter().any(|name| name == "client_reply_on"),
        "deferred and chained callbacks must preserve the installed nonvolatile context too"
    );
    assert!(calls
        .0
        .iter()
        .any(|name| name == "restart_staged_user_callback_context"));
}

#[test]
fn published_callback_transfer_restarts_the_installed_dispatcher() {
    let file = source("component_callback_transfer.rs");
    let restart = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(block) => block.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == "restart" => Some(function),
                _ => None,
            }),
            _ => None,
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&restart.block);
    assert!(calls
        .0
        .iter()
        .any(|name| name == "restart_staged_user_callback_context"));
    assert!(
        calls.0.iter().any(|name| name == "client"),
        "target must come from the retained transfer binding"
    );
    struct Published(bool);
    impl<'a> Visit<'a> for Published {
        fn visit_expr_binary(&mut self, expression: &'a syn::ExprBinary) {
            if matches!(&expression.op, syn::BinOp::Ne(_))
                && matches!(&*expression.left, syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "phase"))
                && matches!(&*expression.right, syn::Expr::Path(path)
                    if path.path.segments.last().unwrap().ident == "Published")
            {
                self.0 = true;
            }
            syn::visit::visit_expr_binary(self, expression);
        }
    }
    let mut published = Published(false);
    published.visit_block(&restart.block);
    assert!(
        published.0,
        "only an acknowledged published transfer may restart"
    );
    assert!(!calls.0.iter().any(|name| name == "client_reply_on"));
    let mut terminal = Calls::default();
    terminal.visit_file(&source("component_terminal.rs"));
    assert!(terminal.0.iter().any(|name| name == "restart"));
}

#[test]
fn initial_callback_redirect_bypasses_normal_ipc_completion() {
    struct Redirect(usize);
    impl<'a> Visit<'a> for Redirect {
        fn visit_expr_if(&mut self, expression: &'a syn::ExprIf) {
            if matches!(&*expression.cond, syn::Expr::Path(path)
                if path.path.is_ident("redirected_user_control"))
            {
                let mut calls = Calls::default();
                calls.visit_block(&expression.then_branch);
                if calls
                    .0
                    .iter()
                    .any(|name| name == "restart_staged_user_callback_context")
                {
                    assert!(!calls.0.iter().any(|name| name == "client_reply_on"));
                    struct Order(Vec<String>);
                    impl<'b> Visit<'b> for Order {
                        fn visit_expr_call(&mut self, call: &'b syn::ExprCall) {
                            if let syn::Expr::Path(path) = &*call.func {
                                self.0
                                    .push(path.path.segments.last().unwrap().ident.to_string());
                            }
                            syn::visit::visit_expr_call(self, call);
                        }
                        fn visit_macro(&mut self, call: &'b syn::Macro) {
                            self.0
                                .push(call.path.segments.last().unwrap().ident.to_string());
                        }
                    }
                    let mut order = Order(Vec::new());
                    order.visit_block(&expression.then_branch);
                    let restart = order
                        .0
                        .iter()
                        .position(|name| name == "restart_staged_user_callback_context")
                        .unwrap();
                    let receive = order
                        .0
                        .iter()
                        .position(|name| name == "component_recv")
                        .unwrap();
                    assert!(restart < receive);
                    self.0 += 1;
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut redirect = Redirect(0);
    redirect.visit_file(&source("service_sec_image.rs"));
    assert_eq!(redirect.0, 1);
}
