use syn::{visit::Visit, Pat};

fn service_arm(name: &str) -> syn::Arm {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    struct Select<'a> { name: &'a str, arm: Option<syn::Arm> }
    impl<'ast> Visit<'ast> for Select<'_> {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, Pat::Path(path)
                if path.path.segments.last().unwrap().ident == self.name) {
                self.arm = Some(arm.clone());
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut selected = Select { name, arm: None };
    selected.visit_file(&file);
    selected.arm.expect("actual native service implementation")
}

#[test]
fn kernel_srm_acceptor_is_selected_by_registered_port_not_executable_role() {
    #[derive(Default)]
    struct Route { role_guard: bool, under_role: bool, acceptor: usize }
    impl<'ast> Visit<'ast> for Route {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            struct Role(bool);
            impl<'ast> Visit<'ast> for Role {
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    self.0 |= call.method == "current_process_is_lsass";
                    syn::visit::visit_expr_method_call(self, call);
                }
            }
            let mut role = Role(false);
            role.visit_expr(&branch.cond);
            let previous = self.under_role;
            self.under_role |= role.0;
            self.visit_block(&branch.then_branch);
            self.under_role = previous;
            if let Some((_, alternate)) = &branch.else_branch { self.visit_expr(alternate); }
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "connect_srm_command_port" {
                self.acceptor += 1;
                self.role_guard |= self.under_role;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut route = Route::default();
    route.visit_arm(&service_arm("NtConnectPort"));
    assert_eq!(route.acceptor, 1);
    assert!(!route.role_guard, "a genuine registered SRM port cannot abandon its connection because the client has a generic image role");
}

#[test]
fn thread_exit_cascade_does_not_depend_on_registered_process_role() {
    #[derive(Default)]
    struct Calls { role: bool, semantic_termination: bool, suppress_cascade: bool }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.role |= call.method == "current_process_is_csrss";
            self.semantic_termination |= call.method == "terminate_thread_at";
            self.suppress_cascade |= call.method == "exit_thread_at";
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut calls = Calls::default();
    calls.visit_arm(&service_arm("NtTerminateThread"));
    assert!(calls.semantic_termination);
    assert!(!calls.role && !calls.suppress_cascade,
        "native thread exit must use canonical active-thread lifetime, not a CSRSS-only no-cascade exception");
}
