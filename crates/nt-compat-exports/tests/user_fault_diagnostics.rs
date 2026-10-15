use syn::visit::Visit;

fn executive(name: &str) -> syn::File {
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
fn low_user_fault_uses_checked_physical_stack_diagnostics() {
    // RSP+0x10 through a bootstrap stack mirror is not the faulting thread's return PC.
    struct LowFaults(usize);
    impl<'a> Visit<'a> for LowFaults {
        fn visit_expr_if(&mut self, branch: &'a syn::ExprIf) {
            if let syn::Expr::Binary(condition) = &*branch.cond {
                if matches!(&*condition.left, syn::Expr::Path(path) if path.path.is_ident("addr"))
                    && matches!(&*condition.right, syn::Expr::Lit(value)
                        if matches!(&value.lit, syn::Lit::Int(value)
                            if value.base10_parse::<u64>().ok() == Some(0x10000)))
                {
                    let mut calls = Calls::default();
                    calls.visit_block(&branch.then_branch);
                    assert!(
                        calls
                            .0
                            .iter()
                            .any(|name| name == "trace_user_fault_context"),
                        "low faults require generic checked context and actual resident RSP[0]"
                    );
                    assert!(
                        !calls.0.iter().any(|name| name == "smss_stack_read"),
                        "bootstrap mirrors cannot authenticate a remote thread's stack"
                    );
                    self.0 += 1;
                }
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut faults = LowFaults(0);
    faults.visit_file(&executive("service_sec_image.rs"));
    assert_eq!(faults.0, 1);
}

#[test]
fn fault_trace_requires_checked_context_and_resident_backing_without_fill() {
    let file = executive("fault_stack_diagnostics.rs");
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "trace_user_fault_context" => {
                Some(function)
            }
            _ => None,
        })
        .expect("generic failure-only diagnostic must live at the physical stack boundary");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    for name in [
        "capture_process_identity",
        "executable_by_tid",
        "read",
        "read_fault_stack_word",
    ] {
        assert!(
            calls.0.iter().any(|call| call == name),
            "missing checked diagnostic {name}"
        );
    }
    for name in [
        "smss_stack_read",
        "tcb_read_regs20",
        "process_memory_read_status",
        "service_native_image_page_residency",
    ] {
        assert!(
            !calls.0.iter().any(|call| call == name),
            "fault diagnostics must not perform unchecked capture or demand filling: {name}"
        );
    }
}
