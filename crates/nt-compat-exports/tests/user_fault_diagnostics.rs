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
