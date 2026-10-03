use syn::{visit::Visit, Expr, Item, ItemFn, Lit};

fn source() -> syn::File {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/provider_registry_caller.rs");
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing exact provider caller boundary {name}"))
}

#[derive(Default)]
struct Evidence {
    stages: Vec<Vec<u8>>,
    calls: Vec<String>,
}
impl<'ast> Visit<'ast> for Evidence {
    fn visit_lit(&mut self, literal: &'ast Lit) {
        if let Lit::ByteStr(value) = literal {
            self.stages.push(value.value());
        }
        syn::visit::visit_lit(self, literal);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn caller_rejections_identify_the_existing_authority_check_before_live_capture() {
    let file = source();
    let mut evidence = Evidence::default();
    evidence.visit_block(&function(&file, "resolve").block);
    for stage in [
        "channel-route",
        "dispatch",
        "mixed-caller",
        "kernel-activation",
        "registry-current",
        "client-pi",
        "process-generation",
        "logical-caller-identity",
        "fresh-native-handle-caller",
        "autonomous-caller",
        "retained-owner",
    ] {
        assert!(
            evidence
                .stages
                .iter()
                .any(|value| value == stage.as_bytes()),
            "identify rejection at {stage} without weakening authority"
        );
    }
    let position = |name| evidence.calls.iter().position(|call| call == name).unwrap();
    assert!(position("channel_route") < position("dispatch"));
    assert!(position("dispatch") < position("registry_logical_caller_is_current"));
    assert!(
        position("registry_logical_caller_is_current")
            < position("validate_provider_logical_caller")
    );
    assert!(
        position("validate_provider_logical_caller") < position("capture_native_handle_caller")
    );
}

#[test]
fn rejection_diagnostics_do_not_capture_memory_or_manufacture_caller_authority() {
    let file = source();
    let mut evidence = Evidence::default();
    evidence.visit_block(&function(&file, "reject").block);
    for forbidden in [
        "read_volatile",
        "capture_native_handle_caller",
        "with_provider_process_manager",
        "copy_component_bytes_to_slice",
        "page_map_r",
        "syscall",
        "resolve",
    ] {
        assert!(
            !evidence.calls.iter().any(|call| call == forbidden),
            "failure logging must only observe already captured scalars: {forbidden}"
        );
    }
}
