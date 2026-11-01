use syn::{visit::Visit, Expr, Item};

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/provider_directory_broker.rs");

fn calls_in(source: &str, function: &str) -> Vec<String> {
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.0.push(path.path.segments.iter().map(|part| part.ident.to_string())
                    .collect::<Vec<_>>().join("::"));
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let file = syn::parse_file(source).expect("native source parses");
    let body = file.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == function => Some(&item.block),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {function}"));
    let mut calls = Calls(Vec::new());
    calls.visit_block(body);
    calls.0
}

#[test]
fn deferred_directory_publication_is_admitted_to_the_nested_redrive() {
    let gate = calls_in(SERVICE, "nested_hosted_file_work_ready");
    let runner = calls_in(SERVICE, "redrive_nested_hosted_file_work");
    assert!(runner.iter().any(|call| call.ends_with("provider_directory_broker::redrive_nested_ready")),
        "the nested runner must retain directory publication ownership");
    assert!(gate.iter().any(|call| call.ends_with("provider_directory_broker::nested_work_ready")),
        "a directory-only deferred PUBLISH must wake the nested runner");
    let readiness = calls_in(BROKER, "nested_work_ready");
    assert!(readiness.iter().any(|call| call.ends_with("wake_due")),
        "nested directory readiness must respect retry cadence");
    assert!(!readiness.iter().any(|call| call.ends_with("has_outstanding")),
        "uncertain or quarantined directory work must not hot-spin the pump");
}
