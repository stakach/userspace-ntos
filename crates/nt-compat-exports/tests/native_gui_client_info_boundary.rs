use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("focused GUI copyout function")
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn gui_copyout_authenticates_before_capture_and_revalidates_before_teb_writes() {
    let file = source("hosted_gui_client_info.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "service").block);
    let index = |name: &str| calls.0.iter().position(|call| call == name).unwrap();
    assert!(index("authenticate_win32k_service_request") < index("capture_provider_pool_packet"));
    assert!(index("capture_provider_pool_packet") < index("read_unaligned"));
    assert!(index("read_unaligned") < index("capture"));
    assert!(index("capture") < index("map_win32k_user_heap_into_client"));
    assert!(index("map_win32k_user_heap_into_client") < index("values_for"));
    assert!(index("values_for") < index("write_volatile"));
    let mapping = index("map_win32k_user_heap_into_client");
    let publication = index("write_volatile");
    for name in [
        "capture_process_identity",
        "thread_lifetime",
        "current_win32k_provider_domain",
        "current_provider_poll_owner",
        "hosted_gui_thread_teb_alias_for",
        "hosted_process_generation",
        "thread_win32",
    ] {
        assert!(
            calls.0[mapping + 1..publication]
                .iter()
                .any(|call| call == name),
            "revalidate {name} after mapping and before publication"
        );
    }
    let wrapper = source("service_sec_image.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&wrapper, "service_win32k_gui_client_info").block);
    assert_eq!(calls.0, ["service"]);
}

#[test]
fn rejection_diagnostics_only_read_captured_scalars_and_preserve_status() {
    let file = source("hosted_gui_client_info.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "rejected").block);
    assert!(calls.0.iter().all(|name| matches!(
        name.as_str(),
        "print_str"
            | "print_hex_u64"
            | "print_u64"
            | "from"
            | "pi"
            | "process"
            | "thread"
            | "thread_id"
            | "generation"
            | "badge"
    )));
    let last = function(&file, "rejected").block.stmts.last().unwrap();
    assert!(matches!(last, syn::Stmt::Expr(Expr::Cast(cast), None)
        if matches!(&*cast.expr, Expr::Path(path) if path.path.is_ident("status"))));
}
