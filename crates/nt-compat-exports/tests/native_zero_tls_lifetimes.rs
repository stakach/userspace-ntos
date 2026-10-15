//! TLS clearing must not revisit retained ETHREADs whose TEB windows were retired or reused.
use syn::visit::Visit;

fn source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn method<'a>(source: &'a syn::File, name: &str) -> Option<&'a syn::ImplItemFn> {
    source.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None };
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
            _ => None,
        })
    })
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls.0
}

#[test]
fn zero_tls_does_not_enumerate_historical_thread_tebs_or_use_a_pool_sized_snapshot() {
    let source = source();
    let clear = method(&source, "nt_set_thread_zero_tls_cell").unwrap();
    let calls = calls(&clear.block);
    assert!(
        !calls.iter().any(|call| call == "for_each_process_thread_teb"),
        "retained terminated ETHREADs do not own their old mapped TEB windows"
    );
    struct FixedSnapshot(bool);
    impl<'ast> Visit<'ast> for FixedSnapshot {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.0 |= ident == "TEB_CAPTURE_LIMIT" || ident == "PM_RUNTIME_THREAD_SLOTS";
        }
    }
    let mut fixed = FixedSnapshot(false);
    fixed.visit_block(&clear.block);
    assert!(!fixed.0, "canonical thread identities are not a fixed mechanism pool");
    assert!(calls.iter().any(|call| call == "capture_live_thread_tebs"));
}

#[test]
fn tls_snapshot_is_fallible_and_captures_exact_executable_thread_lifetimes() {
    let source = source();
    let capture = method(&source, "capture_live_thread_tebs")
        .expect("TLS capture must own a copied live-runtime snapshot before user-memory effects");
    let calls = calls(&capture.block);
    for required in ["executable_by_index", "capture_provider_logical_caller", "thread_teb"] {
        assert!(calls.iter().any(|call| call == required), "missing {required}");
    }
    assert!(calls.iter().any(|call| call == "try_reserve" || call == "try_reserve_exact"));
    assert!(!calls.iter().any(|call| call == "for_each_process_thread_teb"));
    assert!(!calls.iter().any(|call| call == "xas_read" || call == "xas_write_u64"));
}

#[test]
fn each_tls_write_target_revalidates_its_copied_lifetime_and_teb_before_memory_access() {
    let source = source();
    let validate = method(&source, "validate_live_thread_teb")
        .expect("copied TEB addresses require exact current lifetime revalidation");
    let validation_calls = calls(&validate.block);
    for required in ["validate_provider_logical_caller", "thread_teb"] {
        assert!(validation_calls.iter().any(|call| call == required), "missing {required}");
    }
    let clear = method(&source, "nt_set_thread_zero_tls_cell").unwrap();
    struct TargetLoop(bool);
    impl<'ast> Visit<'ast> for TargetLoop {
        fn visit_expr_for_loop(&mut self, loop_: &'ast syn::ExprForLoop) {
            let calls = calls(&loop_.body);
            if let Some(write) = calls.iter().position(|call| call == "xas_write_u64") {
                self.0 |= calls.iter().position(|call| call == "validate_live_thread_teb")
                    .is_some_and(|validate| validate < write);
            }
            syn::visit::visit_expr_for_loop(self, loop_);
        }
    }
    let mut target = TargetLoop(false);
    target.visit_block(&clear.block);
    assert!(target.0, "TLS iteration must revalidate its exact copied target before writes");
}
