use syn::{visit::Visit, Item};

struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            self.0.extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn initial_wait_snapshot_capture_has_one_policy_and_reparks_keep_saved_bytes() {
    let bridge = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    )).unwrap();
    let mut calls = Calls(Vec::new());
    calls.visit_file(&bridge);
    assert_eq!(calls.0.iter().filter(|name| *name == "capture_initial_arg_snapshot").count(), 2,
        "initial Provider/LPC suspension must share one snapshot policy");

    // Read at runtime so a missing module is a behavioral assertion, not a compile failure.
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/win32k_pending_dispatch.rs"))
        .expect("focused pending-dispatch capture module");
    let pending = syn::parse_file(&source).unwrap();
    let capture = pending.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "capture_initial_arg_snapshot" => Some(function),
        _ => None,
    }).expect("single initial capture policy");
    let syn::FnArg::Typed(ssn) = capture.sig.inputs.first().unwrap() else {
        panic!("explicit original service number required");
    };
    assert!(matches!(ssn.ty.as_ref(), syn::Type::Path(path) if path.path.is_ident("u64")),
        "capture must preserve the bridge's full service number without narrowing");
    for name in ["capture_provider_wait_repark", "capture_lpc_wait_repark"] {
        let function = pending.items.iter().find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }).expect("existing repark contract");
        let mut calls = Calls(Vec::new());
        calls.visit_block(&function.block);
        assert!(!calls.0.iter().any(|call| call == "capture_initial_arg_snapshot"
            || call == "copy_nonoverlapping"),
            "a repark must preserve the original captured bytes, not reread client aliases");
    }
}
