use syn::visit::Visit;

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

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing focused native function {name}"))
}

#[test]
fn private_page_mapping_delegates_to_retained_installation_owner_without_local_rollback() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/main.rs"
    ))
    .unwrap();
    let wrapper = function(&file, "vm_map_private_page");
    let mut calls = Calls::default();
    calls.visit_block(&wrapper.block);
    assert_eq!(calls.0, ["map_private_page"],
        "private page effects belong to the retained installation owner, not unchecked frame-release rollback");
    struct Delegate(bool);
    impl<'a> Visit<'a> for Delegate {
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let parts: Vec<_> = path
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect();
                self.0 |= parts.ends_with(&[
                    "hosted_private_page_installation".into(),
                    "map_private_page".into(),
                ]);
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut delegate = Delegate(false);
    delegate.visit_block(&wrapper.block);
    assert!(
        delegate.0,
        "the live mapper must use the actual focused installation adapter"
    );
}

#[test]
fn private_page_installation_retains_native_effect_and_cleanup_receipts() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/hosted_private_page_installation.rs");
    let source = std::fs::read_to_string(path)
        .expect("private mapping needs a retained installation journal before native effects");
    let file = syn::parse_file(&source).unwrap();
    let mapper = function(&file, "map_private_page");
    let mut calls = Calls::default();
    calls.visit_block(&mapper.block);
    assert!(
        !calls.0.iter().any(|call| call == "vm_frame_release"),
        "a failed mapping must not discard cleanup acknowledgement through legacy rollback"
    );
    assert!(
        calls
            .0
            .iter()
            .any(|call| call == "capture_process_identity"),
        "the retained installation must bind the current canonical process incarnation"
    );
    let begin = calls
        .0
        .iter()
        .position(|call| call == "begin")
        .expect("reserve the actual retained installation before advancing native effects");
    let advance = calls
        .0
        .iter()
        .enumerate()
        .find_map(|(index, call)| (index > begin && call == "advance").then_some(index))
        .expect("execute acquisition/map/cleanup through the actual checked lifecycle");
    assert!(begin < advance);
    for raw in [
        "vm_frame_acquire",
        "page_map_r",
        "copy_cap_r",
        "cnode_delete_recycle_r",
    ] {
        assert!(
            !calls.0.iter().any(|call| call == raw),
            "{raw} belongs to a lifecycle backend, not unjournaled effects in the entrypoint"
        );
    }
    assert!(file.items.iter().any(|item| matches!(item, syn::Item::Static(value)
        if matches!(&*value.ty, syn::Type::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "PrivatePageInstallation")))),
        "the owner must outlive native refusal/uncertainty rather than disappear on stack return");
    let backend = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(value)
                if value.trait_.as_ref().is_some_and(|(_, path, _)| {
                    path.segments
                        .last()
                        .is_some_and(|part| part.ident == "PrivatePageInstallationIo")
                }) =>
            {
                Some(value)
            }
            _ => None,
        })
        .expect("the native adapter must use the real retained lifecycle backend contract");
    for name in [
        "map_frame",
        "map_alias",
        "publish",
        "unmap",
        "delete_alias",
        "recycle_alias",
        "release_frame",
    ] {
        let method = backend
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing acknowledged lifecycle backend {name}"));
        assert!(
            matches!(&method.sig.output, syn::ReturnType::Type(_, result)
            if matches!(&**result, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "InstallationEffect"))),
            "{name} must distinguish ACK, witnessed refusal, and uncertain effects"
        );
    }
}
