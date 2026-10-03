use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, value: &'ast syn::ExprMethodCall) {
        self.0.push(value.method.to_string());
        syn::visit::visit_expr_method_call(self, value);
    }
    fn visit_expr_call(&mut self, value: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*value.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, value);
    }
}

fn method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    file.items.iter().filter_map(|item| match item {
        syn::Item::Impl(value) => Some(&value.items), _ => None,
    }).flatten().find_map(|item| match item {
        syn::ImplItem::Fn(value) if value.sig.ident == name => Some(value), _ => None,
    }).unwrap_or_else(|| panic!("missing canonical image process bridge {name}"))
}

#[test]
fn process_creation_selects_canonical_section_before_legacy_image_bookkeeping() {
    let file = syn::parse_file(include_str!("../../../../components/ntos-executive/src/exec_handler.rs")).unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "nt_create_process_service").block);
    let canonical = calls.0.iter().position(|name| name == "reserve_native_image_process")
        .expect("native Section handles must select the exact retained image source");
    let legacy = calls.0.iter().position(|name| name == "index_for_section").unwrap();
    assert!(canonical < legacy, "legacy pseudo-Section state cannot select a canonical image");
}

#[test]
fn image_process_bridge_retains_exact_source_without_path_reopen_or_leaf_cache() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_image_process_create.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).expect("focused native image process bridge module")).unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "reserve_native_image_process").block);
    for required in ["lookup_native_section_handle", "source", "reference_view",
        "register_exact_loaded", "reserve_spawn_from_native_section"] {
        assert!(calls.0.iter().any(|name| name == required), "retain {required} boundary");
    }
    for forbidden in ["mint_handle", "admit_dynamic_hosted_exe", "load_file_to_pool",
        "load_hosted_executable_from_volume_path", "pe_and_pool_by_leaf", "get_latest_by_leaf"] {
        assert!(!calls.0.iter().any(|name| name == forbidden), "no filename-derived source authority via {forbidden}");
    }
}

#[test]
fn exact_loaded_image_registration_does_not_select_an_old_same_leaf_snapshot() {
    let file = syn::parse_file(include_str!("../../../../components/ntos-executive/src/hosted_loaded_images.rs")).unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "register_exact_loaded").block);
    assert!(!calls.0.iter().any(|name| matches!(name.as_str(), "position" | "pe_and_pool_by_leaf" | "register_if_loaded")),
        "a new exact image snapshot must not reuse an earlier cache row by leaf");
}

#[test]
fn generic_image_bridge_checks_relocation_plan_before_publication() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_image_process_create.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let body = &method(&file, "reserve_native_image_process").block;
    let mut calls = Calls::default();
    calls.visit_block(body);
    let checked = calls.0.iter().position(|name| name == "relocate_file_snapshot")
        .expect("generic canonical images require a checked, atomic raw-file relocation transform");
    for publication in ["reference_view", "admit_dynamic_executable_observed", "register_exact_loaded"] {
        let index = calls.0.iter().position(|name| name == publication).unwrap();
        assert!(checked < index, "reject malformed relocation before {publication}");
    }
    for unchecked in ["apply_relocations_to_buf", "read_unaligned", "write_unaligned", "write_volatile"] {
        assert!(!calls.0.iter().any(|name| name == unchecked), "no unchecked transform via {unchecked}");
    }
    #[derive(Default)]
    struct CheckedResult { try_depth: usize, propagated: bool }
    impl<'ast> Visit<'ast> for CheckedResult {
        fn visit_expr_try(&mut self, value: &'ast syn::ExprTry) {
            self.try_depth += 1;
            syn::visit::visit_expr_try(self, value);
            self.try_depth -= 1;
        }
        fn visit_expr_call(&mut self, value: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*value.func {
                if path.path.segments.last().unwrap().ident == "relocate_file_snapshot" {
                    assert_eq!(value.args.len(), 2, "checked transform takes independent bytes and load base");
                    self.propagated |= self.try_depth != 0;
                }
            }
            syn::visit::visit_expr_call(self, value);
        }
    }
    let mut checked_result = CheckedResult::default();
    checked_result.visit_block(body);
    assert!(checked_result.propagated, "malformed-image rejection must propagate before publication");
}
