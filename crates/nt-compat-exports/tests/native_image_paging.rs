use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn source(path: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(path);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("missing retained image paging entry {name}"))
}

fn calls(block: &syn::Block) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls.0
}

#[test]
fn user_leaf_table_prepares_exact_parent_hierarchy_before_native_effects() {
    let file = source("main.rs");
    let sequence = calls(&function(&file, "ensure_process_user_page_table").block);
    let parents = sequence.iter().position(|name| name == "ensure_process_user_paging_parents")
        .expect("PT-only mapping cannot admit an image in a missing PD/PDPT branch");
    for leaf in ["prepare_insert", "untyped_retype_r", "paging_struct_map_r"] {
        let leaf = sequence.iter().position(|name| name == leaf).unwrap();
        assert!(parents < leaf, "parent hierarchy must precede image backing/map effects");
    }
}

#[test]
fn image_paging_uses_retained_existing_mechanism_not_untracked_parent_caps() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/user_image_paging.rs");
    let text = std::fs::read_to_string(path)
        .expect("dynamic image parents require a retained exact-process paging owner");
    let file = syn::parse_file(&text).unwrap();
    struct Owners(bool);
    impl<'a> Visit<'a> for Owners {
        fn visit_type_path(&mut self, path: &'a syn::TypePath) {
            self.0 |= path.path.segments.iter().any(|part| part.ident == "OwnedPagingStructure");
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut owners = Owners(false);
    owners.visit_file(&file);
    assert!(owners.0, "reuse the acknowledged reserve/retype/map/retire owner");
    let entry = calls(&function(&file, "ensure_process_user_paging_parents").block);
    assert!(entry.iter().any(|name| name == "capture_process_identity"),
        "a reused capability integer or process slot cannot authenticate paging ownership");
    assert!(!entry.iter().any(|name| name == "cnode_delete_recycle_r"),
        "mapping refusal must retain parent cleanup ACKs, not discard their cap");
}

#[test]
fn process_teardown_retires_dynamic_image_parents_after_leaf_tables() {
    let file = source("process_vm_retirement.rs");
    let method = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "retire_page_tables" => Some(method),
            _ => None,
        }),
        _ => None,
    }).unwrap();
    let sequence = calls(&method.block);
    let leaves = sequence.iter().position(|name| name == "process_user_page_tables_release").unwrap();
    let parents = sequence.iter().position(|name| name == "retire_process_user_paging_parents")
        .expect("spawn VSpace withdrawal must not orphan newly installed image parents");
    assert!(leaves < parents, "child PTs retire before owned parent PD/PDPT mappings");
}
