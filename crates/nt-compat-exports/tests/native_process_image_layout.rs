use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct Paths(Vec<String>);
impl<'a> Visit<'a> for Paths {
    fn visit_expr_path(&mut self, path: &'a syn::ExprPath) {
        self.0.extend(path.path.segments.iter().map(|segment| segment.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }
    fn visit_type_path(&mut self, path: &'a syn::TypePath) {
        self.0.push(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_type_path(self, path);
    }
}

#[test]
fn canonical_process_reservation_preserves_preferred_layout_not_global_relocation() {
    let file = source("exec_image_process_create.rs");
    let method = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "reserve_native_image_process" => Some(method),
            _ => None,
        }),
        _ => None,
    }).unwrap();
    let mut paths = Paths(Vec::new());
    paths.visit_block(&method.block);
    assert!(!paths.0.iter().any(|path| path == "PE_LOAD_BASE"),
        "canonical Section TransferAddress cannot describe a differently relocated process image");
    assert!(paths.0.iter().any(|path| path == "ProcessImageLayout"),
        "retain one checked base/extent/entry contract before native process effects");
}

#[test]
fn sec_image_spawn_consumes_exact_layout_for_paging_peb_and_entry() {
    let file = source("img_spawn.rs");
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "spawn_sec_image" => Some(function),
        _ => None,
    }).unwrap();
    let mut paths = Paths(Vec::new());
    paths.visit_signature(&function.sig);
    assert!(paths.0.iter().any(|path| path == "ProcessImageLayout"));
    paths.0.clear();
    paths.visit_block(&function.block);
    assert!(!paths.0.iter().any(|path| path == "PE_LOAD_BASE"),
        "spawn cannot publish a fixed PEB/entry distinct from its admitted image layout");
}

#[test]
fn checked_copy_target_uses_retained_main_layout_instead_of_global_image_base() {
    let file = source("main.rs");
    let method = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "for_process" => Some(method),
            _ => None,
        }),
        _ => None,
    }).unwrap();
    let mut paths = Paths(Vec::new());
    paths.visit_block(&method.block);
    assert!(!paths.0.iter().any(|path| path == "PE_LOAD_BASE"),
        "cross-process copies must use the same exact mapped image bounds as faults");
}
