//! Source integration checks supplement the executable PE and image-owner contracts.
//! They do not establish native File reads, frame cleanup, or desktop rendering.
use syn::{visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn body(file: &syn::File, name: &str) -> syn::Block {
    for item in &file.items {
        match item {
            Item::Fn(value) if value.sig.ident == name => return (*value.block).clone(),
            Item::Impl(value) => for method in &value.items {
                if let syn::ImplItem::Fn(method) = method {
                    if method.sig.ident == name { return method.block.clone(); }
                }
            },
            _ => {}
        }
    }
    panic!("missing native function {name}");
}

#[derive(Default)]
struct Audit { calls: Vec<String>, fields: Vec<String> }
impl<'ast> Visit<'ast> for Audit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member { self.fields.push(name.to_string()); }
        syn::visit::visit_expr_field(self, field);
    }
}
fn audit(block: &syn::Block) -> Audit {
    let mut audit = Audit::default();
    audit.visit_block(block);
    audit
}
fn has(audit: &Audit, name: &str) -> bool { audit.calls.iter().any(|call| call == name) }

#[test]
fn first_local_source_captures_bounded_metadata_from_the_retained_file() {
    let audited = audit(&body(&source("file_image_section.rs"), "submit_local_image_section"));
    assert!(has(&audited, "capture_image_layout"),
        "a first DLL source must not allocate and retain its entire canonical EOF");
    assert!(has(&audited, "read_exact"), "capture reads the retained exact File body");
    assert!(!has(&audited, "resize"), "no EOF-sized zeroed snapshot during Section admission");
    assert!(audited.fields.iter().any(|field| field == "file_extent"));
    let at = |name: &str| audited.calls.iter().position(|call| call == name).unwrap();
    for pin in ["retain_io", "retain_io_reference"] {
        assert!(at("reserve") < at(pin) && at(pin) < at("capture_image_layout"));
    }
    assert!(at("capture_image_layout") < at("reserve_local_native_image_section"));
}

#[test]
fn canonical_source_page_initialization_reads_exact_backing_spans() {
    let audited = audit(&body(&source("native_image_residency.rs"), "initialize"));
    assert!(has(&audited, "image_page_fill_plan") && has(&audited, "read_exact"),
        "source frame initialization must read planned spans from retained File authority");
    assert!(audited.fields.iter().any(|field| field == "file_extent"),
        "the authenticated EOF is not the size of the bounded header window");
    assert!(!has(&audited, "copy_nonoverlapping") && !has(&audited, "has_complete_image"),
        "a DLL's raw bytes are not an immutable executive Vec anymore");
    assert!(!audited.fields.iter().any(|field| field == "pe_header"));
    assert!(has(&audited, "with_scratch_range"), "retain the existing checked alias owner");
}

#[test]
fn mapping_and_query_use_the_single_typed_layout_without_snapshot_gates() {
    let mapped = audit(&body(&source("exec_native_image_view.rs"), "map_native_image_section_view"));
    assert!(mapped.fields.iter().any(|field| field == "layout"));
    assert!(!has(&mapped, "has_complete_image"));
    assert!(!mapped.fields.iter().any(|field| field == "pe_header"));
    struct Query(Option<syn::Arm>);
    impl<'ast> Visit<'ast> for Query {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, syn::Pat::Path(path)
                if path.path.segments.last().unwrap().ident == "NtQuerySection") {
                self.0 = Some(arm.clone());
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut query = Query(None);
    query.visit_file(&source("exec_handler.rs"));
    let mut queried = Audit::default();
    queried.visit_arm(&query.0.expect("actual NtQuerySection arm"));
    assert!(queried.fields.iter().any(|field| field == "layout"));
    assert!(!queried.fields.iter().any(|field| field == "pe_header"));
}

#[test]
fn only_actual_process_construction_materializes_a_full_owned_snapshot() {
    let process = audit(&body(&source("exec_image_process_create.rs"), "reserve_native_image_process"));
    assert!(has(&process, "materialize_process_snapshot"),
        "process-owned raw PE readers require one exact isolated materialization");
    assert!(!process.fields.iter().any(|field| field == "pe_header"));
    assert!(has(&process, "register_exact_loaded") && has(&process, "reference_view"),
        "process snapshot readers and canonical Section view retirement retain their existing ownership");
    let materialize = audit(&body(&source("native_image_source_io.rs"), "materialize_process_snapshot"));
    assert!(has(&materialize, "try_reserve_exact") && has(&materialize, "read_exact"));
}
