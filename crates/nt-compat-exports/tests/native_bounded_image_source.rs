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
fn routed_process_snapshot_retains_pending_file_reads_before_process_publication() {
    let ingress = audit(&body(&source("exec_handler.rs"), "nt_create_process_service"));
    assert!(has(&ingress, "submit_routed_process_image"),
        "a routed installed image may return a pending File READ; process creation must retain its Section, File and original Reply instead of returning IO_DEVICE_ERROR");

    let worker_source = source("process_image_snapshot_work.rs");
    let mut worker = Audit::default();
    worker.visit_file(&worker_source);
    for required in ["bind_pending", "terminal", "copy_fragment",
        "acknowledge_completed_irp_strict", "acknowledge", "into_terminal"] {
        assert!(has(&worker, required),
            "routed process image snapshot must retain exact pending bytes through provider ACK: {required}");
    }
    assert!(has(&worker, "reserve_native_image_process_with_bytes"),
        "process construction may publish only the fully acknowledged owned PE snapshot");
    let process = audit(&body(&source("exec_image_process_create.rs"),
        "reserve_native_image_process_with_bytes"));
    assert!(has(&process, "register_exact_loaded"),
        "the completed snapshot must become the exact process-owned image");
}

#[test]
fn failed_dynamic_process_admission_never_binds_an_older_pi_occupant() {
    let source = source("exec_image_process_create.rs");
    let reserve = audit(&body(&source, "reserve_native_image_process_with_bytes"));
    assert!(reserve.calls.iter().position(|call| call == "pm_pid_for_pi")
        .expect("fresh process index preflight")
        < reserve.calls.iter().position(|call| call == "allocate_hosted_process_slot")
            .expect("hosted process allocation"),
        "a fresh dynamic image must reject an occupied process index before process allocation");
    let abort = audit(&body(&source, "abort_native_image_process"));
    assert!(has(&abort, "get") && abort.fields.iter().any(|field| field == "generation")
        && abort.fields.iter().any(|field| field == "top_badge"),
        "failed admission may bind the image owner only to its exact hosted mechanism generation");
    let unentered = audit(&body(&source, "abort_unentered_native_image_process"));
    assert!(has(&unentered, "discard_native_section_spawn")
        && has(&unentered, "rollback_hosted_process_creation")
        && has(&unentered, "abort_native_image_process"),
        "a proven unentered spawn must retire its exact image reservation and child metadata");
}

#[test]
fn immediate_spawn_entered_error_keeps_original_reply_and_process_owner() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/service_sec_image.rs");
    let service_source = std::fs::read_to_string(path).unwrap();
    let start = service_source.find("if let Some(request) = nt_handler.exe_spawn_request")
        .expect("immediate hosted spawn branch");
    let end = service_source[start..].find("} else if m0 >= win32k_subsystem")
        .expect("end of hosted spawn branch") + start;
    let branch = &service_source[start..end];
    assert!(branch.find("hosted_spawn_uncertainty::prepare")
        .expect("pre-effect Reply owner admission")
        < branch.find("publish_reserved_hosted_exe").expect("physical hosted spawn"),
        "the original Reply and retained owner must be admitted before physical spawn");
    assert!(branch.contains("hosted_spawn_uncertainty::retain_entered"),
        "an entered spawn error cannot become an ordinary failed syscall Reply");
    assert!(branch.contains("abort_unentered_hosted_exe"),
        "failed pre-effect admission must retire the exact reserved spawn and new child");
    let process = audit(&body(&source("exec_handler.rs"), "nt_create_process_service"));
    assert!(has(&process, "abort_unentered_hosted_child"),
        "a failed spawn reservation after child allocation must release that exact PM slot");
}
