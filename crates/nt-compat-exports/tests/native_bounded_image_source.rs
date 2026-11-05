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
fn routed_dll_fault_retains_pending_read_until_page_and_reply_are_safe() {
    let fault_loop = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    ).unwrap();
    let deferred = fault_loop.find("native_image_pagein_work::submit(")
        .expect("retained routed DLL fault must park its original Reply before provider READ");
    let synchronous = fault_loop.find("match nt_handler.service_native_image_page_residency(")
        .expect("local and already resident image pages retain the synchronous root fault path");
    assert!(deferred < synchronous,
        "a pending installed DLL READ must not enter synchronous source-page initialization");

    let worker_text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/native_image_pagein_work.rs"),
    ).expect("native image page-in worker");
    let worker = syn::parse_file(&worker_text).expect("parsed native image page-in worker");
    let mut audited = Audit::default();
    audited.visit_file(&worker);
    for required in ["prepare", "commit", "new_at", "next_span",
        "bind_pending", "completed_irp_exact", "copy_completed_irp_output_exact",
        "terminal", "copy_fragment", "acknowledge_completed_irp_strict",
        "acknowledge", "accept_acknowledged_span", "completed_page"] {
        assert!(has(&audited, required),
            "pending DLL page worker must retain exact I/O and accept only ACKed spans: {required}");
    }
    for required in ["RootReplyPark", "RoutedImageRead", "ImagePageFillCapture",
        "capture_process_identity", "source_for_view", "capture_owned"] {
        assert!(worker_text.contains(required),
            "page worker must retain and revalidate the fault, source and File: {required}");
    }
}

#[test]
fn syscall_output_copy_waits_for_routed_image_page_before_dispatch() {
    let ingress = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/service_sec_image.rs"),
    ).unwrap();
    let preflight = ingress.find("native_image_pagein_work::submit_syscall_copy(")
        .expect("syscall ingress must retain a routed CopyAccess page before dispatch");
    let dispatch = ingress.find("nt_dispatcher.dispatch(m0 as u32, &argv[..n]")
        .expect("real syscall dispatch");
    assert!(preflight < dispatch, "output preflight must precede all syscall effects");

    let worker = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/native_image_pagein_work.rs"),
    ).expect("retained syscall CopyAccess owner");
    for required in ["RootReplyPark", "RoutedImageRead", "ImagePageFillCapture",
        "bind_pending", "completed_irp_exact", "copy_completed_irp_output_exact",
        "acknowledge_completed_irp_strict", "accept_acknowledged_span",
        "NtQuerySystemInformation", "dispatch", "reply_parked_syscall"] {
        assert!(worker.contains(required),
            "CopyAccess must retain source I/O through strict ACK before one dispatch: {required}");
    }
    assert!(worker.contains("CopyAccess"),
        "CopyAccess continuation must be distinct from a hardware fault reply");
}

#[test]
fn routed_hardware_fault_does_not_fall_through_on_an_unready_source_row() {
    use nt_memory_manager::image_source_page::ImageSourcePage;

    let row = ImageSourcePage::new((7u64, 0x11000u32));
    assert!(row.ready_frame().is_none(),
        "a retained source row is not proof that its physical frame is ready");

    let worker = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/native_image_pagein_work.rs"),
    ).unwrap();
    assert!(!worker.contains("if matches!(purpose, Purpose::Fault) && existing { return Ok(None); }"),
        "an unready routed row must stay retained; synchronous fallback can re-enter a pending File READ");
    assert!(worker.contains("static mut EXECUTING_SOURCE")
        && worker.contains("addr_of!(EXECUTING_SOURCE)")
        && worker.contains("addr_of_mut!(EXECUTING_SOURCE)"),
        "a producer removed from WORK during provider pumping must remain visible to a second fault");
}

#[test]
fn cancelled_dll_page_read_keeps_exact_key_through_copy_and_ack() {
    use nt_memory_manager::routed_image_read::RoutedImageRead;

    let mut read = RoutedImageRead::<_, u64, _>::new_at(17, 0, 4, 4, "captured File")
        .unwrap();
    read.enter_window().unwrap();
    assert!(read.bind_pending(41));
    assert!(read.terminal(41, 0, 4));
    assert_eq!(read.pending_key(), Some(41),
        "a terminal IRP remains the pending owner during copying");
    assert_eq!(read.copy_position(), Some((41, 0, 4)));
    read = read.abort_ready().err().expect("cancellation cannot withdraw an unacked IRP");
    assert!(read.copy_fragment(41, 0, b"data"));
    assert_eq!(read.acknowledgment_key(), Some(41));
    assert_eq!(read.pending_key(), Some(41),
        "the same IRP remains owned until strict ACK");
    read = read.abort_ready().err().expect("cancellation must still wait for strict ACK");
    assert!(read.acknowledge(41));
    assert_eq!(read.pending_key(), None);
    assert_eq!(read.into_terminal().ok().unwrap().1.unwrap(), b"data");

    let worker = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/native_image_pagein_work.rs"),
    ).unwrap();
    assert!(worker.contains("if cancelled && read.pending_key().is_none()")
        && worker.contains("abort_ready()")
        && worker.contains("acknowledge_completed_irp_strict"),
        "the worker may withdraw only a Ready owner and must ACK an entered IRP");
}

#[test]
fn routed_process_parent_is_pinned_after_one_access_admission() {
    use nt_process::{native_handle::{PsHandleType, STATUS_NOT_SUPPORTED}, HandleObject,
        ProcessManager, PROCESS_CREATE_PROCESS, STATUS_ACCESS_DENIED};
    use nt_types::AccessMode;

    let mut pm = ProcessManager::new();
    let system_pid = pm.create_process("kernel", None, None);
    let system_tid = pm.create_thread(system_pid, 0, 0, true).unwrap();
    pm.designate_initial_system(system_pid, system_tid).unwrap();
    assert!(pm.publish_process_kernel_object(system_pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(system_tid, 0x2000));
    let pid = pm.create_process("smss", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(tid, 0x4000));
    let caller = pm.capture_native_handle_caller(
        pm.thread_lifetime(tid).unwrap(), AccessMode::UserMode).unwrap();
    assert_eq!(pm.resolve_process_handle(pid, u64::MAX, PROCESS_CREATE_PROCESS), Ok(pid));
    assert_eq!(pm.reference_native_ps_handle(caller, u64::MAX,
        Some(PsHandleType::Process), PROCESS_CREATE_PROCESS).unwrap_err(), STATUS_NOT_SUPPORTED,
        "a second pseudo-handle grant check rejects the already admitted parent");
    let denied = pm.insert_handle(pid, HandleObject::Process(pid), 0).unwrap();
    assert_eq!(pm.resolve_process_handle(pid, u64::from(denied), PROCESS_CREATE_PROCESS),
        Err(STATUS_ACCESS_DENIED), "an ordinary handle still needs the first access admission");
    let mut parent = pm.reference_native_ps_handle(caller, u64::MAX,
        Some(PsHandleType::Process), 0).unwrap();
    assert_eq!(parent.object(), HandleObject::Process(pid));
    assert_eq!(Some(parent.body()), pm.process_kernel_object(pid));
    parent.release(&mut pm).unwrap();

    let ingress = audit(&body(&source("exec_handler.rs"), "nt_create_process_service"));
    assert!(ingress.calls.iter().position(|name| name == "resolve_process_handle")
        .expect("parent Process access admission")
        < ingress.calls.iter().position(|name| name == "submit_routed_process_image")
            .expect("retained routed image admission"),
        "parent access must be admitted before the retained snapshot owner enters");
    let worker = source("process_image_snapshot_work.rs");
    let source_text = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/process_image_snapshot_work.rs")).unwrap();
    assert!(source_text.contains("parent.object() != nt_process::HandleObject::Process(parent_pid)")
        && source_text.contains("process_kernel_object(parent_pid) != Some(parent.body())"),
        "the captured parent must still match both admitted Process identity and physical body");
    struct ParentReference(Option<syn::ExprMethodCall>);
    impl<'ast> Visit<'ast> for ParentReference {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "reference_native_ps_handle" { self.0 = Some(call.clone()); }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut reference = ParentReference(None);
    reference.visit_block(&body(&worker, "submit_routed_process_image"));
    let reference = reference.0.expect("retained exact parent Process reference");
    assert!(matches!(reference.args.last(), Some(Expr::Lit(lit))
        if matches!(&lit.lit, syn::Lit::Int(value) if value.base10_parse::<u32>().ok() == Some(0))),
        "once parent access was admitted, pin its exact object with zero additional access");
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
