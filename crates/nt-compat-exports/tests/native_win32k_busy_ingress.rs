//! A returned Receive frame may still own the shared win32k publication after its physical
//! lane parks. The next hosted Call must keep its original message and Reply until admission.

fn source(name: &str) -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src")
            .join(name),
    ).unwrap()
}

#[test]
fn busy_page_keeps_undelivered_win32k_call_in_its_original_owner() {
    let hosted = source("component_ingress_hosted.rs");
    let start = hosted.find("pub(crate) unsafe fn take_hosted_with(").unwrap();
    let end = hosted[start..].find("pub(crate) unsafe fn take_selected_root_hosted_with(")
        .unwrap() + start;
    let selection = &hosted[start..end];
    let filter = selection.find(".filter_map(|(index, row)|").unwrap();
    let import = selection.find("if !import(reply, &message)").unwrap();
    assert!(selection[filter..import].contains("component_shared_publication_is_busy()"),
        "the shared-page gate must run before Reply import and delivered=true");
    assert!(selection[filter..import].contains("call.message()"),
        "classify the original retained message, not staged or mutable syscall locals");
    assert!(selection[filter..import].contains("is_win32k_native_call"),
        "only win32k shadow syscalls should wait for this page");
    let classifier = hosted.split("fn is_win32k_native_call(").nth(1).unwrap();
    let classifier = classifier.split('}').next().unwrap();
    assert!(classifier.contains("NT_NATIVE_SYSCALL_LABEL"),
        "ordinary fault ingress must remain independently deliverable");
    assert!(classifier.contains("WIN32K_SERVICE_BASE"),
        "use the same shadow-table boundary as native dispatch");
}

#[test]
fn busy_page_returns_unexecuted_import_to_exact_hosted_call_before_staging() {
    let hosted = source("component_ingress_hosted.rs");
    let start = hosted.find("pub(crate) unsafe fn defer_hosted_delivery(").unwrap();
    let end = hosted[start..].find("pub(crate) unsafe fn owns_hosted_reply(").unwrap() + start;
    let defer = &hosted[start..end];
    assert!(defer.contains("component_shared_publication_is_busy()"));
    assert!(defer.contains("call.message()"),
        "a delivered Call must be classified from its retained original message");
    assert!(defer.contains("query_component_reply_binding(binding.tcb, reply)"));
    assert!(defer.contains("RootReplyPark::prepare()"));
    assert!(defer.contains(".delivered = false"));

    let service = source("service_sec_image.rs");
    let capture = service.find("let native_ingress_request = nt_syscall_abi::NativeSyscallRequest::capture(")
        .unwrap();
    let staging = service[capture..].find("let native_call_transport =").unwrap() + capture;
    let early = &service[capture..staging];
    assert!(early.contains("component_shared_publication_is_busy()"));
    assert!(early.contains("defer_hosted_delivery("));
    assert!(early.contains("component_recv!(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed))"));
    assert!(early.contains("continue 'service_loop;"),
        "deferred work must not fall through to mutable win32k staging");
}
