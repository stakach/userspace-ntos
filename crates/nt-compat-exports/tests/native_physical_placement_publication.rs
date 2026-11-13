//! The native runtime must retain the authoritative placement with its exact mechanism owner.
//! Pure placement state tests cannot catch a missing publication or an unsafe retirement path.

fn source() -> String {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    std::fs::read_to_string(root.join("hosted_thread_runtime.rs")).unwrap()
}

fn method<'a>(source: &'a str, name: &str, next: &str) -> &'a str {
    let start = source.find(name).expect("native method exists");
    let end = source[start..].find(next).expect("next native method exists") + start;
    &source[start..end]
}

#[test]
fn published_runtime_owns_exact_physical_placement_until_retirement() {
    let source = source();
    let owner = method(&source, "pub(crate) struct HostedThreadRuntimeOwner {", "impl HostedThreadRuntimeOwner {");
    assert!(owner.contains("PhysicalPlacementOwner"), "the non-Copy runtime row must retain placement");
    let registration = method(&source, "pub(crate) fn register_main(", "pub(crate) fn prepare_spawn(");
    let spawn = method(&source, "pub(crate) fn commit_spawn(", "pub(crate) fn reserve(");
    assert!(registration.contains("sched_context") && registration.contains("placement"),
        "main publication must retain its exact bound SC placement");
    assert!(registration.find("owner.current_core(identity)")
        .is_some_and(|check| registration.find("entry.runtime.mechanism = mechanism")
            .is_some_and(|publish| check < publish)),
        "replayed main publication must validate exact placement before changing mechanism metadata");
    assert!(spawn.contains("sched_context") && spawn.contains("placement"),
        "worker publication must retain its exact bound SC placement");
    assert!(source.contains("pub(crate) fn known_physical_core("),
        "native syscall handler needs a checked query of known placement");
    let retirement = method(&source, "fn construction_is_empty(&self)", "fn into_legacy_runtime(");
    assert!(retirement.contains("transition_is_settled"),
        "pending or uncertain placement must pin the runtime through retirement");
    let handoff = method(&source, "fn registered_mechanism_slots(&self)", "fn clear_registered_mechanism_projections(");
    assert!(handoff.contains("transition_is_settled"),
        "mechanism handoff must not release a pending or uncertain SC");
}

#[test]
fn processor_services_read_caller_placement_and_forward_rtl_exports() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handler = std::fs::read_to_string(root.join("components/ntos-executive/src/exec_handler.rs")).unwrap();
    let table = std::fs::read_to_string(root.join("components/ntos-executive/src/main.rs")).unwrap();
    let exports = std::fs::read_to_string(root.join("crates/nt-ntdll-dll/src/exports.rs")).unwrap();
    let query = method(&handler, "fn known_current_caller_physical_core(&self)", "pub(crate) fn reserve_hosted_thread_runtime(");
    assert!(query.contains("admit_hosted_thread_ingress(self.current_badge)")
        && query.contains("caller.pi != self.pi || caller.tid != self.current_tid")
        && query.contains("known_hosted_thread_physical_core(caller)"),
        "processor identity must come from the re-admitted exact caller runtime");
    let service = method(&handler, "NativeService::NtGetCurrentProcessorNumber =>", "// Close the caller's canonical table entry");
    assert!(service.contains("NativeService::NtGetCurrentProcessorNumberEx")
        && service.contains("processor_number_for_index")
        && service.contains("xas_try_write_buf")
        && service.contains("STATUS_ACCESS_VIOLATION"),
        "processor services must return the caller core and check the four-byte output write");
    assert!(table.contains("(NativeService::NtGetCurrentProcessorNumber, 0x446)")
        && table.contains("(NativeService::NtGetCurrentProcessorNumberEx, 0x447)"),
        "both released ntdll service numbers must be published");
    let rtl = method(&exports, "pub unsafe extern \"system\" fn rtl_get_current_processor_number()", "/// `RtlIsProcessorFeaturePresent");
    assert!(rtl.contains("nt_get_current_processor_number()")
        && rtl.contains("nt_get_current_processor_number_ex(processor_number as u64)"),
        "RTL exports must query the native caller placement");
}
