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
    assert!(owner.contains("PlacementReadOwner"), "the runtime row must retain the stable placement anchor");
    let registration = method(&source, "pub(crate) fn register_main(", "pub(crate) fn prepare_spawn(");
    let spawn_validation = method(&source, "pub(crate) fn validate_spawn(", "pub(crate) fn commit_spawn(");
    let spawn = method(&source, "pub(crate) fn commit_spawn(", "pub(crate) fn reserve(");
    assert!(registration.contains("sched_context") && registration.contains("placement"),
        "main publication must retain its exact bound SC placement");
    assert!(registration.find("prepared_placement.as_ref()")
        .is_some_and(|check| registration.find("self.store(")
            .is_some_and(|publish| check < publish))
        && registration.contains("prepared_placement.take()"),
        "main publication must validate and transfer the preallocated anchor");
    assert!(registration.find("owner.current_core(identity)")
        .is_some_and(|check| registration.find("entry.runtime.mechanism = mechanism")
            .is_some_and(|publish| check < publish)),
        "replayed main publication must validate exact placement before changing mechanism metadata");
    assert!(spawn_validation.contains("sched_context") && spawn_validation.contains("placement.current_core(identity)"),
        "worker publication must validate its exact bound SC placement");
    assert!(spawn.contains("spawn.take_placement()") && !spawn.contains("PlacementReadOwner::try_new"),
        "worker publication transfers the prepared anchor without allocation");
    assert!(source.contains("pub(crate) fn known_physical_core("),
        "native syscall handler needs a checked query of known placement");
    let retirement = method(&source, "fn construction_is_empty(&self)", "fn into_legacy_runtime(");
    assert!(retirement.contains("PlacementReadOwner::may_retire"),
        "live loans and pending or uncertain placement must pin runtime retirement");
    let handoff = method(&source, "fn registered_mechanism_slots(&self)", "fn clear_registered_mechanism_projections(");
    assert!(handoff.contains("may_retire"),
        "mechanism handoff must not release an SC while a live loan or transition exists");
}

#[test]
fn thread_mechanism_teardown_checks_placement_before_stopping_its_tcb() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let main = std::fs::read_to_string(root.join("components/ntos-executive/src/main.rs")).unwrap();
    let teardown = method(
        &main,
        "unsafe fn terminate_hosted_thread_mechanism(",
        "unsafe fn terminate_hosted_process_mechanisms(",
    );
    let placement = teardown.find("handler.hosted_thread_placement_may_retire(tid, tcb)")
        .expect("teardown checks the exact runtime's placement loan and TCB before native effects");
    let suspend = teardown.find("tcb_suspend_r(tcb)").expect("physical TCB stop");
    let delete = teardown.find("cnode_delete_recycle_r(tcb)").expect("physical TCB deletion");
    assert!(placement < suspend && placement < delete,
        "a live read loan must block TCB suspension and deletion before either native effect");
    let recheck = teardown[suspend..delete].find("handler.hosted_thread_placement_may_retire(tid, tcb)");
    assert!(recheck.is_some(),
        "nested cancellation may change the loan owner; recheck immediately before TCB deletion");
}

#[test]
fn main_thread_reserves_placement_before_native_construction() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = std::fs::read_to_string(root.join("components/ntos-executive/src/img_spawn.rs")).unwrap();
    let spawn = method(&source, "pub(crate) unsafe fn spawn_sec_image(", "/// Read a u64 through");
    let reserve = spawn.find("PlacementReadReservation::try_new")
        .expect("main-thread placement storage must be reserved before native effects");
    let first_effect = spawn.find("trace_spawn_phase(pi, b\"begin\")")
        .expect("native construction begins here");
    assert!(reserve < first_effect, "placement OOM must precede physical TCB/SC construction");
    assert!(spawn.contains(".initialize(placement)"),
        "the reserved allocation must be initialized without another allocation after SC attach");
}

#[test]
fn processor_services_read_caller_placement_and_forward_rtl_exports() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handler = std::fs::read_to_string(root.join("components/ntos-executive/src/exec_handler.rs")).unwrap();
    let table = std::fs::read_to_string(root.join("components/ntos-executive/src/main.rs")).unwrap();
    let exports = std::fs::read_to_string(root.join("crates/nt-ntdll-dll/src/exports.rs")).unwrap();
    let query = method(&handler, "fn known_current_caller_physical_core(", "pub(crate) fn reserve_hosted_thread_runtime(");
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
