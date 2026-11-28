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
    let main_preflight = method(&source, "pub(crate) fn preflight_main(", "pub(crate) fn register_main(");
    let registration = method(&source, "pub(crate) fn register_main(", "pub(crate) fn prepare_spawn(");
    let spawn_validation = method(&source, "pub(crate) fn validate_spawn(", "pub(crate) fn commit_spawn(");
    let spawn = method(&source, "pub(crate) fn commit_spawn(", "pub(crate) fn reserve(");
    assert!(main_preflight.contains("sched_context") && registration.contains("placement"),
        "main publication must retain its exact bound SC placement");
    assert!(main_preflight.contains("prepared_placement.as_ref()")
        && registration.find("self.preflight_main(")
            .is_some_and(|check| registration.find("self.try_store(")
                .is_some_and(|publish| check < publish))
        && registration.contains("prepared_placement.take()"),
        "main publication must validate and transfer the preallocated anchor");
    assert!(main_preflight.contains("existing.is_some()")
        && registration.find("self.preflight_main(")
            .is_some_and(|check| registration.find("entry.runtime.mechanism = mechanism")
                .is_some_and(|publish| check < publish)),
        "main publication must refuse a second placement owner before changing mechanism metadata");
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

#[test]
fn refused_main_publication_keeps_the_unregistered_native_spawn_owned() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handler = std::fs::read_to_string(root.join("components/ntos-executive/src/exec_handler.rs")).unwrap();
    let service = std::fs::read_to_string(root.join("components/ntos-executive/src/service_sec_image.rs")).unwrap();
    let child_publication = std::fs::read_to_string(root.join("components/ntos-executive/src/child_main_publication.rs")).unwrap();
    let routed = std::fs::read_to_string(root.join("components/ntos-executive/src/process_image_snapshot_work.rs")).unwrap();
    let immediate = std::fs::read_to_string(root.join("components/ntos-executive/src/hosted_spawn_uncertainty.rs")).unwrap();
    let syscall = std::fs::read_to_string(root.join("components/ntos-executive/src/executor/syscall_nt.rs")).unwrap();

    let registration = method(&handler, "pub(crate) fn register_main_thread_spawn(", "pub(crate) fn hosted_thread_tcb(");
    let signature = registration.split('{').next().unwrap();
    assert!(signature.contains("&mut img_spawn::SecImageSpawn")
        || signature.contains("&mut SecImageSpawn"),
        "a refused main runtime publication must return with the exact native TCB/SC spawn still owned by its caller");

    let error = method(&service, "pub(crate) enum HostedExeSpawnError {", "pub(crate) unsafe fn publish_reserved_hosted_exe(");
    assert!(error.contains("SecImageSpawn"),
        "a child whose native construction completed but runtime publication was refused needs an explicit owned error payload");
    let child = method(&service, "unsafe fn spawn_requested_hosted_exe(", "/// Initialize the live executive once");
    assert!(child.contains("ChildMainPublication::new(")
        && child.contains("child_owner.advance(pi, nt_handler)")
        && child_publication.contains("register_main_thread_spawn(")
        && child_publication.contains("self.owner.mechanism_mut()"),
        "the child must register from the exact retained construction owner across refusal");
    let child_publication_words = child_publication.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(child_publication_words.contains("placement.may_retire()")
        && child_publication_words.contains("placement.current_core(identity) == Ok(thread_sched_context::GUEST_SCHED_CONTROL_CORE)"),
        "child publication must preflight the runtime's exact placement admission before VSpace and PEB effects");
    assert!(!child.contains("register_main_thread_spawn(pi, child_spawn)"),
        "passing the spawn by value can discard unregistered physical capabilities on error");

    let routed_owner = method(&routed, "struct Work {", "impl Work {");
    let immediate_owner = method(&immediate, "struct Uncertain {", "static mut WORK:");
    assert!(routed_owner.contains("SecImageSpawn") && immediate_owner.contains("SecImageSpawn"),
        "both entered-spawn lanes must durably retain the owned unregistered spawn, not only a status or process identity");
    assert!(routed.contains("HostedExeSpawnError::") && syscall.contains("HostedExeSpawnError::"),
        "both callers must classify the owned error payload rather than dropping it");
    assert!(service.contains("register_main_thread_spawn(primary_pi, &mut primary_spawn)"),
        "primary bootstrap must retain its exact spawn across a registration refusal");
    assert!(!service.contains("register_main_thread_spawn(primary_pi, primary_spawn)\n        .expect"),
        "primary bootstrap cannot panic and discard an unregistered TCB/SC owner");
}

#[test]
fn primary_bootstrap_retains_spawn_when_registration_refuses() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let service = std::fs::read_to_string(root.join("components/ntos-executive/src/service_sec_image.rs")).unwrap();
    assert!(service.contains("register_main_thread_spawn(primary_pi, &mut primary_spawn)"),
        "primary bootstrap must keep the constructed TCB/SC owner across a refused registration");
    assert!(!service.contains("register_main_thread_spawn(primary_pi, primary_spawn)\n        .expect"),
        "a bootstrap refusal must not panic and discard the exact physical owner");
}

#[test]
fn deterministic_main_registration_refusal_cannot_retry_forever_after_vspace_publication() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = std::fs::read_to_string(root.join("components/ntos-executive/src/hosted_thread_runtime.rs")).unwrap();
    let handler = std::fs::read_to_string(root.join("components/ntos-executive/src/exec_handler.rs")).unwrap();
    let child = std::fs::read_to_string(root.join("components/ntos-executive/src/child_main_publication.rs")).unwrap();
    let registration = method(&runtime, "pub(crate) fn register_main(", "pub(crate) fn prepare_spawn(");
    assert!(runtime.contains("MainRuntimeRefusal")
        && runtime.contains("fn try_store(")
        && registration.contains("Result<HostedThreadRuntime, MainRuntimeRefusal>"),
        "runtime admission must distinguish a permanent binding conflict from allocation pressure");
    let handler_registration = method(&handler, "pub(crate) fn register_main_thread_spawn(", "pub(crate) fn hosted_thread_tcb(");
    assert!(!handler_registration.contains(").ok_or(nt_process::STATUS_INSUFFICIENT_RESOURCES)?"),
        "native registration cannot report every deterministic refusal as retryable OOM");
    assert!(child.contains("preflight_main_thread_spawn")
        && child.contains("refusal.is_permanent()")
        && child.contains("self.fatal_status = Some(refusal.status())"),
        "child admission must classify permanent refusal before VSpace effects and retain the exact owner in a fatal terminal state");
}

#[test]
fn uncertain_child_vspace_distinguishes_borrowed_journal_from_conflicting_owner() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let handler = std::fs::read_to_string(root.join("components/ntos-executive/src/exec_handler.rs")).unwrap();
    let child = std::fs::read_to_string(root.join("components/ntos-executive/src/child_main_publication.rs")).unwrap();
    let reconcile = method(&handler, "pub(crate) fn reconcile_child_vspace_publication(", "pub(crate) fn hosted_vspace_observer(");
    assert!(handler.contains("ChildVspacePublicationObservation")
        && reconcile.contains("ChildVspacePublicationObservation::Busy")
        && reconcile.contains("ChildVspacePublicationObservation::Conflict"),
        "an active journal borrow may retry, but a different published VSpace owner must be a permanent refusal");
    assert!(child.contains("ChildVspacePublicationObservation::Conflict")
        && child.contains("self.fatal_status = Some("),
        "the child must quarantine its original Reply and physical owner on a conflicting VSpace journal");
}
