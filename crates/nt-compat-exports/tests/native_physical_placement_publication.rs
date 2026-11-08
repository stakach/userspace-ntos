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
