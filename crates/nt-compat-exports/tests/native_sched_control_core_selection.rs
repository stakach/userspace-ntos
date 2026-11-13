//! A hosted thread must select a provisioned physical SchedControl before its SC is allocated.

#[test]
fn explicit_guest_core_is_validated_before_scheduling_context_construction() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/thread_sched_context.rs"),
    ).unwrap();
    let explicit = source.find("fn attach_sched_context_on_core(")
        .expect("explicit physical core attachment exists");
    let body = &source[explicit..];
    let validate = body.find("validate_sched_control_core(core)")
        .expect("online and provisioned core admission precedes allocation");
    let construct = body.find("SchedContextConstruction::new(")
        .expect("SC construction follows core admission");
    assert!(validate < construct);
    assert!(source.contains("SLOT_SCHED_CONTROL + u64::from(self.core)"),
        "the exact per-core cap must configure the SC before bind");
    assert!(source.contains("attach_sched_context_on_core(tcb, GUEST_SCHED_CONTROL_CORE)"),
        "existing callers retain their core-zero path");
}
