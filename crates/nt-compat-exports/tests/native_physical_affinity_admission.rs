//! Native affinity changes must not exclude the physical core of a published guest runtime.
//! These source regressions cover the integration boundary that pure placement-owner tests cannot.

fn handler_source() -> String {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    std::fs::read_to_string(root.join("exec_handler.rs")).unwrap()
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let begin = source.find(start).expect("native handler exists");
    let finish = source[begin..].find(end).expect("next native handler exists") + begin;
    &source[begin..finish]
}

#[test]
fn thread_affinity_preflights_exact_runtime_before_ps_mutation() {
    let source = handler_source();
    let setter = between(
        &source,
        "pub(crate) fn set_thread_information_captured(",
        "fn resolve_thread_for_set(",
    );
    let affinity = between(setter, "4 =>", "9 =>");
    let preflight = affinity
        .find("validate_thread_physical_affinity(")
        .expect("ThreadAffinityMask must query exact target placement");
    let ps_change = affinity
        .find("self.pm.set_thread_affinity_mask(")
        .expect("ThreadAffinityMask must update Ps after admission");
    assert!(preflight < ps_change, "physical placement admission must precede Ps mutation");
}

#[test]
fn job_assignment_preflights_all_published_runtime_cores_before_commit() {
    let source = handler_source();
    let assignment = between(
        &source,
        "fn nt_assign_process_to_job_object(",
        "unsafe fn nt_create_job_set(",
    );
    let preflight = assignment
        .find("preflight_process_job_physical_affinity(")
        .expect("job affinity must admit all exact published process runtimes");
    let ps_change = assignment
        .find("self.pm.commit_process_job_assignment(")
        .expect("job assignment must commit Ps policy after admission");
    assert!(preflight < ps_change, "physical placement admission must precede job commit");
}
