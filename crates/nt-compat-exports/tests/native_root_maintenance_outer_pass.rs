//! A parked syscall must get an actual outer worker turn before its exact resume.

const ROOT: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn maintenance_park_runs_independent_worker_before_receive_and_resume() {
    let branch = ROOT.split("if component_suspension_park_request {").nth(1)
        .expect("parked syscall branch")
        .split("if active_callback_bad_resume").next().unwrap();
    let worker = branch.find("process_image_snapshot_work::redrive")
        .expect("independent process-image worker turn");
    let pass = branch.find("mark_root_maintenance_pass")
        .expect("exact suspension observes completed outer pass");
    let resume = branch.find("run_root_maintenance")
        .expect("typed maintenance resume");
    let receive = branch.find("component_recv!")
        .expect("next ingress receive");
    assert!(worker < pass && pass < resume && resume < receive,
        "worker return, pass grant and exact resume precede blocking Receive");
    assert!(branch.contains("maintenance_ticket"), "park branch retains the exact ticket");
}

#[test]
fn maintenance_pass_epoch_advances_only_after_worker_turn() {
    assert!(ROOT.contains("static ROOT_MAINTENANCE_PASS: AtomicU64"));
    let branch = ROOT.split("if component_suspension_park_request {").nth(1)
        .expect("parked syscall branch")
        .split("if active_callback_bad_resume").next().unwrap();
    let worker = branch.find("process_image_snapshot_work::redrive").unwrap();
    let bump = branch.find("ROOT_MAINTENANCE_PASS")
        .expect("checked outer pass epoch increment");
    assert!(worker < bump);
    assert!(!branch.contains("ComponentSuspensionCompletion::receive_ready()"),
        "maintenance readiness is not a fabricated provider result");
}

#[test]
fn maintenance_outer_pass_requires_a_real_worker_attempt_without_a_pending_child() {
    const WORKER: &str = include_str!(
        "../../../components/ntos-executive/src/process_image_snapshot_work.rs"
    );
    let branch = ROOT.split("if component_suspension_park_request {").nth(1)
        .expect("parked syscall branch")
        .split("if active_callback_bad_resume").next().unwrap();
    let worker = branch.find("process_image_snapshot_work::redrive").unwrap();
    let exclusion = branch.find("if receive_child_pending {").unwrap();
    let refusal = branch.find("break 'service_loop;").unwrap();
    assert!(exclusion < refusal && refusal < worker,
        "pending Receive child must retain the maintenance owner without worker reentry");
    let receipt = branch.find("if !worker_attempted").expect("worker attempt receipt");
    let grant = branch.find("mark_root_maintenance_pass").unwrap();
    assert!(worker < receipt && receipt < grant);
    assert!(branch[receipt..grant].contains("if !worker_attempted"),
        "a no-op worker call cannot grant readiness");
    assert!(WORKER.contains("pub(crate) unsafe fn redrive(")
        && WORKER.contains(") -> bool {")
        && WORKER.contains("Some(Step::Progress)"),
        "image redrive reports an entered step to its caller");
}

#[test]
fn all_waiting_quiesce_keeps_an_admitted_ready_maintenance_owner() {
    let gate = ROOT.split("macro_rules! mark_wait_parked {").nth(1)
        .expect("all-waiting gate")
        .split("// Boot-milestone watchdog").next().unwrap();
    assert!(gate.contains("root_maintenance_owner::next_ready_ticket().is_none()"),
        "a ready deferred checkpoint must keep the service loop alive");
}
