//! SCSI timing observes the existing component scheduler without changing transport order.

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SCHEDULER: &str = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");

#[test]
fn only_the_admitted_scsi_dispatch_passes_its_exact_claim_to_the_scheduler() {
    let dispatch = DRIVER.split("unsafe fn dispatch_irp_for_instance_exact(").nth(1).unwrap();
    let claim = dispatch.find("SCSI_SRB_PUMP_OWNERS.claim(").unwrap();
    let enter = dispatch.find("scsi_srb_pump_timing.enter_pump()").unwrap();
    let observed_child = dispatch.find("component_scheduler::hosted_component_pump_observed_child_work(")
        .expect("suspend-aware SCSI dispatch must pass its exact claim to the scheduler");
    let observed = dispatch.find("component_scheduler::hosted_component_pump_observed(")
        .expect("synchronous SCSI dispatch must pass its exact claim to the scheduler");
    let retire = dispatch.find("drop(scsi_srb_pump_owner)").unwrap();
    assert!(claim < enter && enter < observed_child && observed_child < observed && observed < retire);
    let resume = DRIVER.split("unsafe fn resume_after_child(").nth(1).unwrap();
    assert!(resume.contains("Ok(FileIrpResumeProgress::Completed(self.finish(out)))"),
        "resumed SCSI dispatch must settle through the same File completion boundary");
    let finish = DRIVER.split("unsafe fn finish(self, out: &mut [u8]) -> HostedIrpTransportResult {")
        .nth(1).unwrap();
    let restored = finish.find("Some(component_scheduler::HostedPumpRestore::Restored(pr))")
        .expect("File completion requires a restored pump");
    let exit = finish.find("scsi_srb_pump_timing.exit_pump()")
        .expect("SCSI timing must include the resumed child-work interval");
    assert!(restored < exit,
        "SCSI timing must settle only after a completed or resumed pump restores its parent");
    assert!(dispatch.contains("hosted_component_pump_with_caller(&ch, caller)"),
        "non-SCSI dispatch keeps its original caller-bound pump");
}

#[test]
fn scheduler_stage_boundaries_do_not_move_completion_or_restore() {
    let scheduler = SCHEDULER.split("unsafe fn hosted_component_pump_inner(").nth(1).unwrap();
    assert!(scheduler.contains("ScsiSrbPumpTimeline::new("),
        "RED: scheduler needs a stack-local exact-claim timeline");
    for stage in ["Setup", "ProviderPump", "SchedulerService",
        "ReceiveContinuation", "Completion", "Restore"] {
        assert!(scheduler.contains(stage), "RED: missing {stage} phase");
    }
    let pump = scheduler.find("crate::spawn_hosts::component_pump(channel)").unwrap();
    let continuation = scheduler.find("component_pump_continue_receive_after_scheduler_service(").unwrap();
    let complete = scheduler.find("authenticate_component_completion(channel, &result)").unwrap();
    let restore = scheduler.find("runtime::nested::restore(&mut parent)").unwrap();
    assert!(pump < continuation && continuation < complete && complete < restore);
    let authentication = SCHEDULER.split("unsafe fn authenticate_component_completion(").nth(1).unwrap();
    assert!(authentication.contains("runtime::complete_protocol(route, dispatch, reply"),
        "validated startup retains its exact protocol completion");
    assert!(authentication.contains("runtime::complete(route, dispatch, result.reply_cap"),
        "ordinary completion retains its original Reply");
}
