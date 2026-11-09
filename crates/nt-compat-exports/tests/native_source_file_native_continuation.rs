//! Native File pump suspension keeps exact post-dispatch state without replaying entry.

const NATIVE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn file_native_continuation_retains_the_entered_pump_and_dispatch_owners() {
    let contract = NATIVE
        .split_once("struct FileIrpPumpContinuation {")
        .expect("move-only native File continuation")
        .1
        .split_once("impl FileIrpPumpContinuation {")
        .expect("native continuation method boundary")
        .0;
    assert!(contract.contains("HostedPumpRestore"));
    assert!(contract.contains("transfer: Option<FileTransferOwner>"));
    assert!(contract.contains("device_context: Option<FileDeviceContextOwner>"));
    assert!(NATIVE.contains("Active(ActiveHostedIrpTransferGuard)"));
    assert!(NATIVE.contains("Suspended(SuspendedActiveHostedIrpTransfer)"));
    assert!(NATIVE.contains("Active(HostedDeviceDispatchContextGuard)"));
    assert!(NATIVE.contains("Suspended(SuspendedHostedDeviceDispatchContext)"));
    assert!(contract.contains("class_selection"));
    assert!(contract.contains("dispatch_seq"));
    assert!(!contract.contains("&mut [u8]"), "borrowed output cannot survive unwind");

    let progress = NATIVE
        .split_once("enum HostedIrpDispatchProgress")
        .expect("native progress result")
        .1
        .split_once("fn dispatch_irp_for_instance_exact_suspend_aware(")
        .expect("suspend-aware File entry")
        .0;
    assert!(progress.contains("Returned(Option<HostedIrpTransportResult>)"));
    assert!(progress.contains("ChildWorkYield(FileIrpPumpContinuation)"));

    let body = NATIVE
        .split_once("unsafe fn dispatch_irp_for_instance_exact_inner(")
        .expect("shared native dispatch implementation")
        .1
        .split_once("/// Allocate the canonical File")
        .expect("native File dispatch boundary")
        .0;
    assert!(body.contains("hosted_component_pump_with_caller_child_work"));
    assert!(body.contains("HostedPumpRestore::ChildWorkReady"));
    assert!(body.contains("FileIrpPumpContinuation {"));
    assert!(body.contains("yielded.expect("));
    assert!(body.contains("return None;"));
}

#[test]
fn entered_resume_never_reports_a_synthetic_no_entry_result() {
    let resume_progress = NATIVE
        .split_once("enum FileIrpResumeProgress {")
        .expect("separate entered-resume progress")
        .1
        .split_once("unsafe fn dispatch_irp_for_instance_exact(")
        .expect("native dispatch entry")
        .0;
    assert!(resume_progress.contains("Completed(HostedIrpTransportResult)"));
    assert!(resume_progress.contains("ChildWorkYield(FileIrpPumpContinuation)"));
    assert!(!resume_progress
        .split_once("pub(super) enum HostedIrpDispatchProgress")
        .map_or(resume_progress, |(entered, _)| entered)
        .contains("Returned(Option<HostedIrpTransportResult>)"));

    let resume = NATIVE
        .split_once("pub(super) unsafe fn resume_after_child(")
        .expect("native File resume")
        .1
        .split_once("pub(super) enum HostedIrpDispatchProgress")
        .expect("native progress boundary")
        .0;
    assert!(resume.contains("FileIrpResumeProgress::Completed"));
    assert!(!resume.contains("Returned(self.finish(out))"));
}

#[test]
fn existing_dispatch_entry_cannot_admit_a_child_work_yield() {
    let entry = NATIVE
        .split_once("unsafe fn dispatch_irp_for_instance_exact(")
        .expect("legacy dispatch entry")
        .1
        .split_once("fn dispatch_irp_for_instance_exact_suspend_aware(")
        .expect("separate File-only entry")
        .0;
    assert!(entry.contains("None"), "legacy call must withhold the yield permit");
    assert!(!entry.contains("ChildWorkYield"), "legacy caller cannot consume a yield");
}
