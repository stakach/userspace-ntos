//! A completed PDO projection remains owned across a refused semantic handoff.

const SOURCE: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_continuation.rs"
);

#[test]
fn projection_terminal_is_retained_before_fallible_phase_transitions() {
    let owner = SOURCE.split_once("struct AddDeviceRetainedOwners {")
        .expect("retained AddDevice owner").1
        .split_once("static NEXT_ADD_DEVICE_CONTINUATION_EPOCH")
        .expect("owner boundary").0;
    assert!(owner.contains("projection_terminal: Option<Result<u64, nt_status::NtStatus>>"),
        "the real projection result needs an owned slot during restore refusal");

    let resumed = SOURCE.split_once("pub(crate) unsafe fn resume(mut self)")
        .expect("continuation resume").1
        .split_once("impl AddDeviceTransaction {")
        .expect("resume boundary").0;
    let projection = resumed.split_once("AddDevicePumpProgress::ProjectionCompleted(result)")
        .expect("real projection terminal").1
        .split_once("AddDevicePumpProgress::ChildWorkYield(pump)")
        .expect("projection branch boundary").0;
    let store = projection.find("owners.projection_terminal = Some(result)")
        .expect("terminal stored in move-only owner");
    let settle = projection.find("self.settle_projection()")
        .expect("terminal settlement uses retained slot");
    assert!(store < settle, "a refused phase transition must retain the real result");
    assert!(resumed.contains("owners.projection_terminal.is_some()"),
        "a retained projection terminal must be retryable without provider re-entry");
}

#[test]
fn dispatch_terminal_and_owner_bundle_survive_refused_settlement() {
    assert!(SOURCE.contains("undeposited_terminal: Option<Result<AddDeviceDispatchResult, nt_status::NtStatus>>"),
        "a real AddDevice result must survive an owner-deposit refusal");
    let resumed = SOURCE.split_once("pub(crate) unsafe fn resume(mut self)")
        .expect("continuation resume").1
        .split_once("impl AddDeviceTransaction {")
        .expect("resume boundary").0;
    let completed = resumed.split_once("AddDevicePumpProgress::Completed(result)")
        .expect("real AddDevice terminal").1
        .split_once("AddDevicePumpProgress::ProjectionCompleted(result)")
        .expect("dispatch branch boundary").0;
    assert!(completed.contains("self.undeposited_terminal = Some(result)"),
        "a refused deposit must retain the terminal in the move-only continuation");
    for method in ["unsafe fn settle_terminal(", "unsafe fn settle_projection("] {
        let body = SOURCE.split_once(method).expect("settlement method").1
            .split_once("self.retained.finish_terminal(key, ())")
            .expect("terminal owner extraction").0;
        assert!(body.contains("owners.transaction.is_some()"),
            "settlement must check the transaction exists before consuming its owner row");
    }
}
