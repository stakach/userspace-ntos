//! A published process with no committed main thread can outlive CreateProcessW's failed
//! NtCreateThread. Its final process-handle close must enter normal exact retirement.

const EXECUTIVE: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

#[test]
fn final_process_handle_close_retires_an_abandoned_initial_process() {
    let close = EXECUTIVE.split("pub(crate) fn release_handle_object(").nth(1)
        .expect("common handle-release path")
        .split("pub(crate) fn close_process_handle_checked(").next().unwrap();
    let process = close.split("nt_process::HandleObject::Process(pid) => {").nth(1)
        .expect("process-handle release arm")
        .split("nt_process::HandleObject::Thread(tid)").next().unwrap();
    assert!(process.contains("try_terminate_unstarted_process(pid)"),
        "both native and checked closes must reach the abandonment decision");

    let retirement = EXECUTIVE.split("fn try_terminate_unstarted_process(").nth(1)
        .expect("one exact abandoned-process retirement owner")
        .split("pub(crate) fn try_delete_hosted_process_object(").next().unwrap();
    assert!(retirement.contains("request_unstarted_process_abandonment(pid)")
        && retirement.contains("unstarted_process_abandonment_pending(pid)"),
        "the final close must be retained separately from the later eligibility decision");
    assert!(retirement.contains("terminate_process"),
        "a published process must become signaled through normal Ps termination");
    assert!(retirement.contains("try_delete_hosted_process_object(pid)"),
        "the exact execution mechanism must enter normal deletion after termination");

    let drain = EXECUTIVE.split("fn drain_hosted_process_deletion_candidates(").nth(1)
        .expect("common exact process retirement drain");
    assert!(drain.contains("unstarted_process_abandonment_pending(pid)")
        && drain.contains("try_terminate_unstarted_process(pid)"),
        "a failed termination preflight must retain the observed final-close owner for retry");
}
