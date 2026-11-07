//! A retained PM thread is not enough authority after its hosted runtime layout retires.

const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

#[test]
fn hosted_ingress_checks_exact_runtime_attachment_before_mirror_selection() {
    let admission = HANDLER
        .split_once("pub(crate) fn admit_hosted_thread_ingress(")
        .expect("hosted ingress admission")
        .1
        .split_once("pub(crate) fn capture_provider_logical_caller(")
        .expect("admission boundary")
        .0;
    let attachment = admission
        .find("hosted_runtime_attachment_matches")
        .expect("hosted process runtime attachment must be checked");
    let admitted = admission
        .find("self.thread_runtime.admit_ingress(")
        .expect("thread-slot ingress admission");
    assert!(attachment < admitted, "retired layout cannot enter a native dispatch");

    // Rejection owns the received Call, so it must cancel through the exact shared-ingress Reply
    // path before another Receive; a stale runtime cannot turn into a synthetic syscall success.
    let rejection = SERVICE
        .split_once("macro_rules! reject_hosted_ingress")
        .expect("hosted ingress rejection")
        .1
        .split_once("// The previous iteration's event locals")
        .expect("rejection boundary")
        .0;
    assert!(rejection.contains("drop_current_hosted_reply()"));
}

#[test]
fn retired_runtime_cancellation_uses_retained_physical_call_not_live_admission() {
    let resume_stopped = HOSTED
        .split_once("pub(crate) unsafe fn hosted_can_resume(")
        .expect("hosted resume fence")
        .1
        .split_once("let cancelled =")
        .expect("stopped-call fence boundary")
        .0;
    let stop = HOSTED
        .split_once("unsafe fn stop_retained_hosted_call(")
        .expect("retained physical Call Stop")
        .1
        .split_once("pub(crate) unsafe fn stop_hosted_caller(")
        .expect("Stop boundary")
        .0;
    let cancel = HOSTED
        .split_once("pub(crate) unsafe fn stop_and_cancel_hosted(")
        .expect("retained hosted cancellation")
        .1
        .split_once("pub(crate) unsafe fn cancel_hosted(")
        .expect("cancellation boundary")
        .0;
    for source in [resume_stopped, stop, cancel] {
        assert!(!source.contains("hosted_ingress_binding("),
            "retiring the semantic runtime cannot un-fence or revoke its retained Call");
    }
    assert!(stop.contains("query_component_reply_binding("),
        "physical Stop must prove the retained Reply still binds the exact TCB");
    let rejection = SERVICE
        .split_once("macro_rules! reject_hosted_ingress")
        .expect("hosted ingress rejection")
        .1
        .split_once("// The previous iteration's event locals")
        .expect("rejection boundary")
        .0;
    assert!(!rejection.contains("assert!(drop_current_hosted_reply()"),
        "an uncertain or refused cancellation must retain the Call without panicking");
}

#[test]
fn acknowledged_hosted_stop_does_not_require_its_old_reply_binding() {
    let stop = HOSTED
        .split_once("unsafe fn stop_retained_hosted_call(")
        .expect("retained physical Call Stop")
        .1
        .split_once("pub(crate) unsafe fn stop_hosted_caller(")
        .expect("Stop boundary")
        .0;
    let identity = stop.find("admission.admission_sequence() == 0")
        .expect("the exact admission key is checked before accepting a Stop ACK");
    let stopped = stop.find("if call.is_stopped()")
        .expect("an acknowledged Stop must be reusable after the kernel unlinks its Reply");
    let query = stop.find("query_component_reply_binding(tcb, reply)")
        .expect("a new Stop still requires the exact physical Reply binding");
    assert!(identity < stopped && stopped < query);
    assert!(stop[stopped..query].contains("return Ok(())"),
        "the acknowledged Stop must not be sent to the microkernel again");
    let cancel = HOSTED
        .split_once("pub(crate) unsafe fn cancel_hosted(")
        .expect("retained hosted cancellation")
        .1
        .split_once("pub(crate) unsafe fn hosted_reply_cancelled(")
        .expect("cancellation boundary")
        .0;
    assert!(cancel.contains("finish_cancelled_external"),
        "retirement still needs a fresh Free observation of the exact Reply");
}
