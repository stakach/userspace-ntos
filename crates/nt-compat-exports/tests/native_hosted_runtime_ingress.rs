//! A retained PM thread is not enough authority after its hosted runtime layout retires.

const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

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
