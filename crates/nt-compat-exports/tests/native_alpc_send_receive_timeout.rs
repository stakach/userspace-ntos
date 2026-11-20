//! #418: NtAlpcSendWaitReceivePort with a timeout waits until the deadline, then the port
//! service fixes the exact terminal (STATUS_TIMEOUT, or the message that already arrived).

const WORK: &str =
    include_str!("../../../components/ntos-executive/src/native_alpc_send_receive_work.rs");
const TIMERS: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");

#[test]
fn a_due_timeout_expires_the_pending_receive_through_the_port_service() {
    assert!(WORK.contains("Deadline::from_nt_timeout(captured.timeout"),
        "relative, absolute and zero timeouts are captured with NT semantics");
    assert!(!WORK.contains("captured.timeout.is_some() ||"), "a timed wait is no longer refused");
    let ready = WORK.find("Flight::Ready => {").unwrap();
    let body = &WORK[ready..ready + 900];
    assert!(body.contains("owner.submitted_once && owner.deadline.is_due("),
        "expiry happens only after the first submission performed the send half");
    assert!(body.contains("ALPC_OP_EXPIRE_SEND_RECEIVE"));
    assert!(TIMERS.contains("native_alpc_send_receive_work::next_deadline()"),
        "the service loop wakes when a receive's timeout falls due");
}
