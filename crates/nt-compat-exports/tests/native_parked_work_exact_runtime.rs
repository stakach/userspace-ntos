//! Parked File and LPC work resumes only against its exact live caller (#327).
//!
//! A process index is reused across process generations. Resumed work must check the caller it
//! recorded at park time before taking a broker effect or writing caller memory.

const SEC: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

fn body(start: &str, end: &str) -> &'static str {
    SEC.split_once(start).unwrap().1.split_once(end).unwrap().0
}

#[test]
fn lpc_receive_checks_the_parked_receiver_before_dequeuing_a_message() {
    let redrive = body("unsafe fn lpc_receive_wait_redrive_all(", "pub(crate) unsafe fn lpc_endpoint_redrive_all(");
    let identity = redrive.find("== Some(continuation.process)").unwrap();
    let dequeue = redrive.find("reply_wait_receive(").unwrap();
    assert!(identity < dequeue, "a retired receiver must not consume a port message");
    assert!(redrive.contains("let receive = if mirror.is_none() {"));
}

#[test]
fn lpc_connect_completion_publishes_only_to_the_exact_connector() {
    let complete = body("unsafe fn lpc_connect_wait_complete(", "print_str(b\"[lpc-connect-wait] WAKE pi=\");");
    let identity = complete.find("== Some(continuation.process)").unwrap();
    let publish = complete.find("lpc_publish_connect_completion(").unwrap();
    assert!(identity < publish);
    let park = body("unsafe fn lpc_connect_wait_park(", "unsafe fn ");
    assert!(park.contains("process: nt_user_host::process_identity::ProcessIdentity"));
}

#[test]
fn pending_file_terminal_delivery_validates_the_recorded_caller() {
    let redrive = body("unsafe fn pending_file_io_redrive_pass(", "let mut delivery_state = pending.delivery_state;");
    let exact = redrive.rfind("crate::pending_file_caller::caller(identity, pending)").unwrap();
    let validate = redrive.rfind("validate_provider_logical_caller(caller)").unwrap();
    let mirror = redrive.rfind("mirror_ctx_for(nt_handler, pending.badge").unwrap();
    assert!(exact < validate && validate < mirror);
}
