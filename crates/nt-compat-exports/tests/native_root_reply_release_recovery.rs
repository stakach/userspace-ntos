//! A process exit may leave a received Call's physical Reply unresolved.
//! Root receive must preserve that Reply and continue only with a fresh offered cap.

const INGRESS: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn refused_hosted_release_quarantines_the_exact_reply_before_receive() {
    let receive = INGRESS
        .split_once("pub(crate) unsafe fn receive(reply_cptr: u64)")
        .expect("root receive")
        .1
        .split_once("pub(crate) unsafe fn reply_receive(")
        .expect("root receive boundary")
        .0;
    assert!(!receive.contains("release_hosted_reply(reply_cptr).expect("));
    assert!(receive.contains("quarantine_current_hosted_reply()"));
    assert!(receive.contains("RetainedFailure"));
}

#[test]
fn refusal_exits_the_service_loop_without_reusing_the_owned_reply() {
    let outcome = SERVICE
        .split_once("macro_rules! component_receive_outcome")
        .expect("service receive outcome")
        .1
        .split_once("macro_rules! component_recv")
        .expect("receive outcome boundary")
        .0;
    assert!(outcome.contains("ReceiveOutcome::RetainedFailure"));
    assert!(outcome.contains("break 'service_loop"));
}

#[test]
fn uncertain_root_reply_keeps_its_owner_and_skips_receive() {
    let reply_receive = INGRESS
        .split_once("pub(crate) unsafe fn reply_receive(")
        .expect("root reply and receive")
        .1;
    assert!(!reply_receive.contains("assert!(\n        client_reply_on("),
        "a refused or uncertain Reply is a recoverable retained outcome");
    assert!(reply_receive.contains("if !client_reply_on(")
        && reply_receive.contains("return ReceiveOutcome::RetainedFailure"),
        "the original Reply must remain owned without admitting another Call");
}

#[test]
fn receive_failure_retains_incomplete_ingress_without_panicking() {
    let receive = INGRESS
        .split_once("pub(crate) unsafe fn receive(reply_cptr: u64)")
        .expect("root receive")
        .1
        .split_once("pub(crate) unsafe fn reply_receive(")
        .expect("root receive boundary")
        .0;
    assert!(!receive.contains("panic!(\"unified executive ingress retained after receive failure\")"));
    assert!(receive.contains("return ReceiveOutcome::RetainedFailure"),
        "an unclassified or unretained Call must stay owned at the service boundary");
}
