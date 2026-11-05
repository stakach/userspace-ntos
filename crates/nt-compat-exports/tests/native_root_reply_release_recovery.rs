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
