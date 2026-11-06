//! Native shared ingress must retain one physical arrival across recoverable query failures.
//! These source guards complement the pure IngressReceiver ownership tests: native seL4 receive
//! cannot be driven from a host test, so the adapter must expose its failure phase explicitly.

const RUNTIME: &str =
    include_str!("../../../components/ntos-executive/src/component_ingress_runtime.rs");
const SHARED: &str =
    include_str!("../../../components/ntos-executive/src/component_shared_ingress.rs");

fn native_receive() -> &'static str {
    RUNTIME
        .split_once("pub(crate) unsafe fn receive(\n")
        .expect("native shared ingress receive")
        .1
        .split_once("pub(crate) unsafe fn ready_worker(")
        .expect("native receive boundary")
        .0
}

#[test]
fn capture_refusal_keeps_the_returned_message_and_original_reply() {
    assert!(SHARED.contains("ReceiveError::Capture(error, message, sequence)"),
        "the shared adapter returns the physical message when capture refuses");
    let receive = native_receive();
    assert!(receive.contains("ReceiveError::Capture("),
        "native ingress must handle capture refusal separately from a probe refusal");
    assert!(receive.contains("returned_message: Some(message)")
        && receive.contains("execution, probe_tcb, reply, sequence,"),
        "the full message, original execution owner, Reply and sequence need one journal");
    assert!(receive.contains("pending.reply != receiver.reply()"),
        "recovery must check the original physical Reply before touching the payload");
}

#[test]
fn captured_query_refusal_reclassifies_the_same_owner_before_another_receive() {
    let receive = native_receive();
    let new_receive = receive.find(".receive(lanes, execution, probe_tcb, blocking)")
        .expect("native receive effect");
    let captured = receive.find("recovery_for_owner(lanes, execution)")
        .expect("exact captured owner recovery gate");
    assert!(captured < new_receive,
        "a captured owner must be classified before any new native receive effect");
    assert!(receive.contains("ReceiveError::Probe(")
        && receive.contains("ReceiveProbeError::Query(_)"),
        "query refusal must remain distinguishable from authority mismatch or uncertainty");
    assert!(receive.contains("super::super::classify("),
        "retry must classify the existing receiver instead of replaying its physical arrival");
}

#[test]
fn query_retry_is_bounded_and_a_quarantined_owner_blocks_new_receive() {
    let receive = native_receive();
    let recovery_gate = receive.find("if let Some(pending) = owner.pending_receive.as_ref()")
        .expect("retained arrival preflight");
    let native_effect = receive.find("match owner.receive(lanes, execution, probe_tcb, blocking)")
        .expect("one native receive effect");
    assert!(recovery_gate < native_effect);
    assert!(receive[recovery_gate..native_effect].contains("!pending.classify_retry_allowed")
        && receive[recovery_gate..native_effect].contains("return Err(Error::Receive)"),
        "a quarantined captured owner must stop before another native receive");
    assert_eq!(receive.matches("owner.receive(lanes, execution, probe_tcb, blocking)").count(), 1);
    let retry = receive.find("ReceiveProbeError::Query(_)")
        .expect("transient query refusal");
    let retry_body = &receive[retry..];
    assert!(retry_body.contains("pending.classify_retry_allowed = false")
        && retry_body.contains("receiver.recovery_for_owner(lanes, execution)")
        && retry_body.contains("Err(error) => {")
        && retry_body.contains(".classify_retry_allowed = false;"),
        "the sole read-only retry must consume its permit and retain a second refusal");
}

#[test]
fn completed_hosted_replies_recycle_before_mutable_ingress_borrows() {
    let receive = native_receive();
    let snapshot = receive.find("let fresh_before_recycle =")
        .expect("short read-only journal projection");
    let recycle = receive.find("hosted::recycle_completed()?")
        .expect("completed hosted Reply transfer");
    let owner = receive.find("let owner = owner();")
        .expect("mutable ingress owner borrow");
    let lanes = receive.find("let lanes = lanes();")
        .expect("mutable lane table borrow");
    assert!(snapshot < recycle && recycle < owner && recycle < lanes,
        "recycling itself borrows both native owners and must finish before their outer borrows");
    assert!(receive[owner..].contains("if let Some(pending) = owner.pending_receive.as_ref()"),
        "a nested effect during recycling requires a fresh journal check");
}
