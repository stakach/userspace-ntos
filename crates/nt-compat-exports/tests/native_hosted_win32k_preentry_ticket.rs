//! The pre-entry witness must come from the exact retained hosted Call and bound Reply.

const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

fn body(name: &str) -> &str {
    let start = HOSTED.find(name).expect("native pre-entry boundary exists");
    let end = HOSTED[start..].find("\n}").expect("native boundary closes") + start;
    &HOSTED[start..end]
}

#[test]
fn witness_checks_original_call_and_physical_reply() {
    let exact = body("unsafe fn exact_delivered_win32k_preentry(");
    for required in [
        "REPLY_MAIN_SLOT.load", "row.delivered", "row.completion.is_some()",
        "row.released", "row.receive_settlement.is_some()", "row.root_ingress.is_some()",
        "call.can_park()", "call.message().badge()", "call.message().info()",
        "call.message().word(0) != Some(service_number)", "is_win32k_native_call",
        "call.admission_key()", "hosted_ingress_binding",
        "query_component_reply_binding", "ReplyBindingObservation::BoundToTarget",
    ] {
        assert!(exact.contains(required), "pre-entry witness missing {required}");
    }
}

#[test]
fn witness_is_not_copyable_and_rechecks_same_admission() {
    let ticket = body("pub(crate) struct HostedWin32kPreentryTicket {");
    assert!(ticket.contains("ExternalAdmissionKey"));
    assert!(!HOSTED[..HOSTED.find("pub(crate) struct HostedWin32kPreentryTicket {").unwrap()]
        .lines().last().unwrap_or_default().contains("Clone, Copy"));
    let mint = body("pub(crate) unsafe fn mint_hosted_win32k_preentry_ticket(");
    let revalidate = body("pub(crate) unsafe fn revalidate_hosted_win32k_preentry_ticket(");
    assert!(mint.contains("exact_delivered_win32k_preentry("));
    assert!(revalidate.contains("exact_delivered_win32k_preentry("));
    assert!(revalidate.contains("ticket.admission"));
}

#[test]
fn busy_deferral_requires_a_present_first_message_word() {
    let defer = body("unsafe fn defer_hosted_delivery_inner(");
    assert!(defer.contains("call.message().word(0)"),
        "a zero-word Call must not be classified from stale MR0");
    assert!(!defer.contains("call.message().registers()[0]"),
        "the busy classifier must use the received message length");
}
