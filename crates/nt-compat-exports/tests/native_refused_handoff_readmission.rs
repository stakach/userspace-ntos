//! A refused hosted root handoff must not stop or indefinitely exclude the root. Unrelated work
//! is re-admitted only through the exact quarantine/reconciliation receipt issued by CALLS, the
//! owner of the refused Call and its Reply (issue #327).

const INGRESS: &str = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

/// Body of one `fn name(` item, by brace matching from its signature.
fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("fn {name}"));
    let open = start + source[start..].find('{').expect("function body");
    let mut depth = 0usize;
    for (offset, byte) in source[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 { return &source[start..=open + offset]; }
            }
            _ => {}
        }
    }
    panic!("unterminated fn {name}");
}

fn refusal_arm(receive: &str) -> &str {
    let take = receive.find("runtime::take_hosted_with(").expect("hosted delivery");
    let arm = take + receive[take..].find("Err(refusal) =>").expect("typed handoff refusal arm");
    let end = arm + receive[arm..].find("if let Some((_reply, message)) = delivered")
        .expect("delivery follows the refusal arm");
    &receive[arm..end]
}

#[test]
fn refused_handoff_readmits_only_through_the_exact_owner_receipt() {
    let receive = function(INGRESS, "receive");
    let arm = refusal_arm(receive);
    let readmit = arm.find("readmit_after_refused_handoff(").expect("gate the refusal");
    let resumed = arm.find("continue;").expect("a proven quarantine re-admits other work");
    let stopped = arm.find("return ReceiveOutcome::RetainedFailure").expect("no proof keeps excluding");
    assert!(readmit < resumed && readmit < stopped,
        "the receipt decides between re-admission and the retained-failure stop");
    assert!(!arm.contains("install_hosted_reply") && !arm.contains("take_hosted_with"),
        "the refused Call is never re-imported or re-selected in its refusal arm");

    let gate = function(INGRESS, "readmit_after_refused_handoff");
    let refuse = gate.find(".refuse(").expect("exclude before any proof");
    let seal = gate.find("runtime::quarantine_refused_handoff(").expect("CALLS produces the proof");
    let admit = gate.find(".readmit(").expect("the gate consumes the exact receipt");
    assert!(refuse < seal && seal < admit);
}

#[test]
fn root_receive_keeps_excluding_while_a_refusal_lacks_proof() {
    let receive = function(INGRESS, "receive");
    let gate = receive.find("admits_unrelated_work()").expect("excluded root admits nothing");
    let boundary = receive.find("runtime::take_outer_boundary()").unwrap();
    assert!(gate < boundary, "an unresolved exclusion precedes every other admission");
}

#[test]
fn take_hosted_with_classifies_the_exact_refused_row() {
    let take = function(HOSTED, "take_hosted_with");
    for refusal in ["HandoffRefusal::RetiredBinding", "HandoffRefusal::ReplyUnbound",
        "HandoffRefusal::ImportNoEffect", "HandoffRefusal::ImportUncertain"]
    {
        assert!(take.contains(refusal), "take_hosted_with must report {refusal}");
    }
    let filter = take.find(".filter_map(|(index, row)|").unwrap();
    let selected = take.find("Some((index, call))").unwrap();
    assert!(take[filter..selected].contains("row.handoff_quarantine.is_some()"),
        "a quarantined Call is never selected for delivery again");
    let oldest = function(HOSTED, "oldest_pending_snapshot");
    assert!(oldest.contains("row.handoff_quarantine.is_some()"),
        "nested root-child selection must not pick a quarantined Call");
}

#[test]
fn quarantine_is_sealed_in_calls_without_any_reply_effect() {
    let quarantine = function(HOSTED, "quarantine_refused_handoff");
    let seal = quarantine.find(".seal(").expect("pure seal over the held ExternalIngress");
    let stored = quarantine.find("row.handoff_quarantine = Some(").expect("row keeps its seal");
    assert!(seal < stored);
    assert!(quarantine.contains("receive_settlement.is_some()")
        && quarantine.contains("root_ingress.is_some()"),
        "a parent/child row is dependent and cannot be quarantined here");
    for effect in ["delivered = true", "reply_on(", "cancel_hosted", "finish_cancelled_external",
        "stop_owned(", "insert_pending(", "wait_reply_pool_clear_cap(", "REPLY_MAIN_SLOT.store("]
    {
        assert!(!quarantine.contains(effect), "quarantine must not perform {effect}");
    }
}

#[test]
fn a_readmitted_refusal_fails_its_live_native_caller_once() {
    let executive = include_str!("../../../components/ntos-executive/src/executive_ingress.rs");
    let readmit = executive.split_once("unsafe fn readmit_after_refused_handoff(").unwrap().1
        .split_once("\n}\n").unwrap().0;
    let gate = readmit.find("gate.readmit(receipt)").unwrap();
    let fail = readmit.find("runtime::fail_quarantined_native_call(key)").unwrap();
    assert!(gate < fail, "the caller is answered only after the quarantine proof re-admits");
    let hosted = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
    let answer = hosted.split_once("pub(crate) unsafe fn fail_quarantined_native_call(").unwrap().1
        .split_once("\n}\n").unwrap().0;
    let status = answer.find("seal.failure_status()").unwrap();
    let live = answer.find("hosted_ingress_binding(row.binding.badge) != Some(row.binding)").unwrap();
    let reply = answer.find("reply_owned(").unwrap();
    let unseal = answer.find("row.handoff_quarantine = None").unwrap();
    assert!(status < live && live < reply && reply < unseal);
    assert!(answer.contains("NT_NATIVE_SYSCALL_LABEL"), "only a system service is answered with a status");
    assert!(answer[reply..unseal].contains("return Err(Error::Reply)"),
        "an indeterminate send keeps the seal");
}
