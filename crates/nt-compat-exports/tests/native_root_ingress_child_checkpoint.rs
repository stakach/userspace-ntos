//! A selected root child keeps its Reply and settlement under exact ownership.

const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");
const PARK: &str = include_str!("../../../components/ntos-executive/src/root_reply_park.rs");

fn function(name: &str) -> &'static str {
    let start = HOSTED.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("missing {name}"));
    let tail = &HOSTED[start..];
    let open = tail.find('{').unwrap();
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes().iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { return &tail[..=offset]; } }
            _ => {}
        }
    }
    panic!("unclosed {name}")
}

#[test]
fn selected_park_refusal_receipt_requires_a_pre_effect_proof() {
    let selected = PARK.split_once("fn try_commit_selected(").map(|(_, body)| body).unwrap_or("");
    let mismatch = selected.find("if self.active != attempt.reply()").unwrap();
    let commit = selected.find("self.try_commit()").unwrap();
    assert!(mismatch < commit
        && selected.contains("return Err(SelectedParkRefusal::NoEffect(")
        && !selected.contains("SelectedParkRefusal::WrongReply")
        && selected.contains("Err(_park) => Err(SelectedParkRefusal::NoEffect(")
        && selected.contains("attempt.after_no_effect_native_refusal()")
        && selected.contains("Ok(()) => Ok(attempt.after_positive_native_park())"),
        "the selected wrapper may certify a mismatch only before entry, or exact try_commit Err");
}

#[test]
fn selected_reply_park_is_sealed_before_effect_and_acknowledged_only_after_positive_commit() {
    let begin = function("begin_root_ingress_reply_park");
    assert!(begin.contains("call.admission_key() != admission")
        && begin.contains("parent.identity() != parent_identity")
        && begin.contains("root_ingress_parent_is_held")
        && begin.contains("ReplyBindingObservation::BoundToTarget")
        && begin.contains("REPLY_MAIN_SLOT.load(Ordering::Relaxed) != call.reply()")
        && begin.contains("root.pass.begin_park"));
    let positive = function("acknowledge_root_ingress_reply_park");
    assert!(positive.contains("call.admission_key() != admission")
        && positive.contains("parent.identity() != parent_identity")
        && positive.contains("root_ingress_parent_is_held")
        && positive.contains("root.pass.acknowledge_park"));
}

#[test]
fn acknowledged_child_settlement_is_retained_by_root_pass_or_exact_future_owner() {
    let finish = function("finish_acknowledged");
    assert!(finish.contains("settle_root_ingress(row, settlement)"),
        "Free receipt must reach the root owner, not disappear through the Receive-only path");
    let settle = function("settle_root_ingress");
    assert!(settle.contains("root.pass.acknowledge_settlement")
        && settle.contains("root.unconsumed_settlement = Some(settlement)"),
        "a rejected or post-restore settlement must remain owned by the exact child");
    let take = function("take_root_ingress_settlement");
    assert!(take.contains("root.pass.admission_key() == admission")
        && take.contains("root.unconsumed_settlement.take()"));
}
