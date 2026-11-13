//! An undelivered root child cannot be cancelled until its exact parent is restored.

const NESTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("missing {name}"));
    let tail = &source[start..];
    let open = tail.find('{').unwrap();
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes().iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 { return &tail[..=offset]; }
            }
            _ => {}
        }
    }
    panic!("unclosed {name}")
}

#[test]
fn undelivered_parent_receipt_requires_positive_physical_restore() {
    let begin = function(NESTED, "begin_undelivered_root_unwind");
    assert!(begin.contains("parent.root_admission") && begin.contains("parent.child.is_some()")
        && begin.contains("parent.undelivered_root = token.take()"),
        "exact unbound parent must retain the sealed child token before restore");
    let stages = function(NESTED, "restore_stages");
    assert!(stages.find("projection_restored()").unwrap()
        < stages.find("parent.undelivered_root.take()").unwrap(),
        "restored proof cannot leave the parent before every physical stage completes");
    let restore = function(NESTED, "restore_undelivered_root");
    assert!(restore.find("restore_stages").unwrap() < restore.find("RestoredBeforeChildProof {").unwrap(),
        "positive proof must follow the physical restore result");
    let generic = function(NESTED, "pending_ticket");
    assert!(generic.contains("parent.root_admission.is_none()"),
        "ordinary ticket redrive must not discard undelivered-root proof");
    let root = function(NESTED, "pending_undelivered_root_ticket");
    assert!(root.contains("ticket_matches(ticket, parent)")
        && root.contains("ParentPhase::RestorePending")
        && root.contains("restore_refusal_is_retryable(parent)"),
        "typed redrive authenticates an exact retryable parent");
    let cancel = function(HOSTED, "cancel_restored_undelivered_root_pass");
    assert!(cancel.contains("snapshot.binding") && cancel.contains("snapshot.info")
        && cancel.contains("snapshot.registers") && cancel.contains("row.delivered")
        && cancel.contains("row.released") && cancel.contains("row.completion.is_some()")
        && cancel.contains("proof.admission_key()")
        && cancel.contains("root.undelivered_parent != Some(proof.parent())"),
        "cancellation requires the original untouched Call and positive exact proof");
}
