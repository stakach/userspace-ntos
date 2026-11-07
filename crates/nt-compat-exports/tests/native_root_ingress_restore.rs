//! The native parent must retain a root ingress permit through physical restoration.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/component_ingress_nested.rs");

fn function(name: &str) -> &'static str {
    let start = SOURCE.find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("missing native {name}"));
    let tail = &SOURCE[start..];
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
    panic!("unclosed native {name}")
}

#[test]
fn exact_root_child_receipt_survives_until_physical_parent_restore() {
    let begin = function("begin_root_ingress_restore");
    assert!(begin.contains("pass.begin_restore(scope)")
        && begin.contains("parent.root_ingress_restore = Some(permit)"),
        "the child pass must seal its permit in the physical parent row");
    assert!(begin.find("parent.root_ingress_restore = Some(permit)").unwrap()
        < begin.find("lanes().begin_root_ingress_restore").unwrap()
        && begin.find("lanes().begin_root_ingress_restore").unwrap()
            < begin.find("parent.root_lane_begun = true").unwrap(),
        "lane admission must follow durable permit storage and precede its positive marker");
    let stages = function("restore_stages");
    let canonical = stages.find("resume_nested_execution").unwrap();
    let projection = stages.find("restore_projection").unwrap();
    let release = stages.find("physical.release()").unwrap();
    let finish = stages.find("projection_restored").unwrap();
    let receipt = stages.find("root_ingress_restore.take()").unwrap();
    assert!(canonical < projection && projection < release && release < finish && finish < receipt,
        "the child permit must leave PARENTS only after all physical restore stages");
    let root = function("restore_root_ingress");
    assert!(root.find("restore_stages").unwrap() < root.find("acknowledge_restore").unwrap(),
        "the positive restored receipt must follow the physical stage result");
    let ordinary = function("mark_restore_pending");
    assert!(ordinary.contains("ParentChild::RootIngress"),
        "ordinary restore must not consume a root ingress permit");
    let root_mark = function("mark_root_restore_pending");
    assert!(root_mark.contains("parent.root_ingress_restore.is_none()")
        && root_mark.contains("parent.root_lane_begun"),
        "root restore entry requires both retained permit and admitted lane checkpoint");
    let ordinary_ticket = function("pending_ticket");
    let root_ticket = function("pending_root_ticket");
    assert!(ordinary_ticket.contains("parent.child != Some(ParentChild::RootIngress)")
        && root_ticket.contains("parent.child == Some(ParentChild::RootIngress)")
        && root_ticket.contains("ticket_matches(ticket, parent)")
        && root_ticket.contains("ParentPhase::RestorePending")
        && root_ticket.contains("restore_refusal_is_retryable(parent)"),
        "root and ordinary retained tickets must be disjoint and authenticate the exact row");
    let redrive = function("restore_pending_root_ticket");
    assert!(redrive.contains("pending_root_ticket(ticket)")
        && redrive.contains("restore_root_ingress(&mut handle)"),
        "root redrive must return the typed child receipt through exact retained authority");
}
