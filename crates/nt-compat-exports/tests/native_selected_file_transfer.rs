//! The selected queued READ transfers its File owner before its Reply can be parked.

const HANDOFF: &str = include_str!("../../../components/ntos-executive/src/file_dispatch_handoff.rs");

#[test]
fn selected_read_handoff_retains_every_owner_on_checked_refusal() {
    let selected = HANDOFF
        .split_once("fn publish_selected_queued_read(")
        .expect("selected queued READ handoff")
        .1
        .split_once("pub(super) unsafe fn before_post_action(")
        .expect("ordinary handoff boundary")
        .0;
    let caller = selected.find("prepare_selected_publication(").expect("caller preflight");
    let commit = selected.find("park_reserved(").expect("exact File owner commit");
    let publish = selected.find("try_publish_selected(").expect("checked caller publication");
    assert!(caller < commit && commit < publish);
    assert!(selected.contains("driver_launch::queued_hosted_file_read_matches_exact("));
    let event_copy = selected.find("pending.transfer_event = nt_handler.current_file_transfer_event")
        .expect("Event lease observation before commit");
    let event_clear = selected.find("nt_handler.current_file_transfer_event = None")
        .expect("handler Event release after commit");
    assert!(event_copy < commit && commit < event_clear);
    let reply_preflight = selected.find("runtime::owns_ingress_reply(child_reply)")
        .expect("hosted Reply ownership before selected publication");
    assert!(reply_preflight < commit);
    assert!(selected.contains("Outcome::RefusedNoEffect"));
    assert!(selected.contains("Outcome::PublishedCallerRefused"));
    assert!(selected.contains("Outcome::ReadyForReplyPark"));
    assert!(!selected.contains("commit_or_panic"));
    assert!(!selected.contains("reply_park.commit()"));
}
