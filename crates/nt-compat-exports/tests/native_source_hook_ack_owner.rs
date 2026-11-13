//! A pending Hook ACK must use its exact retained File owner, never a raw backend fallback.

#[test]
fn pending_hook_source_ack_requires_its_retained_file_owner() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_input_hook_dispatch.rs");
    let ack = source.split_once("pub(super) unsafe fn retire_after_source_completion(")
        .expect("Hook source ACK boundary").1
        .split_once("unsafe fn validate_source(")
        .expect("Hook source ACK end").0;
    assert!(ack.contains("hosted_file_owners::contains(irp_id)"));
    assert!(ack.contains("hosted_file_owners::acknowledge(irp_id)"));
    assert!(!ack.contains("acknowledge_completed_irp_strict("),
        "a missing File owner cannot authorize a direct backend ACK replay");
}
