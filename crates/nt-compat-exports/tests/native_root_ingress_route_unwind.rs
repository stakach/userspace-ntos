//! Unsupported selected routes restore their held parent before the child pass is cancelled.

const OWNER: &str = include_str!("../../../components/ntos-executive/src/root_ingress_owner.rs");

#[test]
fn route_refusal_retains_each_unwind_effect_and_positive_receipt() {
    for required in [
        "UnwindPrepared", "RestoredProof", "RestoredCancelled",
        "begin_undelivered_root_unwind", "restore_undelivered_root",
        "cancel_restored_undelivered_root_pass",
        "pending_undelivered_root_ticket", "parked_undelivered_root_ticket",
        "RestoredBeforeChildProof",
    ] {
        assert!(OWNER.contains(required), "missing durable route-unwind stage: {required}");
    }
    let begin = OWNER.find("fn begin_route_refusal_unwind(").unwrap();
    let restore = OWNER.find("fn restore_route_refusal_parent(").unwrap();
    let cancel = OWNER.find("fn cancel_route_refusal_child(").unwrap();
    assert!(begin < restore && restore < cancel);
    for forbidden in ["STATUS_SUCCESS", "STATUS_PENDING", "reply_hosted(", "drop(proof)"] {
        assert!(!OWNER[begin..].contains(forbidden), "unwind invented a result: {forbidden}");
    }
}
