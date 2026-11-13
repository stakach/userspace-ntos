//! RootIngress retains the original hosted Reply by pool generation and physical binding.

const OWNER: &str = include_str!("../../../components/ntos-executive/src/root_ingress_owner.rs");
const HOSTED: &str = include_str!("../../../components/ntos-executive/src/component_ingress_hosted.rs");

#[test]
fn original_root_reply_witness_requires_hosted_call_pool_and_physical_binding() {
    assert!(HOSTED.contains("fn parkable_hosted_reply_binding("));
    let capture = OWNER.split_once("fn capture_root_reply_authority(").expect("root Reply capture").1;
    for required in ["REPLY_MAIN_SLOT.load", "wait_reply_pool_ref().find_cap",
        "RootReplySlotState::Used", "parkable_hosted_reply_binding",
        "query_component_reply_binding", "ReplyBindingObservation::BoundToTarget"] {
        assert!(capture.contains(required), "missing root Reply authority check: {required}");
    }
    assert!(OWNER.contains("fn root_reply_authority_is_live("));
    assert!(OWNER.contains("authority.identity") && OWNER.contains("authority.binding"));
}
