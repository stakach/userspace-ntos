//! Partition layout reads must expose which exact DEVICE_OBJECT reference gate refused them.

const LOCAL: &str = include_str!("../../../components/ntos-executive/src/hosted_driver_object_reference.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn partition_device_reference_refusal_reports_local_and_root_identity_gates() {
    let local = LOCAL.split_once("pub(super) extern \"win64\" fn ob_reference_object_by_pointer(")
        .expect("local reference adapter").1;
    assert!(local.contains("trace_local_refusal(b\"pool"));
    assert!(local.contains("trace_local_refusal(b\"type-marker"));
    assert!(LOCAL.contains("[device-reference-local]"));

    let root = ROOT.split_once("if op == HOSTED_DEVICE_OP_REFERENCE_BY_POINTER {")
        .expect("root reference service").1
        .split_once("if op == HOSTED_DEVICE_OP_REFERENCE_POINTER")
        .expect("service boundary").0;
    let root_tokens: String = root.split_whitespace().collect();
    assert!(root_tokens.contains("trace_root_rejection(b\"authentication"));
    assert!(root_tokens.contains("trace_root_rejection(b\"registration"));
    assert!(root_tokens.contains("trace_root_rejection(b\"reference"));
    assert!(LOCAL.contains("[device-reference-root]"));
}
