//! Native DMA service creation must stop at an exact quarantined owner.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section<'a>(start: &str, end: &str) -> &'a str {
    let from = SOURCE.find(start).expect("start marker");
    let tail = &SOURCE[from..];
    &tail[..tail.find(end).expect("end marker")]
}

#[test]
fn provision_checks_quarantine_after_lease_authentication_before_native_effect() {
    let provision = section("if operation == HOSTED_DMA_SERVICE_PROVISION_ADAPTER\n",
        "if matches!(operation,\n        HOSTED_DMA_SERVICE_ALLOC_MAP");
    let authenticated = provision.find("hosted_dma_pdo_generation_is_live(")
        .expect("exact lease generation validation");
    let quarantine = provision.find("hosted_dma_owner_is_quarantined(lease.owner)")
        .expect("quarantine gate for provisioned adapter");
    let effect = provision.find("provision_dma_adapter_pair(")
        .expect("native adapter publication");
    assert!(authenticated < quarantine && quarantine < effect);
}

#[test]
fn creation_arms_check_quarantine_before_any_manager_or_private_graph_effect() {
    let operations = section("if matches!(operation,\n        HOSTED_DMA_SERVICE_ALLOC_MAP",
        "if operation != HOSTED_DMA_SERVICE_REQUEST_ADAPTER {");
    for arm in ["HOSTED_DMA_SERVICE_REGISTER_COMMON_BUFFER =>",
        "HOSTED_DMA_SERVICE_ALLOC_MAP | HOSTED_DMA_SERVICE_ALLOC_SG_GET",
        "HOSTED_DMA_SERVICE_MAP_TRANSFER =>"] {
        assert!(operations.contains(arm), "missing creation arm: {arm}");
    }
    let authenticated = operations.find("hosted_dma_pdo_generation_is_live(")
        .expect("exact lease generation validation");
    let quarantine = operations.find("hosted_dma_owner_is_quarantined(lease.owner)")
        .expect("quarantine gate for creation arms");
    let gate_start = operations[..quarantine].rfind("if matches!(operation,")
        .expect("selective creation-only gate");
    let gate = &operations[gate_start..quarantine];
    for arm in ["HOSTED_DMA_SERVICE_REGISTER_COMMON_BUFFER",
        "HOSTED_DMA_SERVICE_ALLOC_MAP", "HOSTED_DMA_SERVICE_ALLOC_SG_GET",
        "HOSTED_DMA_SERVICE_ALLOC_SG_BUILD", "HOSTED_DMA_SERVICE_MAP_TRANSFER"] {
        assert!(gate.contains(arm), "creation gate omitted {arm}");
    }
    for cleanup in ["HOSTED_DMA_SERVICE_FREE_MAP", "HOSTED_DMA_SERVICE_PUT_SG"] {
        assert!(!gate.contains(cleanup), "quarantine must preserve {cleanup}");
    }
    let effect = operations.find("let result = match operation {")
        .expect("creation and cleanup operation dispatch");
    assert!(authenticated < quarantine && quarantine < effect);
    assert!(operations.contains("HOSTED_DMA_SERVICE_FREE_MAP | HOSTED_DMA_SERVICE_PUT_SG =>"),
        "exact cleanup must remain available after quarantine");
}

#[test]
fn free_common_buffer_remains_outside_creation_gate() {
    let service = section("pub(crate) fn service_hosted_driver_dma_adapter(",
        "if operation == HOSTED_DMA_SERVICE_PROVISION_ADAPTER\n");
    assert!(service.contains("if operation == HOSTED_DMA_SERVICE_FREE_COMMON_BUFFER {"));
    assert!(service.contains("free_hosted_dma_common_buffer_lease("));
}
