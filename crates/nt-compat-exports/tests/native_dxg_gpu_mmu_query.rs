//! The native reverse DDI must preserve the released fixed GPU MMU query output.

const BRIDGE: &str = include_str!("../../../components/ntos-executive/src/hosted_dxg_registration.rs");

#[test]
fn fixed_gpu_mmu_queries_reach_the_owned_callback_and_guarded_copyout() {
    let start = BRIDGE.find("pub(super) unsafe fn service_query_adapter_info_callback(")
        .expect("registered QueryAdapterInfo reverse callback");
    let end = BRIDGE[start..].find("pub(super) unsafe fn service_standard_allocation_callback(")
        .expect("QueryAdapterInfo callback boundary") + start;
    let body = &BRIDGE[start..end];

    let fixed = body.find("DxgFixedQueryLayout::parse(")
        .expect("kind 13/14 fixed POD admission before provider entry");
    let guard = body.find("DxgQueryOutputGuard::capture(")
        .expect("exact output allocation guard");
    let enter = body.find("dispatch_dependent_provider_callback(")
        .expect("registered released miniport callback");
    let copyout = body.find(".write_bytes(record.provider_instance, provider_inst,")
        .expect("guarded output copyback");
    assert!(fixed < enter && guard < enter && enter < copyout);
    assert!(body.contains("dxg_query_output_regions_disjoint("));
    assert!(body.contains("dxg_query_restores_nested_pointer(prefix.kind())"),
        "fixed POD output must bypass segment pointer restoration");
    assert!(!body.contains("return Ok(STATUS_SUCCESS)"),
        "GPU MMU capabilities must come from the released provider");
}
