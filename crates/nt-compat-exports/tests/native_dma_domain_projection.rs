//! Native wiring guards for domain-local DMA records and uncertain export output.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn body(start: &str, end: &str) -> &'static str {
    let from = SOURCE.find(start).expect("start marker");
    let tail = &SOURCE[from..];
    let to = tail.find(end).expect("end marker");
    &tail[..to]
}

#[test]
fn native_dma_records_remain_in_their_own_domain() {
    assert!(!SOURCE.contains("copy_provider_dma_allocation_records"));
    assert_eq!(SOURCE.matches("clear_dma_allocation_records(").count(), 2,
        "only the definition and launch initialization may clear an entire arena");

    assert!(!SOURCE.contains("copy_provider_dma_grant_fields"),
        "a mutable dependent slot must not overwrite the canonical projected grant");
    let projection = body("unsafe fn project_provider_resource_state(",
        "fn provider_export_result_success(");
    assert!(projection.contains("write_hosted_resource_state_projection(provider_shared, state, false)"));
    assert!(projection.contains("project_provider_dma_state(binding, dependent_shared, provider_shared)"));
    let dma = body("unsafe fn project_provider_dma_state(",
        "unsafe fn project_provider_resource_state(");
    for transient in ["SH_DMA_ALLOCATED_VA", "SH_DMA_ALLOCATED_LOGICAL", "SH_DMA_FREED_LOGICAL"] {
        assert!(dma.contains(transient), "missing reset of transient provider diagnostic: {transient}");
    }
    assert!(!dma.contains("SH_DMA_COMMON_"));
}

#[test]
fn an_uncertain_post_dispatch_dma_result_cannot_publish_stale_outputs_or_invite_replay() {
    let export = body("let mut result = match dispatch(singleton", "trace_provider_resource_list_export(");
    assert_eq!(export.matches("dispatch(singleton").count(), 1,
        "the provider export must run once");
    let uncertain = body("let dma_indeterminate = if let Err(status) = complete_provider_dma_state(",
        "complete_provider_ndis_object_shadows(");
    assert!(!uncertain.contains("result = status"),
        "a possible native effect must not become a retryable replacement status");
    assert!(uncertain.contains("register_instance_ready(dependent_index, false)"),
        "an indeterminate DMA result must fault the dependent before it can dispatch again");
    assert!(export.contains("&mut result,\n        dma_indeterminate,"));
    let resource_completion = body("if !dma_indeterminate {\n        complete_provider_resource_mapping(",
        "HOSTED_PROVIDER_EXPORT_COMPLETIONS.fetch_add(");
    assert!(resource_completion.contains("complete_provider_resource_mapping("),
        "an indeterminate native effect must not publish resource state");

    let copyout = body("unsafe fn complete_provider_export_marshal(",
        "unsafe fn complete_hosted_provider_miniport_attributes(");
    assert!(copyout.contains("if dma_indeterminate && state.dma_context.is_some()"));
    assert!(copyout.contains("provider_marshal_zero(copyout.dependent_exec_va, copyout.bytes)"));
}

#[test]
fn generic_input_buffer_dma_alias_requires_an_exact_live_common_claim() {
    let alias = body("unsafe fn dma_common_subrange_exec_va(",
        "unsafe fn component_or_dma_common_to_exec_va(");
    assert!(alias.contains("capture_provider_dma_call_context(instance, inst)"));
    assert!(alias.contains("provider_dma_call_context_live(context)"));
    assert!(alias.contains("dma_common_allocation_record_covers(context, component_va, bytes)"));

    let lookup = body("unsafe fn dma_common_allocation_record_covers(",
        "unsafe fn dma_common_subrange_exec_va(");
    assert!(lookup.contains("common_buffer_claim_covering("));
    assert!(lookup.contains("adapter_id == context.lease.adapter_id"));

    let input = body("unsafe fn provider_marshal_input_buffer_exec_va(",
        "fn provider_marshal_u32_arg(");
    assert!(input.contains("dma_common_subrange_exec_va(dependent_inst, component_va, bytes)"));
    assert!(!input.contains("hosted_dma_alias_for_component_va"));
}
