//! Native op14 routing must use the exact adapter's root DMA authority.

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SCSI: &str = include_str!("../../../components/ntos-executive/src/hosted_scsi_dma_reservation.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source.find(start).expect("start marker");
    let tail = &source[from..];
    &tail[..tail.find(end).expect("end marker")]
}

#[test]
fn both_native_allocators_send_the_exact_adapter_to_op14() {
    let query = section(DRIVER, "unsafe fn dma_root_conflict_next(",
        "struct HostedDmaAdapterMetadata");
    assert!(query.contains("adapter: u64"));
    assert!(query.contains("HOSTED_DMA_SERVICE_CHECK_CONFLICT"));
    assert!(query.contains("        adapter,"),
        "the root service object must identify the caller's exact adapter");

    let common = section(DRIVER, "extern \"win64\" fn s_dma_allocate_common_buffer(",
        "extern \"win64\" fn s_dma_free_common_buffer(");
    assert!(common.contains("dma_root_conflict_next(adapter, candidate_logical, requested)"));
    assert!(common.contains("HOSTED_DMA_CONFLICT_RETRY_LIMIT"));
    assert!(common.contains("NtStatus::CONFLICTING_ADDRESSES.raw()"));

    let transfer = section(DRIVER, "extern \"win64\" fn s_dma_map_transfer(",
        "extern \"win64\" fn s_dma_flush_adapter_buffers(");
    assert!(transfer.contains("dma_root_conflict_next(adapter, candidate_logical, mapped_len)"));
    assert!(transfer.contains("HOSTED_DMA_CONFLICT_RETRY_LIMIT"));
    assert!(transfer.contains("NtStatus::CONFLICTING_ADDRESSES.raw()"));
}

#[test]
fn root_op14_authenticates_lease_and_queries_canonical_manager() {
    let service = section(DRIVER, "pub(crate) fn service_hosted_driver_dma_adapter(",
        "if operation == HOSTED_DMA_SERVICE_RELEASE_ADAPTER {");
    assert!(service.contains("if operation == HOSTED_DMA_SERVICE_CHECK_CONFLICT {"));
    assert!(service.contains("lease.adapter_address == Some(pdo_object)"));
    assert!(service.contains("lease.consumer_domain == domain"));
    assert!(service.contains("hosted_dma_pdo_generation_is_live("));
    assert!(service.contains("conflicting_logical_end("),
        "the manager, not the global SCSI reservation vector, owns overlap authority");
    assert!(service.contains("lease.owner, lease.adapter_id, words[1], words[2]"));
    assert!(!service.contains("hosted_scsi_dma_reservation::overlaps("));
}

#[test]
fn scsi_controller_requires_a_provisioned_adapter_pair() {
    let selector = section(SCSI, "unsafe fn controller_for_scsi_child(",
        "pub(super) unsafe fn reserve_scsi_dma_data(");
    assert!(selector.contains("lease.adapter_address.is_some()"),
        "an unpublished adapter request cannot authorize a coherent reservation");
}
