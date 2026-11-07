//! A late Storport failure must identify its native DMA stage even after normal boot tracing ends.

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const GRAPH: &str =
    include_str!("../../../components/ntos-executive/src/hosted_dma_private_graph.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source.find(start).expect("start marker");
    let tail = &source[from..];
    &tail[..tail.find(end).expect("end marker")]
}

#[test]
fn dma_failures_have_a_separate_bounded_trace_budget() {
    let trace = section(
        DRIVER,
        "unsafe fn trace_hosted_dma_sg(",
        "unsafe fn dma_copy_bytes(",
    );
    assert!(trace.contains("HOSTED_DMA_SG_FAILURE_TRACE_COUNT"));
    assert!(trace.contains("HOSTED_DMA_SG_FAILURE_TRACE_CAP"));
    assert!(trace.contains("status == STATUS_SUCCESS"));

    let private = section(
        DRIVER,
        "unsafe fn dma_allocate_private_graph(",
        "unsafe fn dma_retire_map_token(",
    );
    assert!(private.contains("b\"private-graph-rejected\""));
    assert!(private.contains("status as u32 as i32"));

    let graph = section(GRAPH, "unsafe fn allocate_member(", "/// A request nonce");
    assert!(
        graph.contains("trace_hosted_dma_private_pool_failure"),
        "root-side private graph allocation must identify its component pool failure"
    );
}

#[test]
fn transfer_failures_keep_the_rejected_stage_and_root_status() {
    let conflict = section(
        DRIVER,
        "unsafe fn dma_root_conflict_next(",
        "struct HostedDmaAdapterMetadata",
    );
    assert!(conflict.contains("Result<Option<u64>, i32>"));
    assert!(conflict.contains("Err(status as u32 as i32)"));

    let transfer = section(
        DRIVER,
        "extern \"win64\" fn s_dma_map_transfer(",
        "unsafe fn dma_find_map_record(",
    );
    for reason in [
        "probe-source-failed",
        "root-conflict-failed",
        "root-map-failed",
        "coherent-map-failed",
    ] {
        assert!(transfer.contains(reason), "missing {reason} failure trace");
    }
    assert!(transfer.contains("mapped_status as u32 as i32"));
    assert!(transfer.contains("Err(status) =>"));

    let get = section(
        DRIVER,
        "extern \"win64\" fn s_dma_get_scatter_gather_list(",
        "extern \"win64\" fn s_dma_calculate_scatter_gather_list(",
    );
    assert!(get.contains("b\"list-alloc-failed\""));
    assert!(get.contains("b\"prepare-failed\""));
}
