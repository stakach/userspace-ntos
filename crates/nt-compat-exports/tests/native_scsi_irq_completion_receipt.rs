//! SCSI terminal completion may run inside the restricted hosted IRQ exchange.
//! It must consume the exact reservation receipt retained at dispatch preparation.

const SCSI: &str = include_str!("../../../components/ntos-executive/src/hosted_scsi_srb_provider.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("start marker");
    let end = source[start..].find(end).map(|offset| start + offset).expect("end marker");
    &source[start..end]
}

#[test]
fn irq_lane_scsi_completion_uses_dispatch_receipt_without_dma_service_call() {
    let projection = section(SCSI, "pub(super) struct ProviderScsiProjection {", "/// `packet`");
    assert!(projection.contains("dma_receipt"),
        "dispatch must retain the exact root reservation receipt for later IRQ completion");

    let prepare = section(SCSI, "pub(super) unsafe fn prepare(",
        "/// Copy only provider scalar/CDB state");
    assert!(prepare.contains("HOSTED_DMA_SERVICE_QUERY_SCSI_RESERVATION")
        && prepare.contains("reservation_id") && prepare.contains("grant_len")
        && prepare.contains("dma_receipt"),
        "the receipt must come from the authenticated op13 result at preparation");

    let pending = section(DRIVER, "struct PendingIrp {", "struct PendingIrpNode {");
    assert!(pending.contains("scsi_dma_receipt"),
        "the pending IRP must retain the receipt across asynchronous completion");
    let target = section(DRIVER, "struct PendingIrpCompletionTarget {",
        "struct PendingIrpCompletionClaim {");
    assert!(target.contains("scsi_dma_receipt"),
        "completion must receive the immutable pending-IRP receipt");

    let completion = section(SCSI, "pub(super) unsafe fn capture_completion(",
        "    let captured = capture_scsi_completion_in_place(");
    assert!(!completion.contains("call_on5(")
        && !completion.contains("HOSTED_DMA_SERVICE_QUERY_SCSI_RESERVATION"),
        "IRQ completion cannot issue an ordinary DMA service request");
    assert!(completion.contains("dma_receipt")
        && completion.contains("completion_source(")
        && completion.contains("data_capacity")
        && completion.contains("read_unaligned((srb + 0x18)"),
        "copyout must validate the retained receipt and SRB pointer before copying");
    let call = section(DRIVER, "let scsi_capture_valid =", "let length = if target.scsi_route");
    assert!(call.contains("target.scsi_dma_receipt"),
        "the IRQ completion call must pass the retained receipt, not rediscover it");
}
