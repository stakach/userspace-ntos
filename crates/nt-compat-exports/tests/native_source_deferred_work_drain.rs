//! The outer hosted pump must revisit work queued by nested native dispatch.

#[test]
fn outer_completion_pump_drains_passive_work_before_irp_completion() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("pub(crate) fn pump_hosted_io_completions() -> usize {").unwrap();
    let end = source[start..]
        .find("\n#[inline(never)]\nfn parse_nt_path(")
        .unwrap();
    let function = &source[start..start + end];
    let drain = function
        .find("drain_hosted_work_queues_at_passive_level()")
        .expect("outer pump must revisit queued native workers");
    let pump = function.find("pump_io_manager()").unwrap();
    assert!(drain < pump, "workers may complete the pending CONNECT IRP");
}
