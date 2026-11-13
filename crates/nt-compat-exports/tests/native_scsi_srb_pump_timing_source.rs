//! Mounted SCSI dispatch timing must observe the one physical provider pump without
//! borrowing its retained File, IRP, or completion owner from a nested census.

const DISPATCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let begin = source.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let rest = &source[begin..];
    let finish = rest.find(end).unwrap_or_else(|| panic!("missing {end}"));
    &rest[..finish]
}

#[test]
fn scsi_srb_timing_brackets_the_exact_component_pump() {
    let dispatch = between(
        DISPATCH,
        "unsafe fn dispatch_irp_for_instance_exact(",
        "/// Allocate the canonical File before a hosted driver sees CREATE.",
    );
    let admitted = dispatch.find("enter_active_hosted_irp_transfer(").unwrap();
    let timing = dispatch.find("ScsiSrbPumpTiming::new(")
        .expect("RED: arm SCSI-SRB timing only for an exact admitted dispatch");
    let entered = dispatch.find("scsi_srb_pump_timing.enter_pump(")
        .expect("RED: record an atomic entry before invoking the component pump");
    let pump = dispatch.find("component_scheduler::hosted_component_pump_with_caller(&ch, caller)")
        .expect("the caller-bound physical component pump must remain in place");
    let exited = dispatch.find("scsi_srb_pump_timing.exit_pump(")
        .expect("RED: record an atomic exit immediately after the component pump");
    let release = dispatch.find("drop(transfer_guard)").unwrap();
    let ack = dispatch.find("hosted_scsi_dma_reservation::release_after_ack(canonical_irp_id)")
        .unwrap();
    assert!(admitted < timing && timing < entered && entered < pump
        && pump < exited && exited < release && release < ack,
        "timing may observe dispatch, but must not move the pump, transfer release, or strict ACK");
    assert!(dispatch.contains("nt_io_abi::IRP_DISPATCH_SCSI_SRB"),
        "the timing gate must identify canonical SCSI-SRB dispatches");
}

#[test]
fn nested_pump_census_uses_only_local_ticks_and_atomics() {
    let timing = between(DISPATCH, "struct ScsiSrbPumpTiming", "unsafe fn dispatch_irp_for_instance_exact(");
    assert!(timing.contains("AtomicU64") && timing.contains("Ordering::Relaxed"),
        "RED: SCSI-SRB entry, exit, and phase totals need atomic-only census storage");
    assert!(timing.contains("entries") && timing.contains("exits")
        && timing.matches("fetch_add(").count() >= 2,
        "RED: separately count exact component-pump entry and exit");
    assert!(timing.contains("disk_census_ticks()"),
        "RED: pre-pump, exact pump, and post-pump spans need local clock samples");
    assert!(timing.contains("impl Drop for ScsiSrbPumpTiming"),
        "RED: post-pump timing must survive every return after provider invocation");
    for phase in ["pre-pump", "component-pump", "post-pump"] {
        assert!(timing.contains(phase), "RED: missing {phase} phase observation");
    }
    assert!(!timing.contains("static mut ") && !timing.contains("&mut Pending")
        && !timing.contains("active_hosted_irp_transfer_mut(")
        && !timing.contains("hosted_file_owners::row("),
        "the nested pump can sample only atomic totals, never mutable owner state");
}
