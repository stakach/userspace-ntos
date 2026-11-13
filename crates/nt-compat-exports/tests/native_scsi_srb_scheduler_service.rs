#[path = "../../../components/ntos-executive/src/scsi_srb_scheduler_service.rs"]
mod scsi_srb_scheduler_service;
#[path = "../../../components/ntos-executive/src/scsi_srb_pump_owner.rs"]
mod scsi_srb_pump_owner;

use scsi_srb_scheduler_service::{SchedulerServiceClock, SchedulerServicePhase};
use scsi_srb_pump_owner::{ScsiSrbPumpOwnerIdentity, ScsiSrbPumpOwners};

#[test]
fn one_pass_has_nonoverlapping_wrapping_phase_spans() {
    use SchedulerServicePhase::*;
    let mut clock = SchedulerServiceClock::new(100);
    clock.transition(TimerWork, 110);
    clock.transition(IrqDrain, 120);
    clock.transition(DpcDrain, 125);
    clock.transition(ReceivePrepare, 129);
    clock.transition(ParentRestore, 140);
    let sample = clock.finish(150, 2, 3, 4);
    assert_eq!(sample.ticks(ParentPreserve), 10);
    assert_eq!(sample.ticks(TimerWork), 10);
    assert_eq!(sample.ticks(IrqDrain), 5);
    assert_eq!(sample.ticks(DpcDrain), 4);
    assert_eq!(sample.ticks(ReceivePrepare), 11);
    assert_eq!(sample.ticks(ParentRestore), 10);
    assert_eq!(sample.total_ticks(), 50);
    assert!(!sample.is_empty());

    let mut wrap = SchedulerServiceClock::new(u64::MAX - 2);
    wrap.transition(TimerWork, 1);
    let wrap = wrap.finish(5, 0, 0, 0);
    assert_eq!(wrap.ticks(ParentPreserve), 4);
    assert_eq!(wrap.ticks(TimerWork), 4);
    assert!(wrap.is_empty());
    assert_eq!(wrap.total_ticks(), 8);
}

fn owner(sequence: u64) -> ScsiSrbPumpOwnerIdentity {
    ScsiSrbPumpOwnerIdentity {
        sequence, irp_id: sequence << 32 | 0x41, device_id: sequence << 32 | 0x52,
        instance: sequence + 1, reply_cap: sequence + 2, tcb: sequence + 3,
        caller_tid: sequence + 4, caller_generation: sequence + 5,
        route_badge: sequence + 6, route_endpoint: sequence + 7,
        entered_ticks: sequence + 8,
    }
}

#[test]
fn exact_claim_counts_empty_work_without_erasing_rearm_or_restore_time() {
    use SchedulerServicePhase::*;
    let pool = ScsiSrbPumpOwners::<2>::new();
    let first = pool.claim(owner(1)).unwrap();
    let _other = pool.claim(owner(2)).unwrap();
    let mut clock = SchedulerServiceClock::new(20);
    clock.transition(TimerWork, 22);
    clock.transition(IrqDrain, 25);
    clock.transition(DpcDrain, 28);
    clock.transition(ReceivePrepare, 30);
    clock.transition(ParentRestore, 40);
    first.record_scheduler_service(clock.finish(45, 0, 0, 0));
    assert_eq!(pool.scheduler_service_summary(), (1, 1, 0, 0, 0));
    assert_eq!(pool.scheduler_service_phase_total(ReceivePrepare), (1, 10));
    assert_eq!(pool.scheduler_service_phase_total(ParentRestore), (1, 5));
    let mut work = SchedulerServiceClock::new(50);
    work.transition(TimerWork, 51);
    first.record_scheduler_service(work.finish(55, 1, 0, 2));
    assert_eq!(pool.scheduler_service_summary(), (2, 1, 1, 0, 2));
    assert_eq!(pool.scheduler_service_phase_total(TimerWork), (2, 7));
}
