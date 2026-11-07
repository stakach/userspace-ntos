#[path = "../../../components/ntos-executive/src/scsi_srb_pump_owner.rs"]
mod scsi_srb_pump_owner;
#[path = "../../../components/ntos-executive/src/scsi_srb_scheduler_service.rs"]
mod scsi_srb_scheduler_service;

use scsi_srb_pump_owner::{
    ScsiSrbPumpOwnerIdentity, ScsiSrbPumpOwners, ScsiSrbPumpStage, ScsiSrbPumpTimeline,
};

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
fn one_claim_records_distinct_linear_and_repeated_yield_intervals() {
    use ScsiSrbPumpStage::*;
    let pool = ScsiSrbPumpOwners::<2>::new();
    let claim = pool.claim(owner(1)).unwrap();
    let mut timeline = ScsiSrbPumpTimeline::new(&claim, 100);
    assert_eq!(pool.snapshot_with_stage(0), Some((owner(1), Some(RouteAdmit))));
    timeline.transition(Setup, 110);
    timeline.transition(ProviderPump, 120);
    timeline.transition(SchedulerService, 150);
    timeline.transition(ReceiveContinuation, 155);
    timeline.transition(SchedulerService, 170);
    timeline.transition(ReceiveContinuation, 175);
    timeline.transition(Completion, 190);
    timeline.transition(Restore, 195);
    timeline.finish(200);
    assert_eq!(pool.snapshot_with_stage(0), Some((owner(1), None)));
    assert_eq!(pool.stage_total(RouteAdmit), (1, 10));
    assert_eq!(pool.stage_total(Setup), (1, 10));
    assert_eq!(pool.stage_total(ProviderPump), (1, 30));
    assert_eq!(pool.stage_total(SchedulerService), (2, 10));
    assert_eq!(pool.stage_total(ReceiveContinuation), (2, 30));
    assert_eq!(pool.stage_total(Completion), (1, 5));
    assert_eq!(pool.stage_total(Restore), (1, 5));
}

#[test]
fn separate_claims_and_wrapping_ticks_keep_their_active_stages() {
    use ScsiSrbPumpStage::*;
    let pool = ScsiSrbPumpOwners::<2>::new();
    let first = pool.claim(owner(1)).unwrap();
    let second = pool.claim(owner(2)).unwrap();
    let mut a = ScsiSrbPumpTimeline::new(&first, u64::MAX - 4);
    let mut b = ScsiSrbPumpTimeline::new(&second, 100);
    a.transition(ProviderPump, 2);
    b.transition(Setup, 111);
    assert_eq!(pool.snapshot_with_stage(0), Some((owner(1), Some(ProviderPump))));
    assert_eq!(pool.snapshot_with_stage(1), Some((owner(2), Some(Setup))));
    a.finish(9);
    b.finish(121);
    assert_eq!(pool.stage_total(RouteAdmit), (2, 18));
    assert_eq!(pool.stage_total(ProviderPump), (1, 7));
    assert_eq!(pool.stage_total(Setup), (1, 10));
}

#[test]
fn concurrent_reuse_cannot_pair_an_owner_with_another_generations_stage() {
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
    use ScsiSrbPumpStage::*;
    let pool = Arc::new(ScsiSrbPumpOwners::<1>::new());
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let writer_pool = pool.clone();
        let writer_done = done.clone();
        scope.spawn(move || {
            for sequence in 1..=10_000 {
                let claim = writer_pool.claim(owner(sequence)).unwrap();
                let mut timeline = ScsiSrbPumpTimeline::new(&claim, sequence);
                timeline.transition(if sequence & 1 == 0 { Setup } else { ProviderPump }, sequence + 1);
                timeline.finish(sequence + 2);
            }
            writer_done.store(true, Ordering::Release);
        });
        while !done.load(Ordering::Acquire) {
            if let Some((identity, stage)) = pool.snapshot_with_stage(0) {
                assert_eq!(identity, owner(identity.sequence));
                let selected = if identity.sequence & 1 == 0 { Setup } else { ProviderPump };
                assert!(stage.is_none() || stage == Some(RouteAdmit) || stage == Some(selected));
            }
        }
    });
}
