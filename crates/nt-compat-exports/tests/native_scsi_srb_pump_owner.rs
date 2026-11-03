#[path = "../../../components/ntos-executive/src/scsi_srb_pump_owner.rs"]
mod scsi_srb_pump_owner;

use scsi_srb_pump_owner::{ScsiSrbPumpOwnerIdentity, ScsiSrbPumpOwners};

fn owner(sequence: u64) -> ScsiSrbPumpOwnerIdentity {
    ScsiSrbPumpOwnerIdentity {
        sequence,
        irp_id: sequence << 32 | 0x41,
        device_id: sequence << 32 | 0x52,
        instance: sequence + 10,
        reply_cap: sequence + 20,
        tcb: sequence + 30,
        caller_tid: sequence + 40,
        caller_generation: sequence + 50,
        route_badge: sequence + 60,
        route_endpoint: sequence + 70,
        entered_ticks: sequence + 80,
    }
}

#[test]
fn two_entered_pumps_keep_distinct_complete_identities() {
    let pool = ScsiSrbPumpOwners::<2>::new();
    let first = pool.claim(owner(1)).expect("first admitted pump");
    let second = pool.claim(owner(2)).expect("second concurrent admitted pump");
    assert_eq!(pool.snapshot(0), Some(owner(1)));
    assert_eq!(pool.snapshot(1), Some(owner(2)));
    drop(first);
    assert_eq!(pool.snapshot(0), None);
    assert_eq!(pool.snapshot(1), Some(owner(2)));
    drop(second);
    assert_eq!(pool.snapshot(1), None);
}

#[test]
fn retired_slot_reuse_never_reports_a_stale_owner() {
    let pool = ScsiSrbPumpOwners::<1>::new();
    let previous = pool.claim(owner(3)).unwrap();
    assert_eq!(pool.snapshot(0), Some(owner(3)));
    drop(previous);
    assert_eq!(pool.snapshot(0), None);
    let replacement = pool.claim(owner(4)).unwrap();
    assert_eq!(pool.snapshot(0), Some(owner(4)));
    drop(replacement);
    assert_eq!(pool.snapshot(0), None);
}

#[test]
fn saturation_is_counted_and_never_steals_a_live_slot() {
    let pool = ScsiSrbPumpOwners::<1>::new();
    let entered = pool.claim(owner(7)).unwrap();
    assert!(pool.claim(owner(8)).is_none());
    assert_eq!(pool.overflow_count(), 1);
    assert_eq!(pool.snapshot(0), Some(owner(7)));
    drop(entered);
    assert!(pool.claim(owner(0)).is_none(), "zero is not a valid unique sequence");
    assert_eq!(pool.overflow_count(), 2);
    assert_eq!(pool.snapshot(0), None);
}

#[test]
fn concurrent_reuse_never_returns_mixed_generations() {
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
    let pool = Arc::new(ScsiSrbPumpOwners::<1>::new());
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let writer_pool = pool.clone();
        let writer_done = done.clone();
        scope.spawn(move || {
            for sequence in 1..=10_000 {
                let claim = writer_pool.claim(owner(sequence)).unwrap();
                std::hint::black_box(&claim);
            }
            writer_done.store(true, Ordering::Release);
        });
        while !done.load(Ordering::Acquire) {
            if let Some(snapshot) = pool.snapshot(0) {
                assert_eq!(snapshot, owner(snapshot.sequence));
            }
        }
    });
}
