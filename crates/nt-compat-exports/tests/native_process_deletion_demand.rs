//! Exercise the actual process-retirement drain gate with each kind of retirement input.

#[path = "../../../components/ntos-executive/src/process_deletion_demand.rs"]
mod demand;

use demand::ProcessDeletionDemand;

/// One service boundary: true when the drain ran.
fn boundary(demand: &mut ProcessDeletionDemand, epoch: u64, candidates: bool, retained: bool)
    -> bool
{
    match demand.begin(epoch, candidates) {
        Some(pass) => { demand.finish(pass, retained); true }
        None => false,
    }
}

#[test]
fn the_first_boundary_looks_and_an_idle_one_is_skipped() {
    let mut demand = ProcessDeletionDemand::new();
    assert!(boundary(&mut demand, 7, false, false), "nothing has been looked at yet");
    for _ in 0..1000 {
        assert!(!boundary(&mut demand, 7, false, false), "no new retirement work");
    }
}

#[test]
fn each_retirement_input_drives_the_drain() {
    let mut demand = ProcessDeletionDemand::new();
    assert!(boundary(&mut demand, 1, false, false));

    // A process became signaled or an abandonment was requested.
    assert!(boundary(&mut demand, 2, false, false));
    assert!(!boundary(&mut demand, 2, false, false));

    // A queued deletion candidate drives every boundary while it is live.
    assert!(boundary(&mut demand, 2, true, false));
    assert!(boundary(&mut demand, 2, true, false));
    assert!(!boundary(&mut demand, 2, false, false));

    // A retained failed thread spawn.
    demand.mark();
    assert!(boundary(&mut demand, 2, false, false));
    assert!(!boundary(&mut demand, 2, false, false));
}

#[test]
fn unfinished_work_keeps_being_retried() {
    let mut demand = ProcessDeletionDemand::new();
    assert!(boundary(&mut demand, 1, false, true), "a deletion that could not complete yet");
    for _ in 0..100 {
        assert!(boundary(&mut demand, 1, false, true), "retained work is retried every time");
    }
    assert!(boundary(&mut demand, 1, false, false), "the pass that finishes it still runs");
    assert!(!boundary(&mut demand, 1, false, false));
}

#[test]
fn a_change_during_a_pass_is_seen_by_the_next_boundary() {
    let mut demand = ProcessDeletionDemand::new();
    let pass = demand.begin(5, false).unwrap();
    // The pass's own work signals another process (epoch 5 -> 6) before it finishes.
    demand.finish(pass, false);
    assert!(boundary(&mut demand, 6, false, false));
    let pass = demand.begin(6, false);
    assert!(pass.is_none());
    // A spawn failure marked while no pass is admitted is not lost either.
    demand.mark();
    assert!(boundary(&mut demand, 6, false, false));
}
