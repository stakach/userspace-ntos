//! An idle interactive desktop is neither a stall nor a reason to keep the volume dirty.
//!
//! Boot 44246316182 sealed the boot-progress epoch when Explorer painted, idled, and ~360 s later
//! the milestone gate stopped the service loop. Its quiesce found the volume snapshot dirty and
//! refused hive durability, because nothing had published the volume while the loop ran.

#[path = "../../../components/ntos-executive/src/volume_lazy_flush.rs"]
mod volume_lazy_flush;

use volume_lazy_flush::{LazyFlush, LAZY_FLUSH_DELAY_100NS};

const SECOND: u64 = 10_000_000;

#[test]
fn a_dirty_volume_is_owed_a_checkpoint_after_the_lazy_delay() {
    let mut lazy = LazyFlush::new();
    assert_eq!(lazy.deadline(), None);
    assert!(!lazy.observe(true, 100 * SECOND));
    assert_eq!(lazy.deadline(), Some(100 * SECOND + LAZY_FLUSH_DELAY_100NS));
    assert!(!lazy.observe(true, 100 * SECOND + LAZY_FLUSH_DELAY_100NS - 1));
    assert!(lazy.observe(true, 100 * SECOND + LAZY_FLUSH_DELAY_100NS));
}

#[test]
fn a_begun_checkpoint_closes_the_interval_and_new_writes_open_another() {
    let mut lazy = LazyFlush::new();
    assert!(!lazy.observe(true, 10 * SECOND));
    // The checkpoint began: the volume no longer owes these bytes.
    assert!(!lazy.observe(false, 16 * SECOND));
    assert_eq!(lazy.deadline(), None);
    assert!(!lazy.observe(true, 20 * SECOND));
    assert_eq!(lazy.deadline(), Some(20 * SECOND + LAZY_FLUSH_DELAY_100NS));
}

#[test]
fn a_refused_checkpoint_retries_one_delay_later_not_immediately() {
    let mut lazy = LazyFlush::new();
    assert!(!lazy.observe(true, SECOND));
    assert!(lazy.observe(true, SECOND + LAZY_FLUSH_DELAY_100NS));
    // Still dirty at the next boundary: wait a full delay, never an overdue deadline.
    assert!(!lazy.observe(true, SECOND + LAZY_FLUSH_DELAY_100NS + 1));
    assert_eq!(lazy.deadline(), Some(SECOND + 2 * LAZY_FLUSH_DELAY_100NS));
    let raw = lazy.into_raw();
    assert_eq!(LazyFlush::from_raw(raw), lazy);
}

#[test]
fn the_service_boundary_owes_the_lazy_checkpoint_and_wakes_for_it() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let boundary = service
        .split("fn checkpoint_service_loop_volume(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    let owe = boundary.find("owe_lazy_volume_checkpoint(nt_handler)").expect("lazy flush");
    let publish = boundary.find("publish_required_dirty_volume(").unwrap();
    assert!(owe < publish, "the lazy demand precedes the boundary's publication");
    let deadlines = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
    assert!(deadlines.contains("volume_lazy_flush_deadline()"));
}

#[test]
fn the_milestone_gate_does_not_stop_a_sealed_interactive_desktop() {
    let gate = include_str!("../../../components/ntos-executive/src/executor/maintenance.rs");
    let window = gate
        .split("lp.diag.milestones.observe(")
        .nth(1)
        .expect("milestone watch")
        .split("lp.exit.record(b\"boot-milestone-stall\")")
        .next()
        .unwrap();
    assert!(window.starts_with("ep, crate::boot_progress_sealed(), now)"));
    assert!(window.contains("MilestoneVerdict::Silent"));
}
