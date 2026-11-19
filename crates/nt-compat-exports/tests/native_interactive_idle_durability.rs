//! An idle interactive desktop is neither a stall nor a reason to keep the volume dirty.
//!
//! Boot 44246316182 sealed the boot-progress epoch when Explorer painted, idled, and ~360 s later
//! the milestone gate stopped the service loop. Its quiesce found the volume snapshot dirty and
//! refused hive durability, because nothing had published the volume while the loop ran.

#[path = "../../../components/ntos-executive/src/volume_lazy_flush.rs"]
mod volume_lazy_flush;

use volume_lazy_flush::{episode_traced, LazyFlush, LAZY_FLUSH_DELAY_100NS};

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

// Run 44264311242 resumed a published disk: the volume was dirty from boot setup, the lazy flush
// fell due while the boot block source was draining to the native disk stack, the synchronous
// checkpoint failed with 0xc0000001, and the boundary treated it as fatal.

use volume_lazy_flush::{classify_failed_checkpoint, FailedCheckpoint, StoragePath};

#[test]
fn the_lazy_flush_waits_while_the_storage_path_cannot_serve_it() {
    assert!(StoragePath::Boot.serves_checkpoint());
    assert!(StoragePath::Native.serves_checkpoint());
    for path in [StoragePath::Unmounted, StoragePath::Blocked, StoragePath::Draining] {
        assert!(!path.serves_checkpoint(), "{path:?}");
    }
}

#[test]
fn a_failed_lazy_only_checkpoint_is_retried_not_fatal() {
    assert_eq!(classify_failed_checkpoint(false, false), FailedCheckpoint::RetryLazily);
    assert_eq!(classify_failed_checkpoint(true, false), FailedCheckpoint::Refuse);
    assert_eq!(classify_failed_checkpoint(false, true), FailedCheckpoint::Refuse);
}

#[test]
fn a_draining_route_is_busy_for_every_checkpoint_and_eligibility_uses_the_route() {
    let fs = include_str!("../../../components/ntos-executive/src/writable_fs.rs");
    let checkpoint = fs
        .split("pub(crate) unsafe fn checkpoint_dirty_volume()")
        .nth(1)
        .unwrap()
        .split("snapshot_storage::acquire()")
        .next()
        .unwrap();
    assert!(
        checkpoint.contains("BlockSourceKind::Draining") && checkpoint.contains("snapshot_storage::BUSY"),
        "a draining route admits no snapshot I/O and consumes nothing"
    );
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let owe = service
        .split("fn owe_lazy_volume_checkpoint(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(owe.contains("serves_checkpoint()"));
    let boundary = service
        .split("fn checkpoint_service_loop_volume(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(boundary.contains("classify_failed_checkpoint("));
}

/// An idle desktop: the volume becomes dirty once, nothing else happens, and the root wakes
/// only at the deadline the lazy flush registers. The checkpoint must be owed at that wake.
#[test]
fn an_idle_dirty_volume_is_published_by_its_lazy_deadline() {
    let mut lazy = LazyFlush::new();
    let dirty_at = 900 * SECOND; // long after the boot-progress seal
    assert!(!lazy.observe(true, dirty_at)); // the write's own service boundary
    let wake = lazy.deadline().expect("an idle loop has a timer to wake for");
    assert_eq!(wake, dirty_at + LAZY_FLUSH_DELAY_100NS);
    // The only later event is that timer; its boundary owes the checkpoint.
    assert!(lazy.observe(true, wake), "published by the deadline without any other activity");
    // The checkpoint began; the volume is clean and no further wake is armed.
    assert!(!lazy.observe(false, wake + 1));
    assert_eq!(lazy.deadline(), None);
}

/// Boot 44416320584: published lines stopped at episode 16, long before the desktop sealed,
/// so post-seal lazy publications were invisible. Later episodes trace at powers of two.
#[test]
fn checkpoint_publications_stay_visible_after_sixteen_episodes() {
    assert!((1..=16).all(episode_traced));
    assert!(episode_traced(32) && episode_traced(1024));
    assert!(!episode_traced(17) && !episode_traced(1000));
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    assert!(!service.contains("TRACED_EPISODES"));
    let published = service
        .split("service-loop checkpoint published episode=")
        .next()
        .unwrap();
    let tail = &published[published.len().saturating_sub(200)..];
    assert!(tail.contains("episode_traced(episode)"));
    assert!(service.contains("print_str(b\" lazy=\");"));
}
