//! A periodic volume checkpoint that finds its owner busy defers; only a stalled owner fails.

#[path = "../../../components/ntos-executive/src/volume_checkpoint_deferral.rs"]
mod volume_checkpoint_deferral;

use volume_checkpoint_deferral::{Deferral, Outcome, MAX_STALLED_100NS, STATUS_DEVICE_BUSY};

const SECOND: u64 = 10_000_000;
const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;

/// Run 43554476320: NtSaveKey dirtied the volume, the first boundary started the native commit
/// (rechecking), the second saw it reach committing, and the timer boundary a moment later was
/// still busy. None of those attempts may end the service loop.
#[test]
fn in_flight_native_commit_defers_across_boundaries_until_it_publishes() {
    let mut deferral = Deferral::<(u8, u64)>::new();
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || (1, 0), || 100 * SECOND),
        Outcome::Deferred { episode: 1, first: true },
    );
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || (2, 0), || 100 * SECOND + 1),
        Outcome::Deferred { episode: 1, first: false },
    );
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || (2, 0), || 100 * SECOND + 2),
        Outcome::Deferred { episode: 1, first: false },
    );
    assert_eq!(
        deferral.observe(0, || unreachable!("a publication needs no progress"), || 103 * SECOND),
        Outcome::Settled { episode: 1, deferrals: 3, waited_100ns: 3 * SECOND },
    );
}

#[test]
fn a_clean_boundary_reads_neither_the_clock_nor_the_owner() {
    let mut deferral = Deferral::<u64>::new();
    assert_eq!(
        deferral.observe(0, || unreachable!("no owner"), || unreachable!("no clock")),
        Outcome::Settled { episode: 0, deferrals: 0, waited_100ns: 0 },
    );
}

#[test]
fn an_owner_that_keeps_advancing_is_never_stalled() {
    let mut deferral = Deferral::<u64>::new();
    let start = 50 * SECOND;
    for step in 0..10u64 {
        let now = start + step * (MAX_STALLED_100NS - 1);
        assert!(matches!(
            deferral.observe(STATUS_DEVICE_BUSY, || step, || now),
            Outcome::Deferred { episode: 1, .. }
        ));
    }
}

#[test]
fn an_owner_that_stops_advancing_is_a_named_failure_at_the_bound() {
    let mut deferral = Deferral::<u64>::new();
    let start = 50 * SECOND;
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 7, || start),
        Outcome::Deferred { episode: 1, first: true },
    );
    // Progress restarts the bound from the attempt that observed it.
    let advanced = start + 30 * SECOND;
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 8, || advanced),
        Outcome::Deferred { episode: 1, first: false },
    );
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 8, || advanced + MAX_STALLED_100NS - 1),
        Outcome::Deferred { episode: 1, first: false },
    );
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 8, || advanced + MAX_STALLED_100NS),
        Outcome::Stalled {
            status: STATUS_DEVICE_BUSY,
            deferrals: 4,
            stalled_100ns: MAX_STALLED_100NS,
        },
    );
    // The stalled owner stays stalled; it does not earn a fresh bound by being asked again.
    assert!(matches!(
        deferral.observe(STATUS_DEVICE_BUSY, || 8, || advanced + MAX_STALLED_100NS + 1),
        Outcome::Stalled { deferrals: 5, .. }
    ));
}

#[test]
fn a_refusal_other_than_busy_fails_at_once_and_closes_the_episode() {
    let mut deferral = Deferral::<u64>::new();
    assert_eq!(
        deferral.observe(STATUS_DEVICE_NOT_READY, || 0, || SECOND),
        Outcome::Failed(STATUS_DEVICE_NOT_READY),
    );
    assert!(matches!(
        deferral.observe(STATUS_DEVICE_BUSY, || 0, || SECOND),
        Outcome::Deferred { episode: 1, first: true }
    ));
    assert_eq!(
        deferral.observe(STATUS_DEVICE_NOT_READY, || 0, || 2 * SECOND),
        Outcome::Failed(STATUS_DEVICE_NOT_READY),
    );
    assert!(matches!(
        deferral.observe(STATUS_DEVICE_BUSY, || 0, || 3 * SECOND),
        Outcome::Deferred { episode: 2, first: true }
    ));
}

/// The service boundary owns the one classification, keeps the durable requirement on a
/// deferral, and gives the stalled owner its own stage name.
#[test]
fn the_service_boundary_routes_its_checkpoint_status_through_the_deferral() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let checkpoint = service.split("fn checkpoint_service_loop_volume(").nth(1).unwrap()
        .split("\nfn ").next().unwrap();
    assert!(checkpoint.contains("volume_checkpoint_deferral.observe("));
    assert!(checkpoint.contains("Outcome::Deferred"));
    assert!(checkpoint.contains("b\"volume-checkpoint-stalled\""));
    let publish = service.split("fn publish_required_dirty_volume(").nth(1).unwrap()
        .split("\nfn ").next().unwrap();
    assert!(publish.contains("nt_handler.writable_fs_commit_required = true;"));
}
