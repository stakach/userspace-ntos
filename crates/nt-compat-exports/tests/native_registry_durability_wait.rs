//! A registry request NT completes only once its data is durable waits for an in-flight volume
//! checkpoint; it never answers `STATUS_DEVICE_BUSY` and never succeeds on an older snapshot.

#[path = "../../../components/ntos-executive/src/volume_checkpoint_deferral.rs"]
mod volume_checkpoint_deferral;

use volume_checkpoint_deferral::{
    CallerStep, Deferral, Publication, PublicationTarget, MAX_STALLED_100NS, STATUS_DEVICE_BUSY,
    STATUS_IO_TIMEOUT,
};

const SECOND: u64 = 10_000_000;
const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;

/// The neighbour of KVM run 43554476320: `NtUnloadKey` on the native route with a dirty volume.
/// Its first attempt starts the commit and every attempt until the last write is acknowledged
/// reports busy. The caller waits through all of them and then sees the unload's own status.
#[test]
fn an_unload_waits_through_the_in_flight_commit_and_never_sees_busy() {
    let mut deferral = Deferral::<(u8, u64)>::new();
    let attempts = [(1, 0), (2, 0), (2, 7)];
    for (turn, progress) in attempts.into_iter().enumerate() {
        let step = deferral
            .observe(STATUS_DEVICE_BUSY, || progress, || 100 * SECOND + turn as u64)
            .caller_step();
        assert_eq!(step, CallerStep::Wait);
    }
    let step = deferral.observe(0, || unreachable!(), || 104 * SECOND).caller_step();
    assert_eq!(step, CallerStep::Complete(0));
}

#[test]
fn a_refused_attempt_completes_the_caller_with_that_status() {
    let mut deferral = Deferral::<u64>::new();
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 0, || SECOND).caller_step(),
        CallerStep::Wait,
    );
    assert_eq!(
        deferral.observe(STATUS_DEVICE_NOT_READY, || 0, || 2 * SECOND).caller_step(),
        CallerStep::Complete(STATUS_DEVICE_NOT_READY),
    );
}

/// An owner that stops advancing ends the wait with a failure of its own, not the busy status
/// and not success.
#[test]
fn a_stalled_owner_fails_the_caller_without_reporting_busy_or_success() {
    let mut deferral = Deferral::<u64>::new();
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 4, || SECOND).caller_step(),
        CallerStep::Wait,
    );
    assert_eq!(
        deferral.observe(STATUS_DEVICE_BUSY, || 4, || SECOND + MAX_STALLED_100NS - 1).caller_step(),
        CallerStep::Wait,
    );
    let step = deferral
        .observe(STATUS_DEVICE_BUSY, || 4, || SECOND + MAX_STALLED_100NS)
        .caller_step();
    assert_eq!(step, CallerStep::Complete(STATUS_IO_TIMEOUT));
    assert_ne!(STATUS_IO_TIMEOUT, STATUS_DEVICE_BUSY);
    assert_ne!(STATUS_IO_TIMEOUT, 0);
}

/// Checkpoint 5 was already writing when the request's bytes landed. Its publication may
/// predate them, so only a checkpoint begun afterwards (6) makes the request durable.
#[test]
fn a_publication_begun_before_the_request_does_not_satisfy_it() {
    let target = PublicationTarget::after(5);
    assert_eq!(target.classify(Err(STATUS_DEVICE_BUSY), 4), Publication::InFlight);
    // This caller consumed checkpoint 5's publication.
    assert_eq!(target.classify(Ok(true), 5), Publication::Again);
    // The next attempt began checkpoint 6, which covers the bytes.
    assert_eq!(target.classify(Err(STATUS_DEVICE_BUSY), 5), Publication::InFlight);
    assert_eq!(target.classify(Ok(true), 6), Publication::Durable { settled: true });
}

#[test]
fn a_clean_volume_is_durable_whatever_was_published() {
    let target = PublicationTarget::after(5);
    assert_eq!(target.classify(Ok(false), 5), Publication::Durable { settled: true });
}

/// The service loop can consume the covering publication first. The request is then durable
/// even though a later checkpoint is already in flight for someone else's bytes, and that later
/// requirement stays owed.
#[test]
fn a_covering_publication_consumed_elsewhere_still_satisfies_the_request() {
    let target = PublicationTarget::after(5);
    assert_eq!(
        target.classify(Err(STATUS_DEVICE_BUSY), 6),
        Publication::Durable { settled: false },
    );
}

#[test]
fn a_refused_checkpoint_is_a_failure_even_after_a_covering_publication_is_counted() {
    let target = PublicationTarget::after(5);
    assert_eq!(
        target.classify(Err(STATUS_DEVICE_NOT_READY), 4),
        Publication::Failed(STATUS_DEVICE_NOT_READY),
    );
}

/// On a route that commits synchronously the first attempt begins and publishes at once.
#[test]
fn a_synchronous_commit_satisfies_the_request_on_its_first_attempt() {
    let target = PublicationTarget::after(0);
    assert_eq!(target.classify(Ok(true), 1), Publication::Durable { settled: true });
}
