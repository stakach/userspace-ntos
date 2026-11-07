//! Original caller provenance retained for one pending File delivery lifetime.

use crate::*;
use nt_io_manager::{PendingFileIo, PendingFileIoIdentity, PendingFileIoReservation};
use nt_user_host::pending_caller::{PendingCallerError, PendingCallerTable};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

static mut CALLERS: PendingCallerTable<PendingFileIoIdentity> = PendingCallerTable::new();

fn matches_caller(caller: ProviderLogicalCaller, pending: PendingFileIo) -> bool {
    caller.pi() == pending.pi as usize
        && u64::from(caller.thread().thread_id()) == pending.tid
        && caller.badge() == pending.badge
}

/// A checked publication claim for one selected File row. Preparation does not move or publish
/// the caller; the exact table reservation and File record still have to commit independently.
#[allow(dead_code)]
pub(crate) struct SelectedFileCallerPublication {
    reservation: PendingFileIoReservation,
    pending: PendingFileIo,
    caller: ProviderLogicalCaller,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedFileCallerError {
    MissingReservedCaller,
    CallerMismatch,
    MissingPublishedFile,
    PublishedFileChanged,
    PublishRejected(PendingCallerError),
}

/// Check caller provenance before the File table's first publication effect. A refusal leaves
/// both the File reservation and the reserved caller with their existing owners.
#[allow(dead_code)]
pub(crate) unsafe fn prepare_selected_publication(
    reservation: PendingFileIoReservation,
    pending: PendingFileIo,
) -> Result<SelectedFileCallerPublication, SelectedFileCallerError> {
    let identity = reservation.identity();
    let caller = (&*core::ptr::addr_of!(CALLERS))
        .get_reserved(identity.slot(), identity)
        .ok_or(SelectedFileCallerError::MissingReservedCaller)?;
    if !matches_caller(caller, pending) {
        return Err(SelectedFileCallerError::CallerMismatch);
    }
    Ok(SelectedFileCallerPublication {
        reservation,
        pending,
        caller,
    })
}

/// Advance only the caller captured before dispatch, after the exact File row has committed.
/// On refusal the claim and any published File row remain retained for reconciliation; a caller
/// is never replaced, and no Reply park is implied by this result.
#[allow(dead_code)]
pub(crate) unsafe fn try_publish_selected(
    claim: SelectedFileCallerPublication,
) -> Result<ProviderLogicalCaller, (SelectedFileCallerError, SelectedFileCallerPublication)> {
    let identity = claim.reservation.identity();
    let Some(live) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity) else {
        return Err((SelectedFileCallerError::MissingPublishedFile, claim));
    };
    // The table stamps the Busy identity during park_reserved. All other File fields must still
    // be the exact record prepared for this publication.
    let mut expected = claim.pending;
    if let Some(busy) = expected.busy {
        if !live.busy.is_some_and(|published| {
            published.owner() == busy.owner() && published.release_pending()
        }) {
            return Err((SelectedFileCallerError::PublishedFileChanged, claim));
        }
        expected.busy = live.busy;
    }
    if live != expected || !matches_caller(claim.caller, live) {
        return Err((SelectedFileCallerError::PublishedFileChanged, claim));
    }
    match (&mut *core::ptr::addr_of_mut!(CALLERS)).publish_checked(
        identity.slot(),
        identity,
        claim.caller,
        |stored| matches_caller(stored, live),
    ) {
        Ok(caller) => Ok(caller),
        Err(error) => Err((SelectedFileCallerError::PublishRejected(error), claim)),
    }
}

pub(crate) unsafe fn reserve(
    reservation: PendingFileIoReservation,
    caller: ProviderLogicalCaller,
) -> bool {
    let identity = reservation.identity();
    (&mut *core::ptr::addr_of_mut!(CALLERS))
        .reserve(identity.slot(), identity, caller)
        .is_ok()
}

pub(crate) unsafe fn publish(reservation: PendingFileIoReservation, pending: PendingFileIo) {
    let identity = reservation.identity();
    let caller = (&*core::ptr::addr_of!(CALLERS))
        .get_reserved(identity.slot(), identity)
        .expect("pending File publication lost its reserved caller");
    assert!(
        matches_caller(caller, pending),
        "pending File publication changed its original caller"
    );
    // Admission already captured the lifetime. Publication must not recapture a replacement
    // runtime or fail because teardown ran while the accepted IRP was being dispatched.
    let published = (&mut *core::ptr::addr_of_mut!(CALLERS))
        .publish(identity.slot(), identity)
        .expect("pending File caller refused its reserved publication");
    assert_eq!(published, caller);
}

pub(crate) unsafe fn cancel_reserved(reservation: PendingFileIoReservation) {
    let identity = reservation.identity();
    (&mut *core::ptr::addr_of_mut!(CALLERS))
        .cancel_reserved(identity.slot(), identity)
        .expect("unused pending File reservation lost its original caller");
}

pub(crate) unsafe fn retire(identity: PendingFileIoIdentity) {
    (&mut *core::ptr::addr_of_mut!(CALLERS))
        .retire_published(identity.slot(), identity)
        .expect("retired pending File owner lost its original caller");
}

pub(crate) unsafe fn caller(
    identity: PendingFileIoIdentity,
    pending: PendingFileIo,
) -> Option<ProviderLogicalCaller> {
    let live = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity)?;
    if live.irp_id != pending.irp_id
        || live.pi != pending.pi
        || live.tid != pending.tid
        || live.badge != pending.badge
    {
        return None;
    }
    let caller = (&*core::ptr::addr_of!(CALLERS)).get_published(identity.slot(), identity)?;
    matches_caller(caller, live).then_some(caller)
}

pub(crate) unsafe fn reserved_caller(
    reservation: PendingFileIoReservation,
) -> Option<ProviderLogicalCaller> {
    let identity = reservation.identity();
    (&*core::ptr::addr_of!(CALLERS)).get_reserved(identity.slot(), identity)
}

pub(crate) unsafe fn reset() -> bool {
    (&mut *core::ptr::addr_of_mut!(CALLERS)).reset()
}
