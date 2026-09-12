//! Original caller provenance retained for one pending File delivery lifetime.

use crate::*;
use nt_io_manager::{PendingFileIo, PendingFileIoIdentity, PendingFileIoReservation};
use nt_user_host::pending_caller::PendingCallerTable;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

static mut CALLERS: PendingCallerTable<PendingFileIoIdentity> = PendingCallerTable::new();

fn matches_caller(caller: ProviderLogicalCaller, pending: PendingFileIo) -> bool {
    caller.pi() == pending.pi as usize
        && u64::from(caller.thread().thread_id()) == pending.tid
        && caller.badge() == pending.badge
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

pub(crate) unsafe fn reset() -> bool {
    (&mut *core::ptr::addr_of_mut!(CALLERS)).reset()
}
