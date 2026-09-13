//! Retire already-terminal File work without manufacturing a pending IRP or retaining a caller.

use super::*;
use nt_io_manager::inline_file_retirement::{
    InlineFileRetirementEffect as Effect, InlineFileRetirementError as Error,
    InlineFileRetirementIdentity as Identity, InlineFileRetirementOutcome as Outcome,
    InlineFileRetirementPhase as Phase, InlineFileRetirementReservation as Reservation,
    InlineFileRetirementTable,
};
use nt_io_manager::{FileIoBusyOwner, FileIoWaitKey};

static mut OWNERS: InlineFileRetirementTable = InlineFileRetirementTable::new();
static RETRY_PENDING: AtomicBool = AtomicBool::new(false);
static FAILURES: AtomicU64 = AtomicU64::new(0);

/// Pre-effect storage. Every refused or contended admission cancels only this empty reservation.
pub(crate) struct Admission(Option<Reservation>);

impl Admission {
    pub(crate) fn activate(mut self) -> Identity {
        let reservation = self
            .0
            .take()
            .expect("File admission consumed its reservation twice");
        unsafe {
            (&mut *core::ptr::addr_of_mut!(OWNERS))
                .activate(reservation)
                .expect("accepted File acquisition lost its pre-reserved owner")
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(reservation) = self.0.take() {
            unsafe {
                (&mut *core::ptr::addr_of_mut!(OWNERS))
                    .cancel_reserved(reservation)
                    .expect("refused File admission lost its empty reservation");
            }
        }
    }
}

pub(crate) fn reserve(owner: FileIoBusyOwner) -> Result<Admission, u32> {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(OWNERS))
            .reserve(owner)
            .map(|reservation| Admission(Some(reservation)))
            .map_err(|error| match error {
                Error::InvalidOwner => nt_fs::STATUS_INVALID_PARAMETER,
                _ => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
            })
    }
}

pub(crate) fn active_owner(identity: Identity) -> FileIoBusyOwner {
    unsafe {
        (&*core::ptr::addr_of!(OWNERS))
            .active_owner(identity)
            .expect("current File syscall lost its exact active owner")
    }
}

/// The real pending IRP must already have been published with this same Busy/reference owner.
pub(super) unsafe fn transfer_to_pending(identity: Identity) {
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .transfer_active(identity)
        .expect("published pending File transfer lost its active source");
}

pub(super) unsafe fn retire(identity: Identity) {
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .retire_active(identity)
        .expect("terminal File syscall lost its active retirement owner");
    RETRY_PENDING.store(true, Ordering::Release);
}

fn report(owner: FileIoBusyOwner, effect: Effect, status: u32, uncertain: bool) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    print_str(b"[inline-file-retirement] retained file=");
    match owner.key {
        FileIoWaitKey::Hosted(file_id) => print_u64(file_id),
        FileIoWaitKey::LocalOverlay(_) => print_str(b"invalid-domain"),
    }
    print_str(b" tid=");
    print_u64(owner.tid);
    print_str(b" effect=");
    print_str(match effect {
        Effect::ReleasePolicy => b"busy-release",
        Effect::Wake => b"wake",
        Effect::ReleaseReference => b"reference",
        Effect::ReferenceFollowup => b"reference-followup",
    });
    print_str(b" uncertain=");
    print_u64(uncertain as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

unsafe fn drive(handler: &mut ExecNtHandler, identity: Identity) {
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    // Four independent effects followed by metadata retirement, with no borrowed table at callout.
    for _ in 0..5 {
        let view = (&*core::ptr::addr_of!(OWNERS))
            .get(identity)
            .expect("inline File retirement lost its exact owner");
        if view.phase == Phase::Complete {
            (&mut *core::ptr::addr_of_mut!(OWNERS))
                .finish(identity)
                .expect("inline File retirement lost its complete receipt");
            return;
        }
        if !matches!(view.phase, Phase::Ready { .. }) {
            return;
        }
        let Ok(mut attempt) = (&mut *core::ptr::addr_of_mut!(OWNERS)).begin_step(identity) else {
            RETRY_PENDING.store(true, Ordering::Release);
            return;
        };
        let owner = attempt.owner();
        let effect = attempt.effect();
        let result = match effect {
            Effect::ReleasePolicy => pending_file_busy::release_policy(handler, owner)
                .map(|waiters| Outcome::PolicyReleased { waiters }),
            Effect::Wake => synchronous_file_wait::settle_synchronous_file_wake(handler, owner.key)
                .map(|()| Outcome::Completed(Effect::Wake)),
            Effect::ReleaseReference => match owner.key {
                FileIoWaitKey::Hosted(file_id) => handler
                    .file_completion
                    .release_file(file_id)
                    .map(Outcome::ReferenceReleased),
                FileIoWaitKey::LocalOverlay(_) => Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
            },
            Effect::ReferenceFollowup => {
                let receipt = attempt
                    .reference_release()
                    .expect("inline File followup lost its consumed reference receipt");
                crate::file_reference_retirement::followup(handler, receipt)
                    .map(|()| Outcome::Completed(Effect::ReferenceFollowup))
            }
        };
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(status) => Outcome::NotEntered(status),
        };
        (&mut *core::ptr::addr_of_mut!(OWNERS))
            .record_step(&mut attempt, outcome)
            .expect("inline File receipt lost its entered owner");
        match outcome {
            Outcome::NotEntered(status) => {
                RETRY_PENDING.store(true, Ordering::Release);
                report(owner, effect, status, false);
                return;
            }
            Outcome::Indeterminate(status) => {
                report(owner, effect, status, true);
                return;
            }
            _ => {}
        }
    }
    RETRY_PENDING.store(true, Ordering::Release);
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if !RETRY_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let limit = (&*core::ptr::addr_of!(OWNERS)).slot_len();
    let mut after = None;
    while let Some(identity) = (&*core::ptr::addr_of!(OWNERS)).next_ready_after(after) {
        if identity.slot() >= limit {
            RETRY_PENDING.store(true, Ordering::Release);
            break;
        }
        after = Some(identity.slot());
        drive(handler, identity);
    }
}
