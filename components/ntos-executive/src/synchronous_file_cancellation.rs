//! Retained cancellation for unpublished waits and rejected, reply-retired ingress.

use super::*;
use nt_io_manager::{
    FileIoWaitKey, FileIoWaitRoute, SynchronousFileCancelEffect as Effect,
    SynchronousFileCancelIdentity, SynchronousFileCancelOutcome as Outcome,
    SynchronousFileCancelPhase as Phase, SynchronousFileCancelReceipt as Receipt,
    SynchronousFileWaitReservation, SynchronousFileWaitState, SynchronousFileWaiter,
};

static FAILURES: AtomicU64 = AtomicU64::new(0);

fn report_failure(waiter: SynchronousFileWaiter, effect: Effect, status: u32) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[file-cancel] retained ");
        print_str(match effect {
            Effect::Policy => b"policy",
            Effect::Wake => b"wake",
            Effect::HostedReference => b"reference",
            Effect::ReferenceFollowup => b"reference-followup",
            Effect::RevokeReply => b"reply-revoke",
            Effect::RetireReplyCap => b"reply-retire",
        });
        print_str(b" file=");
        match waiter.key() {
            FileIoWaitKey::Hosted(file_id) => {
                print_str(b"hosted/");
                print_u64(file_id);
            }
            FileIoWaitKey::LocalOverlay(file_id) => {
                print_str(b"overlay/");
                print_u64(file_id);
            }
        }
        print_str(b" tid=");
        print_u64(waiter.tid);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

/// Each policy operation is local and rejects before mutation. Local cancellation also consumes
/// its acquisition reference; the corresponding receipt must never enter HostedReference.
unsafe fn cancel_policy(
    nt_handler: &mut ExecNtHandler,
    waiter: SynchronousFileWaiter,
) -> Result<Receipt, u32> {
    match waiter.route {
        FileIoWaitRoute::Hosted { file_id, .. } => {
            let waiters = match waiter.state {
                SynchronousFileWaitState::Waiting => {
                    nt_handler.file_completion.cancel_io_waiter(file_id)
                }
                SynchronousFileWaitState::Promoted => nt_handler
                    .file_completion
                    .cancel_promoted_io(file_id, waiter.tid)
                    .map(|release| release.waiters),
            }?;
            Ok(Receipt::HostedPolicy { waiters })
        }
        FileIoWaitRoute::LocalOverlay { file_object } => {
            let waiters = match waiter.state {
                SynchronousFileWaitState::Waiting => {
                    crate::writable_fs::cancel_file_io_waiter(file_object)
                }
                SynchronousFileWaitState::Promoted => {
                    crate::writable_fs::cancel_promoted_file_io(file_object, waiter.tid)
                }
            }?;
            Ok(Receipt::LocalPolicy { waiters })
        }
    }
}

/// Finish independent effects in one bounded visit. No global table borrow crosses wake/IPC.
/// A retained failure retries only its current effect on a later service pass.
pub(crate) unsafe fn drive(
    nt_handler: &mut ExecNtHandler,
    identity: SynchronousFileCancelIdentity,
) -> bool {
    for _ in 0..5 {
        let (waiter, phase) = {
            let Ok(view) = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).cancellation(identity)
            else {
                return false;
            };
            (*view.waiter, view.phase)
        };
        // Live Reply cancellation requires retained final-cap deletion and exact-slot retyping.
        // No producer in this adapter transfers such an owner yet.
        if waiter.reply_cap != 0 {
            return false;
        }
        if phase == Phase::Complete {
            (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                .finish_cancellation(identity)
                .expect("settled File cancellation lost its exact owner");
            return true;
        }
        if !matches!(phase, Phase::Ready { .. }) {
            return false;
        }
        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
        let mut attempt = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
            .begin_cancellation(identity)
            .expect("ready File cancellation lost its exact owner");
        let result = match attempt.effect() {
            Effect::Policy => cancel_policy(nt_handler, waiter),
            Effect::Wake => {
                // nt-fs may have retired its File in the preceding atomic cancellation.
                if matches!(waiter.key(), FileIoWaitKey::LocalOverlay(_))
                    && attempt.policy_waiters() == Some(0)
                {
                    Ok(Receipt::Wake)
                } else {
                    synchronous_file_wait::settle_synchronous_file_wake(nt_handler, waiter.key())
                        .map(|()| Receipt::Wake)
                }
            }
            Effect::HostedReference => match waiter.route {
                FileIoWaitRoute::Hosted { file_id, .. } => nt_handler
                    .file_completion
                    .release_file(file_id)
                    .map(Receipt::HostedReference),
                FileIoWaitRoute::LocalOverlay { .. } => Err(nt_fs::STATUS_INVALID_PARAMETER),
            },
            Effect::ReferenceFollowup => {
                let release = attempt
                    .reference_release()
                    .expect("File cancellation followup lost its reference receipt");
                // Ordinary reference release cannot initiate CLEANUP. close_required describes
                // policy-row retirement; it does not authorize a second driver CLOSE.
                if release.cleanup_required {
                    Err(nt_fs::STATUS_INVALID_PARAMETER)
                } else if let Some(port_id) = release.port_id {
                    nt_handler
                        .try_release_io_completion_reference(port_id)
                        .map(|()| Receipt::ReferenceFollowup)
                } else {
                    Ok(Receipt::ReferenceFollowup)
                }
            }
            Effect::RevokeReply | Effect::RetireReplyCap => {
                unreachable!("reply-free File cancellation requested a capability effect")
            }
        };
        (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
            .record_cancellation(
                &mut attempt,
                match result {
                    Ok(receipt) => Outcome::Completed(receipt),
                    Err(status) => Outcome::NotEntered(status),
                },
            )
            .expect("File cancellation receipt lost its entered owner");
        if let Err(status) = result {
            report_failure(waiter, attempt.effect(), status);
            return false;
        }
    }
    false
}

pub(crate) unsafe fn cancel_unpublished(
    nt_handler: &mut ExecNtHandler,
    reservation: SynchronousFileWaitReservation,
    waiter: SynchronousFileWaiter,
) -> bool {
    let identity = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
        .cancel_reserved(reservation, waiter)
        .expect("unpublished File cancellation lost its reserved ownership");
    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    drive(nt_handler, identity)
}

pub(super) unsafe fn redrive(nt_handler: &mut ExecNtHandler) {
    let mut after = None;
    while let Some(identity) =
        (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).next_cancellation_after(after)
    {
        after = Some(identity.slot());
        drive(nt_handler, identity);
    }
}
