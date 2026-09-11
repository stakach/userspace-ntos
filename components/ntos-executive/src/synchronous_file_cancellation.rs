//! Retained cancellation for unpublished, published, and rejected-ingress File waits.

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
            Effect::StageUserApc => b"apc-stage",
            Effect::SendUserApc => b"apc-send",
            Effect::RetireApcReplyCap => b"apc-reply-retire",
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

unsafe fn revoke_reply(cap: u64) -> Result<Receipt, u32> {
    crate::parked_reply::revoke(cap)?;
    Ok(Receipt::ReplyRevoked)
}

unsafe fn retire_reply_cap(cap: u64) -> Result<Receipt, u32> {
    crate::parked_reply::retype(cap)?;
    Ok(Receipt::ReplyCapRetired)
}

/// Finish independent effects in one bounded visit. No global table borrow crosses wake/IPC.
/// A retained failure retries only its current effect on a later service pass.
pub(crate) unsafe fn drive(
    nt_handler: &mut ExecNtHandler,
    identity: SynchronousFileCancelIdentity,
) -> bool {
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    // Seven effects at most (including reference followup/APC return), then owner removal.
    for _ in 0..8 {
        let (waiter, phase) = {
            let Ok(view) = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).cancellation(identity)
            else {
                return false;
            };
            (*view.waiter, view.phase)
        };
        if phase == Phase::Complete {
            if let Err(status) = synchronous_file_apc::finish(nt_handler, identity) {
                FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                report_failure(waiter, Effect::RetireApcReplyCap, status);
                return false;
            }
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
        let outcome = match attempt.effect() {
            Effect::StageUserApc => synchronous_file_apc::stage(nt_handler, identity, waiter),
            Effect::SendUserApc => synchronous_file_apc::send(nt_handler, identity, waiter),
            effect => {
                let result = match effect {
                    Effect::Policy => cancel_policy(nt_handler, waiter),
                    Effect::Wake => {
                        // nt-fs may have retired its File in the preceding atomic cancellation.
                        if matches!(waiter.key(), FileIoWaitKey::LocalOverlay(_))
                            && attempt.policy_waiters() == Some(0)
                        {
                            Ok(Receipt::Wake)
                        } else {
                            synchronous_file_wait::settle_synchronous_file_wake(
                                nt_handler,
                                waiter.key(),
                            )
                            .map(|()| Receipt::Wake)
                        }
                    }
                    Effect::HostedReference => match waiter.route {
                        FileIoWaitRoute::Hosted { file_id, .. } => nt_handler
                            .file_completion
                            .release_file(file_id)
                            .map(Receipt::HostedReference),
                        FileIoWaitRoute::LocalOverlay { .. } => {
                            Err(nt_fs::STATUS_INVALID_PARAMETER)
                        }
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
                    Effect::RevokeReply => revoke_reply(waiter.reply_cap),
                    Effect::RetireReplyCap => retire_reply_cap(waiter.reply_cap),
                    Effect::RetireApcReplyCap => {
                        synchronous_file_apc::retire_reply(waiter.reply_cap)
                    }
                    Effect::StageUserApc | Effect::SendUserApc => unreachable!(),
                };
                match result {
                    Ok(receipt) => Outcome::Completed(receipt),
                    Err(status) => Outcome::NotEntered(status),
                }
            }
        };
        (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
            .record_cancellation(&mut attempt, outcome)
            .expect("File cancellation receipt lost its entered owner");
        if let Outcome::NotEntered(status) | Outcome::Indeterminate(status) = outcome {
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

/// Intent is published before any teardown callout; callers may mark an entire process before
/// driving effects. Cancelled rows retain their own references/cap slots, not target VM lifetime.
pub(crate) unsafe fn request_thread(nt_handler: &ExecNtHandler, tid: u64) -> usize {
    let table = &mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS);
    let marked = table.request_thread_cancellation(tid);
    // This is a teardown request against the still-live runtime. Never defer badge cleanup to
    // effect completion: the captured cancellation may survive TCB/runtime and PI retirement.
    if table.has_cancellation_for_thread(tid) {
        thread_wait_state_clear_tid(nt_handler, tid);
        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    }
    marked
}

pub(crate) unsafe fn redrive(nt_handler: &mut ExecNtHandler) {
    let mut after = None;
    while let Some(identity) =
        (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).next_cancellation_after(after)
    {
        after = Some(identity.slot());
        drive(nt_handler, identity);
    }
}
