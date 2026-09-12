//! Retained APC interruption of an accepted synchronous File IRP.

use crate::*;
use nt_io_manager::{
    PendingFileApcEffect as Effect, PendingFileApcOutcome as Outcome, PendingFileApcPhase as Phase,
    PendingFileApcReceipt as Receipt, PendingFileIo, PendingFileIoIdentity as Identity,
    PendingFileIoOperation,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

struct Interruption {
    identity: Identity,
    caller: ProviderLogicalCaller,
    apc: nt_process::UserApcClaim,
    staged: bool,
    reply_sent: bool,
    claim_released: bool,
}

static mut INTERRUPTIONS: Vec<Option<Interruption>> = Vec::new();
static RETRY_PENDING: AtomicBool = AtomicBool::new(false);
static ADMISSION_PENDING: AtomicBool = AtomicBool::new(false);
static FAILURES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn schedule_redrive() {
    RETRY_PENDING.store(true, Ordering::Release);
}

pub(crate) fn schedule_admission() {
    ADMISSION_PENDING.store(true, Ordering::Release);
}

unsafe fn index(identity: Identity) -> Option<usize> {
    (&*core::ptr::addr_of!(INTERRUPTIONS))
        .iter()
        .position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.identity == identity)
        })
}

pub(crate) fn owns_thread(tid: u64) -> bool {
    unsafe { (&*core::ptr::addr_of!(PENDING_FILE_IO)).has_apc_for_thread(tid) }
}

pub(crate) fn has_thread(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .has_apc_runtime_dependency_matching(|pending| pending.tid == tid)
    }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(PENDING_FILE_IO)).has_apc_runtime_dependency_matching(|pending| {
            pending.pi as usize == pi && preserve_tid != Some(pending.tid)
        })
    }
}

pub(crate) unsafe fn request(handler: &mut ExecNtHandler, tid: u64) -> bool {
    if owns_thread(tid) {
        return true;
    }
    handler.publish_local_byte_lock_completions();
    let Some((identity, pending)) =
        (&*core::ptr::addr_of!(PENDING_FILE_IO)).user_apc_interrupt_candidate(tid)
    else {
        return false;
    };
    let Some(caller) = pending_file_caller::caller(identity, pending) else {
        return false;
    };
    if !handler.validate_provider_logical_caller(caller) {
        return false;
    }
    let records = &mut *core::ptr::addr_of_mut!(INTERRUPTIONS);
    let vacant = records.iter().position(Option::is_none);
    if vacant.is_none() && records.try_reserve(1).is_err() {
        schedule_admission();
        return false;
    }
    let Ok(Some(mut apc)) = handler.pm.claim_user_apc(caller.thread().thread_id()) else {
        return false;
    };
    assert_eq!(apc.lifetime(), caller.thread());
    if (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
        .request_user_apc_interruption(identity, pending.irp_id)
        .is_err()
    {
        handler
            .pm
            .release_user_apc_claim(&mut apc)
            .expect("unpublished pending File APC lost its queue claim");
        return false;
    }
    let entry = Some(Interruption {
        identity,
        caller,
        apc,
        staged: false,
        reply_sent: false,
        claim_released: false,
    });
    if let Some(slot) = vacant {
        records[slot] = entry;
    } else {
        records.push(entry);
    }
    // The core owner and native claim are visible before any provider cancellation can reenter.
    thread_wait_state_park_badge_waiting(handler, pending.badge);
    RETRY_PENDING.store(true, Ordering::Release);
    drive(handler, identity);
    true
}

/// Record intent while the original runtime still exists; late effects never clear its badge.
pub(crate) unsafe fn request_thread(handler: &ExecNtHandler, tid: u64) -> usize {
    let mut count = 0;
    for entry in (&*core::ptr::addr_of!(INTERRUPTIONS)).iter().flatten() {
        if u64::from(entry.caller.thread().thread_id()) != tid {
            continue;
        }
        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
            .request_apc_teardown(entry.identity)
            .expect("pending File APC teardown lost its exact owner");
        count += 1;
    }
    if count != 0 {
        thread_wait_state_clear_tid(handler, tid);
        RETRY_PENDING.store(true, Ordering::Release);
    }
    count
}

unsafe fn cancel_select(
    handler: &mut ExecNtHandler,
    pending: PendingFileIo,
) -> Result<Receipt, u32> {
    let selected = match pending.operation {
        PendingFileIoOperation::Transfer => {
            // This lookup pumps providers. CancelSelect already owns the control, preventing
            // nested terminal delivery from staging the APC before selection is recorded.
            if driver_launch::completed_irp_exact(pending.irp_id).is_some() {
                false
            } else {
                driver_launch::cancel_irp_if_pending(pending.irp_id)?
            }
        }
        PendingFileIoOperation::LocalByteLock(operation) => {
            let selected = handler.cancel_local_byte_lock_wait(operation.wait_id);
            if selected {
                handler.publish_local_byte_lock_completions();
            }
            selected
        }
        PendingFileIoOperation::LocalDirectoryNotify(operation) => handler
            .cancel_local_directory_notify(
                pending
                    .route
                    .local_file_object()
                    .ok_or(nt_fs::STATUS_INVALID_HANDLE)?,
                operation.notify_id,
            )?,
        _ => return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    };
    service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    Ok(if selected {
        Receipt::CancelSelected
    } else {
        Receipt::CancelNotSelected
    })
}

unsafe fn stage(
    handler: &mut ExecNtHandler,
    identity: Identity,
    pending: PendingFileIo,
    terminal_status: Option<u32>,
) -> Result<Receipt, u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let (caller, payload) = {
        let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .unwrap();
        if entry.staged || entry.claim_released || !handler.pm.validate_user_apc_claim(&entry.apc) {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        (entry.caller, entry.apc.apc())
    };
    let status = terminal_status.ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    use nt_thread_start::amd64_context::UserApcContinuation;
    let continuation = if pending.native_call_transport {
        UserApcContinuation::NativeCall
    } else {
        UserApcContinuation::Fault {
            resume_ip: pending.resume_ip,
            resume_sp: pending.resume_sp,
            resume_flags: pending.resume_flags,
        }
    };
    let install = user_apc::stage_frame(handler, caller, payload, continuation, status)?;
    {
        let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .filter(|entry| entry.identity == identity)
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        let view = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .apc(identity)
            .map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
        if view.teardown_requested {
            return Err(nt_status::NtStatus::CANCELLED.raw() as u32);
        }
        if !matches!(
            view.phase,
            Phase::Invoking {
                effect: Effect::Stage,
                ..
            }
        ) || view.terminal_status != Some(status)
            || pending_file_caller::caller(identity, view.pending) != Some(caller)
            || !handler.validate_provider_logical_caller(caller)
            || !handler.pm.validate_user_apc_claim(&entry.apc)
        {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
    }
    thread_context::write(caller.tcb(), &install, false)
        .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)?;
    // No executive reentry separates register installation from consuming the exact APC claim.
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap();
    assert_eq!(entry.identity, identity);
    handler
        .pm
        .commit_user_apc_claim(&mut entry.apc)
        .expect("installed pending File APC lost its exact queue claim");
    entry.staged = true;
    Ok(Receipt::Staged)
}

unsafe fn send(handler: &ExecNtHandler, identity: Identity, pending: PendingFileIo) -> Outcome {
    let Some(slot) = index(identity) else {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    };
    let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
        .as_ref()
        .unwrap();
    if !entry.staged
        || entry.reply_sent
        || entry.claim_released
        || !handler.validate_provider_logical_caller(entry.caller)
    {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    }
    if let Err(status) = parked_reply::validate_saved(pending.reply_cap) {
        return Outcome::NotEntered(status);
    }
    if !client_reply_on(pending.reply_cap, 0, 0, 0, 0, 0) {
        return Outcome::Indeterminate(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap()
        .reply_sent = true;
    Outcome::Completed(Receipt::Sent)
}

unsafe fn release_claim(handler: &mut ExecNtHandler, identity: Identity) -> Result<Receipt, u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap();
    if entry.claim_released {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    handler.pm.release_user_apc_claim(&mut entry.apc)?;
    entry.claim_released = true;
    Ok(Receipt::ApcClaimReleased)
}

unsafe fn finish(handler: &mut ExecNtHandler, identity: Identity, teardown: bool) {
    let slot = index(identity).expect("settled pending File APC lost its native owner");
    assert!(
        (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .unwrap()
            .claim_released,
        "pending File APC finished before releasing its queue claim"
    );
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .take()
        .unwrap();
    if entry.reply_sent && !teardown && handler.validate_provider_logical_caller(entry.caller) {
        thread_wait_state_clear_badge_ready(handler, entry.caller.badge());
    }
    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
        .finish_apc(identity)
        .expect("settled pending File APC lost its exact core owner");
    service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
}

fn report(identity: Identity, tid: u64, effect: Effect, status: u32, uncertain: bool) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[pending-file-apc] retained slot=");
        print_u64(identity.slot() as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" effect=");
        print_str(match effect {
            Effect::CancelSelect => b"cancel-select",
            Effect::Stage => b"stage",
            Effect::Send => b"send",
            Effect::RetireSentReply => b"sent-reply-retire",
            Effect::RevokeReply => b"reply-revoke",
            Effect::RetypeReply => b"reply-retype",
            Effect::ReleaseApcClaim => b"claim-release",
        });
        print_str(b" uncertain=");
        print_u64(u64::from(uncertain));
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

pub(crate) unsafe fn drive(handler: &mut ExecNtHandler, identity: Identity) {
    let _message = ipc_message::SavedMessageBuffer::capture();
    // Cancel selection, Stage/Send/cap retirement, claim release, and final control retirement.
    for _ in 0..8 {
        let Ok(view) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).apc(identity) else {
            return;
        };
        if view.phase == Phase::Complete {
            finish(handler, identity, view.teardown_requested);
            return;
        }
        if !matches!(view.phase, Phase::Ready { .. }) {
            return;
        }
        let Ok(mut attempt) =
            (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO)).begin_apc_step(identity)
        else {
            RETRY_PENDING.store(true, Ordering::Release);
            return;
        };
        let effect = attempt.effect();
        let outcome = if effect == Effect::Send {
            send(handler, identity, view.pending)
        } else {
            let result = match effect {
                Effect::CancelSelect => cancel_select(handler, view.pending),
                Effect::Stage => stage(handler, identity, view.pending, view.terminal_status),
                Effect::RetireSentReply => parked_reply::retire_sent(view.pending.reply_cap)
                    .map(|()| Receipt::SentReplyRetired),
                Effect::RevokeReply => {
                    parked_reply::revoke(view.pending.reply_cap).map(|()| Receipt::ReplyRevoked)
                }
                Effect::RetypeReply => {
                    parked_reply::retype(view.pending.reply_cap).map(|()| Receipt::ReplyRetyped)
                }
                Effect::ReleaseApcClaim => release_claim(handler, identity),
                Effect::Send => unreachable!(),
            };
            match result {
                Ok(receipt) => Outcome::Completed(receipt),
                Err(status) => Outcome::NotEntered(status),
            }
        };
        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
            .record_apc_step(&mut attempt, outcome)
            .expect("pending File APC receipt lost its entered owner");
        match outcome {
            Outcome::NotEntered(status) => {
                RETRY_PENDING.store(true, Ordering::Release);
                report(identity, view.pending.tid, effect, status, false);
                return;
            }
            Outcome::Indeterminate(status) => {
                report(identity, view.pending.tid, effect, status, true);
                return;
            }
            Outcome::Completed(_) => {}
        }
    }
    RETRY_PENDING.store(true, Ordering::Release);
}

unsafe fn admit_deferred(handler: &mut ExecNtHandler) {
    let Some(last_slot) = (&*core::ptr::addr_of!(PENDING_FILE_IO))
        .drain_exact()
        .map(|(identity, _)| identity.slot())
        .max()
    else {
        return;
    };
    for slot in 0..=last_slot {
        let next = {
            let table = &*core::ptr::addr_of!(PENDING_FILE_IO);
            table
                .identity(slot)
                .and_then(|identity| table.get_exact(identity).map(|pending| (identity, pending)))
        };
        let Some((identity, pending)) = next else {
            continue;
        };
        let Some(caller) = pending_file_caller::caller(identity, pending) else {
            continue;
        };
        if handler
            .pm
            .peek_user_apc(caller.thread().thread_id())
            .is_none()
            || !handler.validate_provider_logical_caller(caller)
            || (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .user_apc_interrupt_candidate(pending.tid)
                .is_none_or(|(candidate, _)| candidate != identity)
        {
            continue;
        }
        // Reenter only after the live identity check, with no retained table borrow. A reused
        // slot or a newly leased prefix must pass request's own exact admission again.
        let _ = request(handler, pending.tid);
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let retry = RETRY_PENDING.swap(false, Ordering::AcqRel);
    if ADMISSION_PENDING.swap(false, Ordering::AcqRel) {
        admit_deferred(handler);
    }
    if !retry {
        return;
    }
    let mut after = None;
    while let Some(identity) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).next_apc_after(after) {
        after = Some(identity.slot());
        drive(handler, identity);
    }
}
