//! Native APC provenance retained alongside an exact File cancellation owner.

use super::*;
use nt_io_manager::{
    SynchronousFileCancelIdentity as Identity, SynchronousFileCancelOutcome as Outcome,
    SynchronousFileCancelReceipt as Receipt, SynchronousFileWaiter,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

struct Interruption {
    identity: Identity,
    caller: ProviderLogicalCaller,
    apc: nt_process::UserApcClaim,
    staged: bool,
    reply_sent: bool,
}

static mut INTERRUPTIONS: Vec<Option<Interruption>> = Vec::new();

unsafe fn index(identity: Identity) -> Option<usize> {
    (&*core::ptr::addr_of!(INTERRUPTIONS))
        .iter()
        .position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.identity == identity)
        })
}

/// Claim both native provenance and the exact FIFO owner before any File effect or copyout.
pub(super) unsafe fn request(nt_handler: &mut ExecNtHandler, tid: u64) -> bool {
    if (&*core::ptr::addr_of!(INTERRUPTIONS))
        .iter()
        .flatten()
        .any(|entry| u64::from(entry.caller.thread().thread_id()) == tid)
    {
        return true;
    }
    let Some((slot, waiter)) =
        (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).alertable_waiting_for_thread(tid)
    else {
        return false;
    };
    let Some(tcb) = nt_handler.hosted_thread_tcb(tid) else {
        return false;
    };
    let Some(caller) =
        nt_handler.capture_provider_logical_caller(waiter.pi as usize, tid, waiter.badge, tcb)
    else {
        return false;
    };
    let Some(identity) =
        (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).wait_identity(slot, waiter.key(), tid)
    else {
        return false;
    };
    let records = &mut *core::ptr::addr_of_mut!(INTERRUPTIONS);
    let vacant = records.iter().position(Option::is_none);
    if vacant.is_none() && records.try_reserve(1).is_err() {
        return false;
    }
    let Ok(Some(mut apc)) = nt_handler.pm.claim_user_apc(caller.thread().thread_id()) else {
        return false;
    };
    assert_eq!(apc.lifetime(), caller.thread());
    if (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
        .request_user_apc_interruption(identity)
        .is_err()
    {
        nt_handler
            .pm
            .release_user_apc_claim(&mut apc)
            .expect("unpublished File APC claim lost its queue entry");
        return false;
    }
    let entry = Some(Interruption {
        identity,
        caller,
        apc,
        staged: false,
        reply_sent: false,
    });
    if let Some(slot) = vacant {
        records[slot] = entry;
    } else {
        records.push(entry);
    }
    // No callback can observe the core owner before its native provenance and Waiting marker.
    thread_wait_state_park_badge_waiting(nt_handler, waiter.badge);
    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    synchronous_file_cancellation::drive(nt_handler, identity);
    true
}

unsafe fn stage_current(
    nt_handler: &mut ExecNtHandler,
    identity: Identity,
    waiter: SynchronousFileWaiter,
) -> Result<Receipt, u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let (caller, apc) = {
        let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .unwrap();
        if entry.staged
            || !nt_handler.validate_provider_logical_caller(entry.caller)
            || !nt_handler.pm.validate_user_apc_claim(&entry.apc)
        {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        (entry.caller, entry.apc.apc())
    };
    use nt_thread_start::amd64_context::UserApcContinuation;
    let continuation = if waiter.native_call_transport {
        UserApcContinuation::NativeCall
    } else {
        UserApcContinuation::Fault {
            resume_ip: waiter.resume_ip,
            resume_sp: waiter.resume_sp,
            resume_flags: waiter.resume_flags,
        }
    };
    let install = crate::user_apc::stage_frame(nt_handler, caller, apc, continuation, 0xC0)?;
    // Copyout may reenter. Revalidate the retained identities, not a new queue head or runtime,
    // immediately before the checked register commit. No user APC is consumed on refusal.
    {
        let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .filter(|entry| entry.identity == identity)
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        if !nt_handler.validate_provider_logical_caller(caller)
            || !nt_handler.pm.validate_user_apc_claim(&entry.apc)
        {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
    }
    crate::thread_context::write(caller.tcb(), &install, false)
        .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)?;
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .expect("installed File APC lost its native owner");
    assert_eq!(entry.identity, identity);
    nt_handler
        .pm
        .commit_user_apc_claim(&mut entry.apc)
        .expect("installed File APC lost its exact queued entry");
    entry.staged = true;
    Ok(Receipt::UserApcStaged)
}

pub(super) unsafe fn stage(
    nt_handler: &mut ExecNtHandler,
    identity: Identity,
    waiter: SynchronousFileWaiter,
) -> Outcome {
    match stage_current(nt_handler, identity, waiter) {
        Ok(receipt) => Outcome::Completed(receipt),
        Err(status) => Outcome::NotEntered(status),
    }
}

pub(super) unsafe fn send(
    nt_handler: &ExecNtHandler,
    identity: Identity,
    waiter: SynchronousFileWaiter,
) -> Outcome {
    let Some(slot) = index(identity) else {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    };
    let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
        .as_ref()
        .unwrap();
    if !entry.staged
        || entry.reply_sent
        || !nt_handler.validate_provider_logical_caller(entry.caller)
    {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    }
    if let Err(status) = crate::parked_reply::validate_saved(waiter.reply_cap) {
        return Outcome::NotEntered(status);
    }
    // The staged context supplies the dispatcher entry. Empty Reply only releases its binding.
    if !client_reply_on(waiter.reply_cap, 0, 0, 0, 0, 0) {
        return Outcome::Indeterminate(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap()
        .reply_sent = true;
    Outcome::Completed(Receipt::UserApcReplySent)
}

pub(super) unsafe fn retire_reply(cap: u64) -> Result<Receipt, u32> {
    // Successful Reply already consumed the binding. There is no deletion or retyping here.
    crate::parked_reply::retire_sent(cap).map(|()| Receipt::UserApcReplyCapRetired)
}

/// Native provenance and any unconsumed APC claim retire before the core owner is removed.
pub(super) unsafe fn finish(nt_handler: &mut ExecNtHandler, identity: Identity) -> Result<(), u32> {
    let Some(slot) = index(identity) else {
        return Ok(());
    };
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap();
    if !entry.staged {
        nt_handler.pm.release_user_apc_claim(&mut entry.apc)?;
    }
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .take()
        .unwrap();
    if entry.reply_sent && nt_handler.validate_provider_logical_caller(entry.caller) {
        thread_wait_state_clear_badge_ready(nt_handler, entry.caller.badge());
    }
    Ok(())
}
