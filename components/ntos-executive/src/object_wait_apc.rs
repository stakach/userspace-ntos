//! Retained native APC provenance for exact dispatcher-object wait owners.

use crate::object_wait::OBJECT_WAITERS;
use crate::*;
use nt_user_host::object_wait::{
    ObjectWaitApcEffect as Effect, ObjectWaitApcOutcome as Outcome, ObjectWaitApcPhase as Phase,
    ObjectWaiterIdentity as Identity,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

struct Interruption {
    identity: Identity,
    caller: ProviderLogicalCaller,
    apc: nt_process::UserApcClaim,
    staged: bool,
    reply_sent: bool,
    reference_followup: Option<(usize, Option<nt_io_completion::FileReferenceRelease>)>,
}

static mut INTERRUPTIONS: Vec<Option<Interruption>> = Vec::new();
static RETRY_PENDING: AtomicBool = AtomicBool::new(false);
static FAILURES: AtomicU64 = AtomicU64::new(0);

unsafe fn index(identity: Identity) -> Option<usize> {
    (&*core::ptr::addr_of!(INTERRUPTIONS))
        .iter()
        .position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.identity == identity)
        })
}

pub(crate) fn has_thread(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .has_runtime_dependency_matching(|record| record.tid == tid)
    }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS)).has_runtime_dependency_matching(|record| {
            record.pi == pi && preserve_tid != Some(record.tid)
        })
    }
}

pub(crate) unsafe fn request(handler: &mut ExecNtHandler, tid: u64) -> bool {
    if has_thread(tid) {
        return true;
    }
    let Some((identity, record)) = object_waiter_alertable_for_tid(tid) else {
        return false;
    };
    let Some(tcb) = handler.hosted_thread_tcb(tid) else {
        return false;
    };
    let Some(caller) = handler.capture_provider_logical_caller(record.pi, tid, record.badge, tcb)
    else {
        return false;
    };
    let records = &mut *core::ptr::addr_of_mut!(INTERRUPTIONS);
    let vacant = records.iter().position(Option::is_none);
    if vacant.is_none() && records.try_reserve(1).is_err() {
        return false;
    }
    let Ok(Some(mut apc)) = handler.pm.claim_user_apc(caller.thread().thread_id()) else {
        return false;
    };
    assert_eq!(apc.lifetime(), caller.thread());
    if (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
        .claim_apc(identity, record.count as usize)
        .is_err()
    {
        handler
            .pm
            .release_user_apc_claim(&mut apc)
            .expect("unpublished object APC claim lost its manager");
        return false;
    }
    let entry = Some(Interruption {
        identity,
        caller,
        apc,
        staged: false,
        reply_sent: false,
        reference_followup: None,
    });
    if let Some(slot) = vacant {
        records[slot] = entry;
    } else {
        records.push(entry);
    }
    thread_wait_state_park_badge_waiting(handler, record.badge);
    RETRY_PENDING.store(true, Ordering::Release);
    drive(handler, identity);
    true
}

/// Publish intent against the still-live owner before any teardown callout can reenter.
pub(crate) unsafe fn request_thread(handler: &ExecNtHandler, tid: u64) -> usize {
    let table = &mut *core::ptr::addr_of_mut!(OBJECT_WAITERS);
    let mut count = 0;
    for slot in 0..table.slot_len() {
        let Some((identity, record)) = table.get(slot) else {
            continue;
        };
        if record.tid != tid || !table.is_claimed(identity) {
            continue;
        }
        table
            .request_teardown(identity)
            .expect("object APC teardown lost its exact row");
        count += 1;
    }
    if count != 0 {
        thread_wait_state_clear_tid(handler, tid);
        RETRY_PENDING.store(true, Ordering::Release);
    }
    count
}

unsafe fn release_reference(
    handler: &mut ExecNtHandler,
    identity: Identity,
    record: ObjectWaiterRecord,
    reference: usize,
) -> Result<(), u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if reference >= record.count as usize
        || (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .unwrap()
            .reference_followup
            .is_some()
    {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    let object = record.objects[reference];
    let release = if object.kind() == WaitObject::KIND_FILE {
        Some(handler.file_completion.release_file(object.id())?)
    } else {
        // These adapters only return Err before canonical decrement. Reentrant object/job cleanup
        // remains within this Invoking effect, so no second pass can release the reference again.
        handler.release_wait_object_reference(object, record.event_leases[reference])?;
        None
    };
    (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap()
        .reference_followup = Some((reference, release));
    Ok(())
}

unsafe fn reference_followup(
    handler: &mut ExecNtHandler,
    identity: Identity,
    reference: usize,
) -> Result<(), u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let (index, release) = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
        .as_ref()
        .unwrap()
        .reference_followup
        .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    if index != reference {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    if let Some(release) = release {
        // Ordinary wait-reference retirement cannot authorize another driver CLEANUP/CLOSE.
        if release.cleanup_required {
            return Err(nt_fs::STATUS_INVALID_PARAMETER);
        }
        if let Some(port) = release.port_id {
            handler.try_release_io_completion_reference(port)?;
        }
    }
    (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap()
        .reference_followup = None;
    Ok(())
}

unsafe fn stage(
    handler: &mut ExecNtHandler,
    identity: Identity,
    record: ObjectWaiterRecord,
) -> Result<(), u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let (caller, payload) = {
        let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .unwrap();
        if entry.staged || !handler.pm.validate_user_apc_claim(&entry.apc) {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        (entry.caller, entry.apc.apc())
    };
    use nt_thread_start::amd64_context::UserApcContinuation;
    let continuation = if record.native_call_transport {
        UserApcContinuation::NativeCall
    } else {
        UserApcContinuation::Fault {
            resume_ip: record.resume_ip,
            resume_sp: record.resume_sp,
            resume_flags: record.resume_flags,
        }
    };
    let install = user_apc::stage_frame(handler, caller, payload, continuation, 0xC0)?;
    {
        let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
            .as_ref()
            .filter(|entry| entry.identity == identity)
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        let view = (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .apc(identity)
            .map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
        if view.teardown_requested {
            return Err(nt_status::NtStatus::CANCELLED.raw() as u32);
        }
        if !handler.validate_provider_logical_caller(caller)
            || !handler.pm.validate_user_apc_claim(&entry.apc)
        {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
    }
    thread_context::write(caller.tcb(), &install, false)
        .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)?;
    // No executive reentry separates installed context from consuming this exact queue entry.
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap();
    handler
        .pm
        .commit_user_apc_claim(&mut entry.apc)
        .expect("installed object APC lost its exact queue claim");
    entry.staged = true;
    Ok(())
}

unsafe fn send(handler: &ExecNtHandler, identity: Identity, record: ObjectWaiterRecord) -> Outcome {
    let Some(slot) = index(identity) else {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    };
    let entry = (&*core::ptr::addr_of!(INTERRUPTIONS))[slot]
        .as_ref()
        .unwrap();
    if !entry.staged || entry.reply_sent || !handler.validate_provider_logical_caller(entry.caller)
    {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    }
    if let Err(status) = parked_reply::validate_saved(record.reply_cap) {
        return Outcome::NotEntered(status);
    }
    if !client_reply_on(record.reply_cap, 0, 0, 0, 0, 0) {
        return Outcome::Indeterminate(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap()
        .reply_sent = true;
    Outcome::Completed(Effect::Send)
}

unsafe fn finish(
    handler: &mut ExecNtHandler,
    identity: Identity,
    teardown: bool,
) -> Result<(), u32> {
    let slot = index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .as_mut()
        .unwrap();
    if entry.reference_followup.is_some() {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    if !entry.staged {
        handler.pm.release_user_apc_claim(&mut entry.apc)?;
    }
    let entry = (&mut *core::ptr::addr_of_mut!(INTERRUPTIONS))[slot]
        .take()
        .unwrap();
    if entry.reply_sent && !teardown && handler.validate_provider_logical_caller(entry.caller) {
        thread_wait_state_clear_badge_ready(handler, entry.caller.badge());
    }
    (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
        .finish_apc(identity)
        .expect("settled object APC lost its exact row");
    Ok(())
}

fn report(identity: Identity, tid: u64, status: u32) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        let phase = unsafe {
            (&*core::ptr::addr_of!(OBJECT_WAITERS))
                .apc(identity)
                .ok()
                .map(|view| view.phase)
        };
        print_str(b"[object-wait-apc] retained slot=");
        print_u64(identity.slot() as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" effect=");
        let effect = match phase {
            Some(
                Phase::Ready { effect, .. }
                | Phase::Invoking { effect, .. }
                | Phase::Indeterminate { effect, .. },
            ) => Some(effect),
            _ => None,
        };
        print_str(match effect {
            Some(Effect::ReleaseReference { .. }) => b"reference",
            Some(Effect::ReferenceFollowup { .. }) => b"reference-followup",
            Some(Effect::Stage) => b"stage",
            Some(Effect::Send) => b"send",
            Some(Effect::RetireSentReply) => b"sent-reply-retire",
            Some(Effect::RevokeReply) => b"reply-revoke",
            Some(Effect::RetypeReply) => b"reply-retype",
            None => b"finish",
        });
        if let Some(Effect::ReleaseReference { index } | Effect::ReferenceFollowup { index }) =
            effect
        {
            print_str(b" index=");
            print_u64(index as u64);
        }
        if matches!(phase, Some(Phase::Indeterminate { .. })) {
            print_str(b" uncertain=1");
        }
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

unsafe fn drive(handler: &mut ExecNtHandler, identity: Identity) {
    let _message = ipc_message::SavedMessageBuffer::capture();
    // At most 64 reference/followup pairs, Stage/Send/Retire, and final owner removal.
    for _ in 0..(WAITER_MAX_EVENTS * 2 + 4) {
        let (record, phase, teardown) = {
            let Ok(view) = (&*core::ptr::addr_of!(OBJECT_WAITERS)).apc(identity) else {
                return;
            };
            (*view.payload, view.phase, view.teardown_requested)
        };
        if phase == Phase::Complete {
            if let Err(status) = finish(handler, identity, teardown) {
                RETRY_PENDING.store(true, Ordering::Release);
                report(identity, record.tid, status);
            }
            return;
        }
        if !matches!(phase, Phase::Ready { .. }) {
            return;
        }
        let Ok(mut attempt) =
            (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS)).begin_apc_step(identity)
        else {
            RETRY_PENDING.store(true, Ordering::Release);
            return;
        };
        let effect = attempt.effect();
        let outcome = if effect == Effect::Send {
            send(handler, identity, record)
        } else {
            let result = match effect {
                Effect::ReleaseReference { index } => {
                    release_reference(handler, identity, record, index)
                }
                Effect::ReferenceFollowup { index } => reference_followup(handler, identity, index),
                Effect::Stage => stage(handler, identity, record),
                Effect::RetireSentReply => parked_reply::retire_sent(record.reply_cap),
                Effect::RevokeReply => parked_reply::revoke(record.reply_cap),
                Effect::RetypeReply => parked_reply::retype(record.reply_cap),
                Effect::Send => unreachable!(),
            };
            match result {
                Ok(()) => Outcome::Completed(effect),
                Err(status) => Outcome::NotEntered(status),
            }
        };
        (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
            .record_apc_step(&mut attempt, outcome)
            .expect("object APC receipt lost its entered owner");
        match outcome {
            Outcome::NotEntered(status) => {
                RETRY_PENDING.store(true, Ordering::Release);
                report(identity, record.tid, status);
                return;
            }
            Outcome::Indeterminate(status) => {
                report(identity, record.tid, status);
                return;
            }
            Outcome::Completed(_) => {}
        }
    }
    RETRY_PENDING.store(true, Ordering::Release);
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if !RETRY_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let mut after = None;
    while let Some(identity) = (&*core::ptr::addr_of!(OBJECT_WAITERS)).next_apc_after(after) {
        after = Some(identity.slot());
        drive(handler, identity);
    }
}
