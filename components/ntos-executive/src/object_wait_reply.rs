//! Retained signal, timeout and teardown effects for exact dispatcher-wait owners.

use crate::object_wait::OBJECT_WAITERS;
use crate::*;
use nt_user_host::object_wait::{
    ObjectWaitReplyAttempt as Attempt, ObjectWaitReplyEffect as Effect,
    ObjectWaitReplyOutcome as Outcome, ObjectWaitReplyPhase as Phase,
    ObjectWaiterIdentity as Identity,
};

static RETRY_PENDING: AtomicBool = AtomicBool::new(false);
static TERMINATION_PENDING: AtomicBool = AtomicBool::new(false);
static TERMINATION_ACTIVE: AtomicBool = AtomicBool::new(false);
static FAILURES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn owns_thread(tid: u64) -> bool {
    unsafe {
        let table = &*core::ptr::addr_of!(OBJECT_WAITERS);
        table
            .iter()
            .any(|(id, record)| record.tid == tid && table.reply(id).is_ok())
    }
}

pub(crate) fn has_thread(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .has_reply_runtime_dependency_matching(|record| record.tid == tid)
    }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_WAITERS)).has_reply_runtime_dependency_matching(|record| {
            record.pi == pi && preserve_tid != Some(record.tid)
        })
    }
}

/// Selection and claim run without callouts after dispatcher state has been consumed.
pub(crate) unsafe fn select(identity: Identity, status: u64) {
    let table = &mut *core::ptr::addr_of_mut!(OBJECT_WAITERS);
    let count = table
        .get_exact(identity)
        .expect("wait selection lost its owner")
        .count;
    table
        .claim_reply(identity, count as usize, status)
        .expect("wait selection lost its exclusive terminal result");
    RETRY_PENDING.store(true, Ordering::Release);
}

/// Publish intent for every target before teardown can run a nested provider dispatch.
pub(crate) unsafe fn request_thread(_handler: &ExecNtHandler, tid: u64) {
    let table = &mut *core::ptr::addr_of_mut!(OBJECT_WAITERS);
    for slot in 0..table.slot_len() {
        let Some((id, record)) = table.get(slot) else {
            continue;
        };
        if record.tid != tid || table.apc(id).is_ok() {
            continue;
        }
        let count = record.count as usize;
        if table.reply(id).is_ok() {
            table
                .request_reply_teardown(id)
                .expect("wait teardown lost its terminal owner");
        } else {
            table
                .claim_reply_teardown(id, count)
                .expect("wait teardown lost its unselected owner");
        }
        RETRY_PENDING.store(true, Ordering::Release);
    }
}

unsafe fn reference(
    handler: &mut ExecNtHandler,
    attempt: &Attempt,
    record: ObjectWaiterRecord,
    index: usize,
) -> Result<(), u32> {
    if record.reference_followup.is_some() {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    let release = release_wait_reference_step(handler, record, index)?;
    (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
        .update_reply_payload(attempt, |record| {
            record.reference_followup = Some((index, release))
        })
        .expect("wait reference receipt lost its entered owner");
    Ok(())
}

unsafe fn reference_followup(
    handler: &mut ExecNtHandler,
    attempt: &Attempt,
    record: ObjectWaiterRecord,
    index: usize,
) -> Result<(), u32> {
    let (pending, release) = record
        .reference_followup
        .ok_or(nt_fs::STATUS_INVALID_PARAMETER)?;
    if pending != index {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    finish_wait_reference_step(handler, release)?;
    (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
        .update_reply_payload(attempt, |record| record.reference_followup = None)
        .expect("wait reference followup lost its entered owner");
    Ok(())
}

unsafe fn send(
    handler: &mut ExecNtHandler,
    attempt: &Attempt,
    record: ObjectWaiterRecord,
) -> Outcome {
    if record.reply_sent || !handler.validate_provider_logical_caller(record.caller) {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    }
    if let Err(status) = parked_reply::validate_saved(record.reply_cap) {
        return Outcome::NotEntered(status);
    }
    if !reply_parked_syscall(record.reply_cap, attempt.status()) {
        return Outcome::Indeterminate(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS))
        .update_reply_payload(attempt, |record| record.reply_sent = true)
        .expect("accepted wait reply lost its exact receipt");
    Outcome::Completed(Effect::Send)
}

fn report(identity: Identity, effect: Effect, status: u32, uncertain: bool) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    print_str(b"[object-wait-reply] retained slot=");
    print_u64(identity.slot() as u64);
    print_str(b" effect=");
    print_str(match effect {
        Effect::ReleaseReference { .. } => b"reference",
        Effect::ReferenceFollowup { .. } => b"reference-followup",
        Effect::Send => b"send",
        Effect::RetireSentReply => b"sent-reply-retire",
        Effect::RevokeReply => b"reply-revoke",
        Effect::RetypeReply => b"reply-retype",
    });
    print_str(b" uncertain=");
    print_u64(uncertain as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

unsafe fn finish(handler: &mut ExecNtHandler, id: Identity) -> u64 {
    let table = &mut *core::ptr::addr_of_mut!(OBJECT_WAITERS);
    let view = table.reply(id).expect("wait retirement lost its owner");
    assert_eq!(view.phase, Phase::Complete);
    let sent = view.payload.reply_sent && !view.teardown_requested;
    let status = view.status;
    let record = table
        .finish_reply(id)
        .expect("wait retirement lost its settled row");
    if !sent {
        return 0;
    }
    if handler.validate_provider_logical_caller(record.caller) {
        thread_wait_state_clear_badge_ready(handler, record.caller.badge());
    }
    let trace = WAIT_WAKE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
    if trace < 96 {
        print_str(b"[wait-wake] #");
        print_u64(trace);
        print_str(b" tid=");
        print_u64(record.tid);
        print_str(b" badge=");
        print_u64(record.caller.badge());
        print_str(b" result=");
        print_u64(status);
        print_str(b" count=");
        print_u64(record.count as u64);
        print_str(b" wait_all=");
        print_u64(record.wait_all as u64);
        print_str(b"\n");
    }
    WAIT_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
    1
}

unsafe fn drive(handler: &mut ExecNtHandler, id: Identity) -> u64 {
    let _message = ipc_message::SavedMessageBuffer::capture();
    for _ in 0..(WAITER_MAX_EVENTS * 2 + 4) {
        let (record, phase, teardown) = {
            let table = &*core::ptr::addr_of!(OBJECT_WAITERS);
            let Ok(view) = table.reply(id) else {
                return 0;
            };
            (*view.payload, view.phase, view.teardown_requested)
        };
        if phase == Phase::Complete {
            if teardown {
                TERMINATION_PENDING.store(true, Ordering::Release);
                return 0;
            }
            return finish(handler, id);
        }
        if !matches!(phase, Phase::Ready { .. }) {
            return 0;
        }
        let Ok(mut attempt) = (&mut *core::ptr::addr_of_mut!(OBJECT_WAITERS)).begin_reply_step(id)
        else {
            RETRY_PENDING.store(true, Ordering::Release);
            return 0;
        };
        let effect = attempt.effect();
        let outcome = if effect == Effect::Send {
            send(handler, &attempt, record)
        } else {
            let result = match effect {
                Effect::ReleaseReference { index } => reference(handler, &attempt, record, index),
                Effect::ReferenceFollowup { index } => {
                    reference_followup(handler, &attempt, record, index)
                }
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
            .record_reply_step(&mut attempt, outcome)
            .expect("wait reply receipt lost its entered owner");
        match outcome {
            Outcome::Completed(_) => {}
            Outcome::NotEntered(status) => {
                RETRY_PENDING.store(true, Ordering::Release);
                report(id, effect, status, false);
                return 0;
            }
            Outcome::Indeterminate(status) => {
                report(id, effect, status, true);
                return 0;
            }
        }
    }
    RETRY_PENDING.store(true, Ordering::Release);
    0
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) -> u64 {
    if !RETRY_PENDING.swap(false, Ordering::AcqRel) {
        return 0;
    }
    let mut after = None;
    let mut woken = 0;
    let limit = object_waiter_len();
    while let Some(id) = (&*core::ptr::addr_of!(OBJECT_WAITERS)).next_reply_after(after) {
        if id.slot() >= limit {
            RETRY_PENDING.store(true, Ordering::Release);
            break;
        }
        after = Some(id.slot());
        woken += drive(handler, id);
    }
    woken
}

pub(crate) unsafe fn redrive_terminated_runtimes(
    handler: &mut ExecNtHandler,
    queue: &mut nt_delay_execution::Queue,
) {
    if TERMINATION_ACTIVE.swap(true, Ordering::AcqRel) {
        return;
    }
    struct Active;
    impl Drop for Active {
        fn drop(&mut self) {
            TERMINATION_ACTIVE.store(false, Ordering::Release);
        }
    }
    let _active = Active;
    if !TERMINATION_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let _message = ipc_message::SavedMessageBuffer::capture();
    let limit = object_waiter_len();
    for slot in 0..limit {
        let Some((id, record)) = object_waiter_record(slot) else {
            continue;
        };
        let ready = (&*core::ptr::addr_of!(OBJECT_WAITERS))
            .reply(id)
            .is_ok_and(|view| view.phase == Phase::Complete && view.teardown_requested);
        if !ready {
            continue;
        }
        if hosted_termination::reconcile(handler, queue, record.caller) {
            finish(handler, id);
        } else {
            TERMINATION_PENDING.store(true, Ordering::Release);
        }
    }
}
