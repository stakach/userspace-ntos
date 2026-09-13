//! Retained APC delivery for a current syscall, independent of its mutable main Reply slot.

use crate::*;
use nt_thread_start::amd64_context::UserApcContinuation;
use nt_user_host::current_apc::{
    CurrentApcEffect as Effect, CurrentApcIdentity as Identity, CurrentApcOutcome as Outcome,
    CurrentApcPhase as Phase, CurrentApcTable,
};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

#[derive(Clone, Copy)]
struct Caller {
    logical: ProviderLogicalCaller,
    continuation: UserApcContinuation,
    return_status: u32,
}

struct Claim {
    identity: Identity,
    apc: nt_process::UserApcClaim,
    staged: bool,
    reply_sent: bool,
    released: bool,
}

static mut OWNERS: CurrentApcTable<Caller> = CurrentApcTable::new();
static mut CLAIMS: Vec<Option<Claim>> = Vec::new();
static RETRY_PENDING: AtomicBool = AtomicBool::new(false);
static TERMINATION_PENDING: AtomicBool = AtomicBool::new(false);
static TERMINATION_ACTIVE: AtomicBool = AtomicBool::new(false);
static FAILURES: AtomicU64 = AtomicU64::new(0);

unsafe fn claim_index(identity: Identity) -> Option<usize> {
    (&*core::ptr::addr_of!(CLAIMS)).iter().position(|entry| {
        entry
            .as_ref()
            .is_some_and(|entry| entry.identity == identity)
    })
}

pub(crate) fn owns_thread(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OWNERS))
            .has_owned_matching(|caller| u64::from(caller.logical.thread().thread_id()) == tid)
    }
}

pub(crate) fn has_thread(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OWNERS)).has_runtime_dependency_matching(|caller| {
            u64::from(caller.logical.thread().thread_id()) == tid
        })
    }
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(OWNERS)).has_runtime_dependency_matching(|caller| {
            caller.logical.pi() == pi
                && preserve_tid != Some(u64::from(caller.logical.thread().thread_id()))
        })
    }
}

pub(crate) unsafe fn request(
    handler: &mut ExecNtHandler,
    return_status: u32,
) -> Result<Option<Identity>, u32> {
    let tid = nt_process::ThreadId::try_from(handler.current_tid)
        .map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
    if owns_thread(handler.current_tid) {
        return Err(nt_process::STATUS_DEVICE_BUSY);
    }
    if handler.pm.peek_user_apc(tid).is_none() {
        return Ok(None);
    }
    let tcb = handler
        .hosted_thread_tcb(handler.current_tid)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let logical = handler
        .capture_provider_logical_caller(
            handler.pi,
            handler.current_tid,
            handler.current_badge,
            tcb,
        )
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let continuation = if handler.current_native_call_transport {
        UserApcContinuation::NativeCall
    } else {
        UserApcContinuation::Fault {
            resume_ip: handler.current_resume_ip,
            resume_sp: handler.current_sp,
            resume_flags: handler.current_flags,
        }
    };
    let claims = &mut *core::ptr::addr_of_mut!(CLAIMS);
    let vacant = claims.iter().position(Option::is_none);
    if vacant.is_none() {
        claims
            .try_reserve(1)
            .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    }
    let reservation = (&mut *core::ptr::addr_of_mut!(OWNERS))
        .reserve()
        .map_err(|_| nt_fs::STATUS_INSUFFICIENT_RESOURCES)?;
    let mut apc = match handler.pm.claim_user_apc(tid) {
        Ok(Some(apc)) => apc,
        result => {
            (&mut *core::ptr::addr_of_mut!(OWNERS))
                .cancel_reserved(reservation)
                .expect("unpublished current APC lost its reservation");
            return result.map(|_| None);
        }
    };
    assert_eq!(apc.lifetime(), logical.thread());
    // Reply pool growth invokes capabilities but cannot dispatch another executive caller.
    // Preserve the active syscall's IPC words even when a spare Reply must be created.
    let _message = ipc_message::SavedMessageBuffer::capture();
    let Some(reply_cap) = service_sec_image::steal_main_reply() else {
        handler
            .pm
            .release_user_apc_claim(&mut apc)
            .expect("unpublished current APC lost its PM claim");
        (&mut *core::ptr::addr_of_mut!(OWNERS))
            .cancel_reserved(reservation)
            .expect("unpublished current APC lost its reservation");
        return Err(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
    };
    let identity = (&mut *core::ptr::addr_of_mut!(OWNERS))
        .publish(
            reservation,
            Caller {
                logical,
                continuation,
                return_status,
            },
            reply_cap,
        )
        .expect("reserved current APC publication failed after Reply transfer");
    let entry = Some(Claim {
        identity,
        apc,
        staged: false,
        reply_sent: false,
        released: false,
    });
    if let Some(slot) = vacant {
        claims[slot] = entry;
    } else {
        claims.push(entry);
    }
    thread_wait_state_park_badge_waiting(handler, logical.badge());
    Ok(Some(identity))
}

pub(crate) unsafe fn request_thread(handler: &ExecNtHandler, tid: u64) {
    let mut found = false;
    for entry in (&*core::ptr::addr_of!(CLAIMS)).iter().flatten() {
        let view = (&*core::ptr::addr_of!(OWNERS))
            .get(entry.identity)
            .expect("current APC claim lost its core owner");
        if u64::from(view.payload.logical.thread().thread_id()) != tid {
            continue;
        }
        (&mut *core::ptr::addr_of_mut!(OWNERS))
            .request_teardown(entry.identity)
            .expect("current APC teardown lost its core owner");
        found = true;
    }
    if found {
        thread_wait_state_clear_tid(handler, tid);
        RETRY_PENDING.store(true, Ordering::Release);
    }
}

pub(crate) unsafe fn release_tail(handler: &mut ExecNtHandler, identity: Identity) {
    let Ok(view) = (&*core::ptr::addr_of!(OWNERS)).get(identity) else {
        return;
    };
    if view.phase == Phase::AwaitTail {
        (&mut *core::ptr::addr_of_mut!(OWNERS))
            .release_tail(identity)
            .expect("current APC tail lost its original handoff");
    }
    RETRY_PENDING.store(true, Ordering::Release);
    drive(handler, identity);
}

pub(crate) unsafe fn cancel_tail(handler: &mut ExecNtHandler, identity: Identity) {
    if (&*core::ptr::addr_of!(OWNERS)).get(identity).is_err() {
        return;
    }
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .request_teardown(identity)
        .expect("current APC cancelled tail lost its owner");
    release_tail(handler, identity);
}

unsafe fn stage(
    handler: &mut ExecNtHandler,
    identity: Identity,
    caller: Caller,
) -> Result<(), u32> {
    let slot = claim_index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let payload = {
        let claim = (&*core::ptr::addr_of!(CLAIMS))[slot].as_ref().unwrap();
        if claim.staged || claim.released || !handler.pm.validate_user_apc_claim(&claim.apc) {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        claim.apc.apc()
    };
    let install = user_apc::stage_frame(
        handler,
        caller.logical,
        payload,
        caller.continuation,
        caller.return_status,
    )?;
    let view = (&*core::ptr::addr_of!(OWNERS))
        .get(identity)
        .map_err(|_| nt_fs::STATUS_INVALID_HANDLE)?;
    let claim = (&*core::ptr::addr_of!(CLAIMS))[slot]
        .as_ref()
        .filter(|claim| claim.identity == identity)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    if view.teardown_requested {
        return Err(nt_fs::STATUS_CANCELLED);
    }
    if !matches!(
        view.phase,
        Phase::Invoking {
            effect: Effect::Stage,
            ..
        }
    ) || !handler.validate_provider_logical_caller(caller.logical)
        || !handler.pm.validate_user_apc_claim(&claim.apc)
    {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    thread_context::write(caller.logical.tcb(), &install, false)
        .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32)?;
    // Checked context installation and exact APC consumption have no intervening reentry.
    let claim = (&mut *core::ptr::addr_of_mut!(CLAIMS))[slot]
        .as_mut()
        .unwrap();
    handler
        .pm
        .commit_user_apc_claim(&mut claim.apc)
        .expect("installed current APC lost its exact queue claim");
    claim.staged = true;
    Ok(())
}

unsafe fn send(handler: &ExecNtHandler, identity: Identity, caller: Caller, cap: u64) -> Outcome {
    let Some(slot) = claim_index(identity) else {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    };
    let claim = (&*core::ptr::addr_of!(CLAIMS))[slot].as_ref().unwrap();
    if !claim.staged
        || claim.reply_sent
        || claim.released
        || !handler.validate_provider_logical_caller(caller.logical)
    {
        return Outcome::NotEntered(nt_fs::STATUS_INVALID_HANDLE);
    }
    if let Err(status) = parked_reply::validate_saved(cap) {
        return Outcome::NotEntered(status);
    }
    if !client_reply_on(cap, 0, 0, 0, 0, 0) {
        return Outcome::Indeterminate(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    (&mut *core::ptr::addr_of_mut!(CLAIMS))[slot]
        .as_mut()
        .unwrap()
        .reply_sent = true;
    Outcome::Completed(Effect::Send)
}

unsafe fn release_claim(handler: &mut ExecNtHandler, identity: Identity) -> Result<(), u32> {
    let slot = claim_index(identity).ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    let claim = (&mut *core::ptr::addr_of_mut!(CLAIMS))[slot]
        .as_mut()
        .unwrap();
    if claim.released {
        return Err(nt_fs::STATUS_INVALID_PARAMETER);
    }
    handler.pm.release_user_apc_claim(&mut claim.apc)?;
    claim.released = true;
    Ok(())
}

unsafe fn drive(handler: &mut ExecNtHandler, identity: Identity) {
    let _message = ipc_message::SavedMessageBuffer::capture();
    for _ in 0..8 {
        let Ok(view) = (&*core::ptr::addr_of!(OWNERS)).get(identity) else {
            return;
        };
        if view.phase == Phase::Complete {
            if view.teardown_requested {
                // A one-shot remote termination may have stopped at our earlier context barrier.
                // Keep the exact payload until the queue-owning service boundary retries it.
                TERMINATION_PENDING.store(true, Ordering::Release);
            } else {
                finish(handler, identity);
            }
            return;
        }
        if !matches!(view.phase, Phase::Ready { .. }) {
            return;
        }
        let Ok(mut attempt) = (&mut *core::ptr::addr_of_mut!(OWNERS)).begin_step(identity) else {
            RETRY_PENDING.store(true, Ordering::Release);
            return;
        };
        let effect = attempt.effect();
        let outcome = if effect == Effect::Send {
            send(handler, identity, view.payload, view.reply_cap)
        } else {
            let result = match effect {
                Effect::Stage => stage(handler, identity, view.payload),
                Effect::RetireSentReply => parked_reply::retire_sent(view.reply_cap),
                Effect::RevokeReply => parked_reply::revoke(view.reply_cap),
                Effect::RetypeReply => parked_reply::retype(view.reply_cap),
                Effect::ReleaseClaim => release_claim(handler, identity),
                Effect::Send => unreachable!(),
            };
            match result {
                Ok(()) => Outcome::Completed(effect),
                Err(status) => Outcome::NotEntered(status),
            }
        };
        (&mut *core::ptr::addr_of_mut!(OWNERS))
            .record_step(&mut attempt, outcome)
            .expect("current APC receipt lost its entered owner");
        match outcome {
            Outcome::Completed(_) => {}
            Outcome::NotEntered(status) | Outcome::Indeterminate(status) => {
                let uncertain = matches!(outcome, Outcome::Indeterminate(_));
                if !uncertain {
                    RETRY_PENDING.store(true, Ordering::Release);
                }
                if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
                    print_str(b"[current-apc] retained tid=");
                    print_u64(u64::from(view.payload.logical.thread().thread_id()));
                    print_str(b" effect=");
                    print_str(match effect {
                        Effect::Stage => b"stage",
                        Effect::Send => b"send",
                        Effect::RetireSentReply => b"retire-sent",
                        Effect::RevokeReply => b"revoke",
                        Effect::RetypeReply => b"retype",
                        Effect::ReleaseClaim => b"release-claim",
                    });
                    print_str(b" status=0x");
                    print_hex(status);
                    print_str(b" uncertain=");
                    print_u64(uncertain as u64);
                    print_str(b"\n");
                }
                return;
            }
        }
    }
    RETRY_PENDING.store(true, Ordering::Release);
}

unsafe fn finish(handler: &mut ExecNtHandler, identity: Identity) {
    let view = (&*core::ptr::addr_of!(OWNERS))
        .get(identity)
        .expect("completed current APC lost its retained owner");
    assert_eq!(view.phase, Phase::Complete);
    let slot = claim_index(identity).expect("completed current APC lost its PM owner");
    let claim = (&mut *core::ptr::addr_of_mut!(CLAIMS))[slot]
        .take()
        .unwrap();
    assert!(
        claim.released,
        "current APC retired before exact claim release"
    );
    if claim.reply_sent
        && !view.teardown_requested
        && handler.validate_provider_logical_caller(view.payload.logical)
    {
        thread_wait_state_clear_badge_ready(handler, view.payload.logical.badge());
    }
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .finish(identity)
        .expect("completed current APC lost its retained owner");
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
    let limit = (&*core::ptr::addr_of!(CLAIMS)).len();
    for index in 0..limit {
        let Some(identity) = (&*core::ptr::addr_of!(CLAIMS))[index]
            .as_ref()
            .map(|claim| claim.identity)
        else {
            continue;
        };
        let view = (&*core::ptr::addr_of!(OWNERS))
            .get(identity)
            .expect("current APC retirement lost its exact owner");
        if view.phase != Phase::Complete || !view.teardown_requested {
            continue;
        }
        let caller = view.payload.logical;
        let retired = hosted_termination::reconcile(handler, queue, caller);
        if retired {
            finish(handler, identity);
        } else {
            TERMINATION_PENDING.store(true, Ordering::Release);
        }
    }
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if !RETRY_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let mut after = None;
    let limit = (&*core::ptr::addr_of!(OWNERS)).capacity();
    while let Some(identity) = (&*core::ptr::addr_of!(OWNERS)).next_ready_after(after) {
        if identity.slot() >= limit {
            RETRY_PENDING.store(true, Ordering::Release);
            break;
        }
        after = Some(identity.slot());
        drive(handler, identity);
    }
}
