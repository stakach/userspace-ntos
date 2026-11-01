//! Detached directory handle cleanup and retained native directory effects.
//! Every removed PM handle already owns one cleanup credit, so enqueuing it
//! cannot allocate after the irreversible table removal.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_process::native_handle::{NativeDirectoryCloseReservation, NativeThreadProcessReference};
use nt_user_host::canonical_directory_backing::{BackingError, Publication};

use crate::*;

const RETRY_100NS: u64 = 1_000_000;
const ACK_RETRY_100NS: u64 = 10_000_000;

pub(crate) struct DetachedClose {
    pub(crate) identity: u64,
    pending: bool,
    quarantined: bool,
    canonical_done: bool,
    reply: Option<ReplyOwner>,
}

struct ReplyOwner {
    reference: NativeThreadProcessReference,
    tid: u64,
    badge: u64,
    cap: u64,
    indeterminate: bool,
}

impl DetachedClose {
    pub(crate) const fn new(identity: u64) -> Self {
        Self { identity, pending: false, quarantined: false, canonical_done: false, reply: None }
    }

    fn with_reply(identity: u64, reply: ReplyOwner) -> Self {
        Self { reply: Some(reply), ..Self::new(identity) }
    }
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static DETACHED_RETRY: AtomicU64 = AtomicU64::new(0);
static EFFECT_RETRY: AtomicU64 = AtomicU64::new(0);
static HAS_DETACHED: AtomicBool = AtomicBool::new(false);
static DETACHED_SCAN: AtomicU64 = AtomicU64::new(0);
static EFFECT_SCAN: AtomicU64 = AtomicU64::new(0);
static mut EFFECTS: alloc::vec::Vec<PendingNativeDirectoryEffect> = alloc::vec::Vec::new();

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectKind { Close, Temporary, Permanent }

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectPhase { Start, Poll, Reply(u32), ReplyIndeterminate, ReleaseReference, Quarantined, Done }

pub(crate) struct PendingNativeDirectoryEffect {
    kind: EffectKind,
    reservation: NativeDirectoryCloseReservation,
    reference: Option<NativeThreadProcessReference>,
    tid: u64,
    badge: u64,
    reply: u64,
    reply_indeterminate: bool,
    identity: u64,
    phase: EffectPhase,
}

impl PendingNativeDirectoryEffect {
    pub(crate) fn new(kind: EffectKind, reservation: NativeDirectoryCloseReservation,
        reference: NativeThreadProcessReference, tid: u64, badge: u64, identity: u64) -> Self {
        Self { kind, reservation, reference: Some(reference), tid, badge, reply: 0,
            reply_indeterminate: false,
            identity, phase: EffectPhase::Start }
    }
}

pub(crate) fn wake_now() {
    HAS_DETACHED.store(true, Ordering::Release);
    DETACHED_RETRY.store(monotonic_time_100ns(), Ordering::Release);
    unsafe { crate::service_sec_image::rearm_registered_active_delay_timer() };
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from((HAS_DETACHED.load(Ordering::Acquire)
        && now >= DETACHED_RETRY.load(Ordering::Acquire))
        || (unsafe {
        (&*core::ptr::addr_of!(EFFECTS)).iter()
            .any(|work| work.phase != EffectPhase::Quarantined)
    } && now >= EFFECT_RETRY.load(Ordering::Acquire)))
}

pub(crate) fn has_outstanding(handler: &ExecNtHandler) -> bool {
    handler.directory_cleanup.detached_len() != 0
        || unsafe { !(&*core::ptr::addr_of!(EFFECTS)).is_empty() }
}

fn schedule_detached(handler: &mut ExecNtHandler) {
    let mut any = false;
    let mut fast = false;
    for index in 0..handler.directory_cleanup.detached_len() {
        let row = handler.directory_cleanup.get_mut(index).unwrap();
        if row.quarantined { continue; }
        any = true;
        fast |= !row.canonical_done || row.reply.as_ref()
            .is_none_or(|reply| !reply.indeterminate || reply.cap == 0);
    }
    HAS_DETACHED.store(any, Ordering::Release);
    if any {
        DETACHED_RETRY.store(monotonic_time_100ns().saturating_add(
            if fast { RETRY_100NS } else { ACK_RETRY_100NS }), Ordering::Release);
    }
}

fn schedule_effects(queue: &[PendingNativeDirectoryEffect]) {
    let mut any = false;
    let mut fast = false;
    for work in queue {
        if work.phase == EffectPhase::Quarantined { continue; }
        any = true;
        fast |= work.phase != EffectPhase::ReplyIndeterminate;
    }
    if any {
        EFFECT_RETRY.store(monotonic_time_100ns().saturating_add(
            if fast { RETRY_100NS } else { ACK_RETRY_100NS }), Ordering::Release);
    }
}

/// Thread death drops transport ownership only. An already submitted canonical
/// operation keeps its requestor and directory identity until terminal proof.
pub(crate) unsafe fn abandon_thread(tid: u64) {
    for work in (&mut *core::ptr::addr_of_mut!(EFFECTS)).iter_mut().filter(|work| work.tid == tid) {
        if work.reply != 0 {
            if cancel_parked_reply_transport(work.reply) {
                release_reply_pool_cap(work.reply);
                work.reply = 0;
                if work.phase == EffectPhase::Start {
                    work.phase = EffectPhase::Reply(nt_process::STATUS_INVALID_HANDLE);
                } else if work.phase == EffectPhase::ReplyIndeterminate {
                    work.phase = EffectPhase::ReleaseReference;
                } else if work.phase == EffectPhase::Quarantined && work.reply_indeterminate {
                    work.phase = EffectPhase::ReleaseReference;
                }
            } else {
                // The transport may already have sent. Keep the exact Reply for ACK.
                work.reply_indeterminate = true;
                if work.phase != EffectPhase::Poll {
                    work.phase = EffectPhase::ReplyIndeterminate;
                }
            }
        }
    }
    // Detached NtClose has already removed the PM handle; only its Reply may go.
    // The canonical lease remains queued until the OM operation is terminal.
    // The caller passes the handler to the second loop below through the service hook.
}

pub(crate) unsafe fn abandon_detached_thread(handler: &mut ExecNtHandler, tid: u64) {
    for index in 0..handler.directory_cleanup.detached_len() {
        let Some(row) = handler.directory_cleanup.get_mut(index) else { continue; };
        let Some(reply) = row.reply.as_mut() else { continue; };
        if reply.tid != tid || reply.cap == 0 { continue; }
        if cancel_parked_reply_transport(reply.cap) {
            release_reply_pool_cap(reply.cap);
            reply.cap = 0;
            if row.canonical_done && row.quarantined {
                row.quarantined = false;
                wake_now();
            }
        } else {
            reply.indeterminate = true;
        }
    }
}

pub(crate) unsafe fn redrive_detached(handler: &mut ExecNtHandler) -> bool {
    if monotonic_time_100ns() < DETACHED_RETRY.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel) {
        return false;
    }
    let len = handler.directory_cleanup.detached_len();
    if len == 0 {
        HAS_DETACHED.store(false, Ordering::Release);
        ACTIVE.store(false, Ordering::Release);
        return false;
    }
    let start = (DETACHED_SCAN.fetch_add(1, Ordering::Relaxed) as usize) % len;
    let Some(index) = (0..len).map(|offset| (start + offset) % len)
        .find(|&index| handler.directory_cleanup.get_mut(index)
            .is_some_and(|row| !row.quarantined)) else {
        HAS_DETACHED.store(false, Ordering::Release);
        ACTIVE.store(false, Ordering::Release);
        return false;
    };
    let canonical_done = handler.directory_cleanup.get_mut(index).unwrap().canonical_done;
    if canonical_done {
        let reply_complete = if let Some(mut reply) = handler.directory_cleanup.get_mut(index).unwrap().reply.take() {
            let delivered = reply.cap == 0
                || (reply.indeterminate
                    && spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(reply.cap)
                    && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                        reply.cap), Ok(true)))
                || (!reply.indeterminate && (reply_parked_syscall(reply.cap, 0)
                    || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(reply.cap)
                        && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                            reply.cap), Ok(true)))));
            if delivered {
                if reply.cap != 0 { release_reply_pool_cap(reply.cap); }
                reply.cap = 0;
                thread_wait_state_clear_badge_ready(handler, reply.badge);
                if reply.reference.release(&mut handler.pm).is_err() {
                    handler.directory_cleanup.get_mut(index).unwrap().reply = Some(reply);
                    handler.directory_cleanup.get_mut(index).unwrap().quarantined = true;
                    ACTIVE.store(false, Ordering::Release);
                    return false;
                }
            } else {
                reply.indeterminate = true;
                handler.directory_cleanup.get_mut(index).unwrap().reply = Some(reply);
                if !spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(
                    handler.directory_cleanup.get_mut(index).unwrap().reply.as_ref().unwrap().cap) {
                    handler.directory_cleanup.get_mut(index).unwrap().quarantined = true;
                }
            }
            delivered
        } else { true };
        if reply_complete {
            handler.directory_cleanup.retire(index);
            HAS_DETACHED.store(handler.directory_cleanup.detached_len() != 0, Ordering::Release);
        }
        schedule_detached(handler);
        ACTIVE.store(false, Ordering::Release);
        return reply_complete;
    }
    let identity = handler.directory_cleanup.get_mut(index).unwrap().identity;
    let pending = handler.directory_cleanup.get_mut(index).unwrap().pending;
    let mut port = canonical_directory_port::CanonicalDirectoryPort::new();
    let result = if pending {
        handler.canonical_directories.poll_close(identity, &mut port)
    } else {
        handler.canonical_directories.release_local(identity, &mut port).map(Some)
    };
    let progressed = match result {
        Ok(Some(Publication::Ready)) => {
            handler.finish_detached_directory_close(identity);
            handler.directory_cleanup.get_mut(index).unwrap().canonical_done = true;
            if handler.directory_cleanup.get_mut(index).unwrap().reply.is_none() {
                handler.directory_cleanup.retire(index);
                HAS_DETACHED.store(handler.directory_cleanup.detached_len() != 0, Ordering::Release);
            }
            true
        }
        Ok(None) | Ok(Some(Publication::Pending)) => {
            handler.directory_cleanup.get_mut(index).unwrap().pending = true;
            false
        }
        Err(BackingError::NoEffect(_) | BackingError::InvalidPhase) if !pending => false,
        Err(BackingError::Terminal(_)) => {
            // The service definitively rejected this attempt; its original lease
            // remains bound and may be retried without replaying an uncertain call.
            handler.directory_cleanup.get_mut(index).unwrap().pending = false;
            false
        }
        Err(_) => {
            handler.directory_cleanup.get_mut(index).unwrap().quarantined = true;
            false
        }
    };
    schedule_detached(handler);
    ACTIVE.store(false, Ordering::Release);
    progressed
}

/// Queue admission and Reply rotation happen before any PM removal or Object Manager call.
pub(crate) unsafe fn park(handler: &mut ExecNtHandler,
    mut work: PendingNativeDirectoryEffect) -> Result<(), u32> {
    let queue = &mut *core::ptr::addr_of_mut!(EFFECTS);
    if queue.try_reserve(1).is_err() {
        work.reference.take().unwrap().release(&mut handler.pm)
            .expect("unsubmitted native directory effect reference");
        return Err(0xC000_009A);
    }
    let Some(park) = root_reply_park::RootReplyPark::prepare() else {
        work.reference.take().unwrap().release(&mut handler.pm)
            .expect("unsubmitted native directory effect reference");
        return Err(0xC000_009A);
    };
    work.reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(work.reply, 0);
    queue.push(work);
    park.commit();
    let work = queue.last().unwrap();
    thread_wait_state_park_badge_waiting(handler, work.badge);
    EFFECT_RETRY.store(monotonic_time_100ns(), Ordering::Release);
    crate::service_sec_image::rearm_registered_active_delay_timer();
    Ok(())
}

unsafe fn step_effect(handler: &mut ExecNtHandler, work: &mut PendingNativeDirectoryEffect) -> bool {
    match work.phase {
        EffectPhase::Start => {
            if let Err(status) = work.reference.as_ref().unwrap().validate(&handler.pm) {
                work.phase = EffectPhase::Reply(status);
                return true;
            }
            let required = if work.kind == EffectKind::Close { 0 } else { DELETE_ACCESS };
            match handler.pm.validate_reserved_native_directory(&work.reservation, required) {
                Ok(identity) if identity == work.identity => {}
                Ok(_) => { work.phase = EffectPhase::Reply(nt_process::STATUS_INVALID_HANDLE); return true; }
                Err(status) => { work.phase = EffectPhase::Reply(status); return true; }
            }
            if work.kind == EffectKind::Close {
                match handler.pm.close_reserved_native_directory(work.reservation) {
                    Ok(closed) => {
                        assert_eq!(closed.object(), nt_process::HandleObject::ObjectDirectory(work.identity));
                        driver_launch::driver_registry_value_transfers::cancel_closed_handle(
                            closed.table_owner(), closed.handle());
                        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
                        let owner = ReplyOwner { reference: work.reference.take().unwrap(),
                            tid: work.tid, badge: work.badge, cap: work.reply,
                            indeterminate: false };
                        handler.directory_cleanup.detach(DetachedClose::with_reply(work.identity, owner));
                        wake_now();
                        work.phase = EffectPhase::Done;
                        return true;
                    }
                    Err(nt_process::native_handle::NativeCloseError::Status(status)) => {
                        work.phase = EffectPhase::Reply(status);
                        return true;
                    }
                    Err(nt_process::native_handle::NativeCloseError::BugCheck { .. }) => {
                        panic!("protected kernel directory handle close")
                    }
                }
            }
            let mut port = canonical_directory_port::CanonicalDirectoryPort::new();
            let result = match work.kind {
                EffectKind::Temporary => handler.canonical_directories.make_temporary(work.identity, &mut port),
                EffectKind::Permanent => handler.canonical_directories.make_permanent(work.identity, &mut port),
                EffectKind::Close => unreachable!(),
            };
            match result {
                Ok(Publication::Ready) => match handler.finish_native_directory_permanence(
                    work.identity, work.kind == EffectKind::Permanent) {
                    Ok(()) => work.phase = EffectPhase::Reply(0),
                    Err(_) => work.phase = EffectPhase::Quarantined,
                },
                Ok(Publication::Pending) => work.phase = EffectPhase::Poll,
                Err(BackingError::NoEffect(_) | BackingError::InvalidPhase) => return false,
                Err(BackingError::Terminal(status)) => work.phase = EffectPhase::Reply(status),
                Err(_) => work.phase = EffectPhase::Quarantined,
            }
            true
        }
        EffectPhase::Poll => {
            let mut port = canonical_directory_port::CanonicalDirectoryPort::new();
            let result = match work.kind {
                EffectKind::Temporary => handler.canonical_directories.poll_make_temporary(work.identity, &mut port),
                EffectKind::Permanent => handler.canonical_directories.poll_make_permanent(work.identity, &mut port),
                EffectKind::Close => unreachable!(),
            };
            match result {
                Ok(Some(Publication::Ready)) => match handler.finish_native_directory_permanence(
                    work.identity, work.kind == EffectKind::Permanent) {
                    Ok(()) => work.phase = EffectPhase::Reply(0),
                    Err(_) => work.phase = EffectPhase::Quarantined,
                },
                Ok(None) | Ok(Some(Publication::Pending)) => return false,
                Err(BackingError::Terminal(status)) => work.phase = EffectPhase::Reply(status),
                Err(_) => work.phase = EffectPhase::Quarantined,
            }
            true
        }
        EffectPhase::Reply(status) => {
            let delivered = work.reply == 0
                || (!work.reply_indeterminate && reply_parked_syscall(work.reply, status as u64))
                || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply)
                    && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                        work.reply), Ok(true)));
            if !delivered {
                work.reply_indeterminate = true;
                work.phase = EffectPhase::ReplyIndeterminate;
                return false;
            }
            if work.reply != 0 { release_reply_pool_cap(work.reply); }
            work.reply = 0;
            thread_wait_state_clear_badge_ready(handler, work.badge);
            work.phase = EffectPhase::ReleaseReference;
            true
        }
        EffectPhase::ReplyIndeterminate => {
            if !spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                work.phase = EffectPhase::Quarantined;
                return false;
            }
            if !matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                    work.reply), Ok(true)) { return false; }
            release_reply_pool_cap(work.reply);
            work.reply = 0;
            thread_wait_state_clear_badge_ready(handler, work.badge);
            work.phase = EffectPhase::ReleaseReference;
            true
        }
        EffectPhase::ReleaseReference => {
            if work.reference.as_mut().unwrap().release(&mut handler.pm).is_err() {
                work.phase = EffectPhase::Quarantined;
                return false;
            }
            work.reference = None;
            work.phase = EffectPhase::Done;
            true
        }
        EffectPhase::Quarantined | EffectPhase::Done => false,
    }
}

pub(crate) unsafe fn redrive_effects(handler: &mut ExecNtHandler) -> bool {
    if monotonic_time_100ns() < EFFECT_RETRY.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel) { return false; }
    let queue = &mut *core::ptr::addr_of_mut!(EFFECTS);
    let len = queue.len();
    if len == 0 {
        ACTIVE.store(false, Ordering::Release);
        return false;
    }
    let start = (EFFECT_SCAN.fetch_add(1, Ordering::Relaxed) as usize) % len;
    let Some(index) = (0..len).map(|offset| (start + offset) % len)
        .find(|&index| queue[index].phase != EffectPhase::Quarantined) else {
        ACTIVE.store(false, Ordering::Release);
        return false;
    };
    let advanced = step_effect(handler, &mut queue[index]);
    if queue[index].phase == EffectPhase::Done { queue.swap_remove(index); }
    schedule_effects(queue);
    ACTIVE.store(false, Ordering::Release);
    advanced
}
