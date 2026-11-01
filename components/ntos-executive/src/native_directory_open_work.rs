//! Retained native directory syscalls across exact Object Manager completion.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_address_space::copy::MemoryCopyFailure;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

use crate::exec_handler::directory_object::{DirectoryPublishProgress, ReservedDirectoryObjectOpen};
use crate::*;

const RETRY_100NS: u64 = 1_000_000;
const REPLY_ACK_RETRY_100NS: u64 = 10_000_000;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const MAX_PENDING_NATIVE_DIRECTORY_OPEN: usize = 64;

enum Phase {
    Start,
    CanonicalPending,
    LocalCommit,
    Copyout,
    Publish,
    InvalidateOutput { status: u32, cleanup_done: bool },
    Rollback,
    QuarantinedRollback,
    ReplyReady(u32),
    ReplyIndeterminate,
    Quarantined,
    Done,
}

/// The native syscall has no visible handle until its checked output copy succeeds.
/// Its original Reply and process/thread generation remain owned across every wait.
pub(crate) struct PendingNativeDirectoryOpen {
    reserved: ReservedDirectoryObjectOpen,
    reference: NativeThreadProcessReference,
    caller: NativeHandleCaller,
    pi: usize,
    tid: u64,
    badge: u64,
    output: u64,
    reply: u64,
    abandoned: bool,
    phase: Phase,
}

impl PendingNativeDirectoryOpen {
    pub(crate) fn new(
        reserved: ReservedDirectoryObjectOpen,
        reference: NativeThreadProcessReference,
        caller: NativeHandleCaller,
        pi: usize,
        tid: u64,
        badge: u64,
        output: u64,
    ) -> Self {
        Self { reserved, reference, caller, pi, tid, badge, output, reply: 0,
            abandoned: false, phase: Phase::Start }
    }
}

static mut PENDING: Vec<PendingNativeDirectoryOpen> = Vec::new();
static mut SELECTED: *mut PendingNativeDirectoryOpen = core::ptr::null_mut();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);

pub(crate) fn occupied() -> bool {
    ACTIVE.load(Ordering::Acquire)
        || unsafe { !(&*core::ptr::addr_of!(PENDING)).is_empty() }
}

/// Thread teardown changes transport ownership only when cancellation is proven. The
/// canonical transaction and captured Ps references remain in the retained work until
/// terminal cleanup, even if the original Reply can no longer be sent.
pub(crate) unsafe fn abandon_thread(tid: u64) {
    let selected = *core::ptr::addr_of!(SELECTED);
    if !selected.is_null() && (*selected).tid == tid {
        abandon_one(&mut *selected);
    }
    for work in (&mut *core::ptr::addr_of_mut!(PENDING)).iter_mut().filter(|work| work.tid == tid) {
        abandon_one(work);
    }
}

unsafe fn abandon_one(work: &mut PendingNativeDirectoryOpen) {
    work.abandoned = true;
    if work.reply != 0 && cancel_parked_reply_transport(work.reply) {
        release_reply_pool_cap(work.reply);
        work.reply = 0;
    }
    NEXT_RETRY.store(monotonic_time_100ns(), Ordering::Release);
}

/// Move an already reserved syscall into the Reply pool before any canonical effect.
/// Failure here is definite and leaves the ordinary syscall Reply available.
pub(crate) unsafe fn park(
    handler: &mut ExecNtHandler,
    mut work: PendingNativeDirectoryOpen,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let detached = usize::from(ACTIVE.load(Ordering::Acquire));
    let queue = &mut *core::ptr::addr_of_mut!(PENDING);
    if queue.len().saturating_add(detached) >= MAX_PENDING_NATIVE_DIRECTORY_OPEN
        || queue.try_reserve(1 + detached).is_err()
    {
        assert!(handler.abort_reserved_provider_directory_object(&mut work.reserved));
        work.reference.release(&mut handler.pm)
            .expect("unsubmitted native directory requestor reference");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        assert!(handler.abort_reserved_provider_directory_object(&mut work.reserved));
        work.reference.release(&mut handler.pm)
            .expect("unsubmitted native directory requestor reference");
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    work.reply = reply;
    (&mut *core::ptr::addr_of_mut!(PENDING)).push(work);
    reply_park.commit();
    thread_wait_state_park_badge_waiting(handler, (&*core::ptr::addr_of!(PENDING))
        .last().expect("parked native directory operation").badge);
    NEXT_RETRY.store(monotonic_time_100ns(), Ordering::Release);
    crate::service_sec_image::rearm_registered_active_delay_timer();
    Ok(())
}

unsafe fn settle_abandoned_reply(
    handler: &mut ExecNtHandler,
    work: &mut PendingNativeDirectoryOpen,
) -> bool {
    if work.reply != 0 {
        if !spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
            // A private Reply has no hosted ACK census. Its failed cancellation is uncertain;
            // retain the cap/reference without periodic polling or a second send.
            work.phase = Phase::Quarantined;
            return false;
        }
        if !matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.reply), Ok(true))
        {
            work.phase = Phase::ReplyIndeterminate;
            return false;
        }
        release_reply_pool_cap(work.reply);
        work.reply = 0;
    }
    thread_wait_state_clear_badge_ready(handler, work.badge);
    work.phase = if work.reference.release(&mut handler.pm).is_ok() {
        Phase::Done
    } else { Phase::Quarantined };
    true
}

unsafe fn step(handler: &mut ExecNtHandler, work: &mut PendingNativeDirectoryOpen) -> bool {
    if work.abandoned {
        match work.phase {
            Phase::Start => {
                work.phase = if handler.abort_reserved_provider_directory_object(&mut work.reserved) {
                    Phase::ReplyReady(nt_process::STATUS_INVALID_HANDLE)
                } else { Phase::Quarantined };
                return true;
            }
            Phase::CanonicalPending => {
                work.phase = match handler.canonical_poll_directory_object(&mut work.reserved) {
                    DirectoryPublishProgress::Pending => return false,
                    DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
                    DirectoryPublishProgress::Ready(_) => {
                        match handler.rollback_unpublished_directory_open(
                            &mut work.reserved, nt_process::STATUS_INVALID_HANDLE) {
                            DirectoryPublishProgress::Pending => Phase::Rollback,
                            DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
                            DirectoryPublishProgress::Ready(_) => Phase::Quarantined,
                        }
                    }
                };
                return true;
            }
            Phase::LocalCommit => {
                work.phase = match handler.rollback_unpublished_directory_open(
                    &mut work.reserved, nt_process::STATUS_INVALID_HANDLE) {
                    DirectoryPublishProgress::Pending => Phase::Rollback,
                    DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
                    DirectoryPublishProgress::Ready(_) => Phase::Quarantined,
                };
                return true;
            }
            Phase::Copyout | Phase::Publish => {
                // A prior checked write may have copied part or all of the numeric handle.
                // Closing the caller's Reply does not erase bytes in a still-live process.
                work.phase = match handler.rollback_unpublished_directory_open(
                    &mut work.reserved, nt_process::STATUS_INVALID_HANDLE) {
                    DirectoryPublishProgress::Pending => Phase::InvalidateOutput {
                        status: nt_process::STATUS_INVALID_HANDLE, cleanup_done: false,
                    },
                    DirectoryPublishProgress::Failed(status) => Phase::InvalidateOutput {
                        status, cleanup_done: true,
                    },
                    DirectoryPublishProgress::Ready(_) => Phase::QuarantinedRollback,
                };
                return true;
            }
            Phase::ReplyReady(_) | Phase::ReplyIndeterminate => {
                return settle_abandoned_reply(handler, work);
            }
            Phase::InvalidateOutput { .. } | Phase::Rollback | Phase::QuarantinedRollback
            | Phase::Quarantined | Phase::Done => {}
        }
    }
    match work.phase {
        Phase::Start => {
            if let Err(status) = work.reference.validate(&handler.pm) {
                work.phase = if handler.abort_reserved_provider_directory_object(&mut work.reserved) {
                    Phase::ReplyReady(status)
                } else {
                    Phase::Quarantined
                };
            } else if let Err(status) = handler.pm.validate_native_handle_caller(work.caller) {
                work.phase = if handler.abort_reserved_provider_directory_object(&mut work.reserved) {
                    Phase::ReplyReady(status)
                } else {
                    // An uncertain native reservation cannot be recycled or replied as failed.
                    Phase::Quarantined
                };
            } else {
                work.phase = match handler.canonical_publish_directory_object(
                    &mut work.reserved, work.caller,
                ) {
                    DirectoryPublishProgress::Ready(_) => Phase::LocalCommit,
                    DirectoryPublishProgress::Pending => Phase::CanonicalPending,
                    DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
                };
            }
            true
        }
        Phase::CanonicalPending => {
            work.phase = match handler.canonical_poll_directory_object(&mut work.reserved) {
                DirectoryPublishProgress::Ready(_) => Phase::LocalCommit,
                DirectoryPublishProgress::Pending => return false,
                DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
            };
            true
        }
        Phase::LocalCommit => {
            work.phase = match handler.commit_directory_local(&mut work.reserved) {
                DirectoryPublishProgress::Ready(_) => Phase::Copyout,
                DirectoryPublishProgress::Pending => Phase::Rollback,
                DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
            };
            true
        }
        Phase::Copyout => {
            match handler.process_memory_write_checked(work.pi, work.output,
                &work.reserved.value().to_le_bytes()) {
                Ok(()) => work.phase = Phase::Publish,
                Err(MemoryCopyFailure::Retry(_)) => return false,
                Err(MemoryCopyFailure::UserFault(status)) => {
                    work.phase = match handler.rollback_unpublished_directory_open(
                        &mut work.reserved, status,
                    ) {
                        DirectoryPublishProgress::Ready(_) => Phase::QuarantinedRollback,
                        DirectoryPublishProgress::Pending => Phase::InvalidateOutput {
                            status, cleanup_done: false,
                        },
                        DirectoryPublishProgress::Failed(status) => Phase::InvalidateOutput {
                            status, cleanup_done: true,
                        },
                    };
                }
            }
            true
        }
        Phase::Publish => {
            work.phase = match handler.publish_directory_local(&mut work.reserved) {
                DirectoryPublishProgress::Ready(status) => Phase::ReplyReady(status),
                DirectoryPublishProgress::Pending => Phase::InvalidateOutput {
                    status: work.reserved.rollback_failure_status()
                        .unwrap_or(nt_process::STATUS_INVALID_HANDLE),
                    cleanup_done: false,
                },
                DirectoryPublishProgress::Failed(status) => Phase::InvalidateOutput {
                    status, cleanup_done: true,
                },
            };
            true
        }
        Phase::InvalidateOutput { status, cleanup_done } => {
            match handler.process_memory_write_checked(work.pi, work.output, &0u64.to_le_bytes()) {
                Ok(()) => {
                    work.phase = if cleanup_done { Phase::ReplyReady(status) } else { Phase::Rollback };
                    true
                }
                Err(MemoryCopyFailure::Retry(_)) => false,
                Err(MemoryCopyFailure::UserFault(_)) => {
                    // The copied handle value may still be visible. Keep the exact Reply and
                    // reservation quarantined instead of returning a failure with stale output.
                    work.phase = if cleanup_done {
                        Phase::Quarantined
                    } else { Phase::QuarantinedRollback };
                    false
                }
            }
        }
        Phase::QuarantinedRollback => {
            work.phase = match handler.canonical_poll_directory_object(&mut work.reserved) {
                DirectoryPublishProgress::Pending => return false,
                DirectoryPublishProgress::Ready(_) | DirectoryPublishProgress::Failed(_) => {
                    Phase::Quarantined
                }
            };
            true
        }
        Phase::Rollback => {
            work.phase = match handler.canonical_poll_directory_object(&mut work.reserved) {
                DirectoryPublishProgress::Ready(_) => Phase::Quarantined,
                DirectoryPublishProgress::Pending => return false,
                DirectoryPublishProgress::Failed(status) => Phase::ReplyReady(status),
            };
            true
        }
        Phase::ReplyReady(status) => {
            let delivered = reply_parked_syscall(work.reply, status as u64)
                || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply)
                    && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                        work.reply), Ok(true)));
            if !delivered {
                work.phase = if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                    Phase::ReplyIndeterminate
                } else { Phase::Quarantined };
                return false;
            }
            release_reply_pool_cap(work.reply);
            thread_wait_state_clear_badge_ready(handler, work.badge);
            work.phase = if work.reference.release(&mut handler.pm).is_ok() {
                Phase::Done
            } else {
                // Reply is terminal, but the exact Ps reference could not retire. Keep its
                // owner row; a liveness check must never turn into an unsafe second release.
                Phase::Quarantined
            };
            true
        }
        Phase::ReplyIndeterminate => {
            if !spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(work.reply) {
                work.phase = Phase::Quarantined;
                return false;
            }
            if !matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                    work.reply), Ok(true))
            {
                return false;
            }
            release_reply_pool_cap(work.reply);
            thread_wait_state_clear_badge_ready(handler, work.badge);
            work.phase = if work.reference.release(&mut handler.pm).is_ok() {
                Phase::Done
            } else { Phase::Quarantined };
            true
        }
        Phase::Quarantined | Phase::Done => false,
    }
}

/// Progress one exact retained operation at a safe service-loop boundary.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) -> bool {
    if monotonic_time_100ns() < NEXT_RETRY.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel) {
        return false;
    }
    let queue = &mut *core::ptr::addr_of_mut!(PENDING);
    let len = queue.len();
    if len == 0 {
        ACTIVE.store(false, Ordering::Release);
        return false;
    }
    let start = (CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % len;
    let Some(index) = (0..len).map(|offset| (start + offset) % len).find(|&index|
        !matches!(queue[index].phase, Phase::Quarantined | Phase::Done)) else {
        ACTIVE.store(false, Ordering::Release);
        return false;
    };
    let mut work = queue.swap_remove(index);
    *core::ptr::addr_of_mut!(SELECTED) = &mut work;
    let mut progressed = false;
    for _ in 0..8 {
        let step_progressed = step(handler, &mut work);
        progressed |= step_progressed;
        if !step_progressed || matches!(work.phase, Phase::Quarantined | Phase::Done) {
            break;
        }
    }
    *core::ptr::addr_of_mut!(SELECTED) = core::ptr::null_mut();
    let done = matches!(work.phase, Phase::Done);
    if !done {
        (&mut *core::ptr::addr_of_mut!(PENDING)).push(work);
        let queue = &*core::ptr::addr_of!(PENDING);
        let active = queue.iter().any(|row| !matches!(row.phase,
            Phase::ReplyIndeterminate | Phase::Quarantined | Phase::Done));
        let delay = if active { RETRY_100NS } else { REPLY_ACK_RETRY_100NS };
        NEXT_RETRY.store(monotonic_time_100ns().saturating_add(delay), Ordering::Release);
    }
    ACTIVE.store(false, Ordering::Release);
    progressed
}

pub(crate) fn wake_due(now: u64) -> u64 {
    let runnable = unsafe { (&*core::ptr::addr_of!(PENDING)).iter().any(|work|
        !matches!(work.phase, Phase::Quarantined | Phase::Done)) };
    u64::from(runnable && now >= NEXT_RETRY.load(Ordering::Acquire))
}
