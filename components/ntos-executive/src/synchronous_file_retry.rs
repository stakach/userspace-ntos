//! Retained synchronous File retry delivery, separate from File Busy ownership.

use super::*;
use nt_io_manager::{SynchronousFileRetryIdentity, SynchronousFileRetryOutcome,
    SynchronousFileRetryPhase, SynchronousFileWaiter};

static DELIVERED: AtomicU64 = AtomicU64::new(0);
static RETIRED: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);

fn report_failure(waiter: SynchronousFileWaiter, status: u32) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[file-retry] delivery retained file=");
        print_u64(waiter.file_id);
        print_str(b" tid=");
        print_u64(waiter.tid);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

unsafe fn send(waiter: SynchronousFileWaiter) -> bool {
    if waiter.native_call_transport {
        set_reply_mr(4, waiter.reply_mrs[4]);
        set_reply_mr(5, waiter.reply_mrs[5]);
        client_reply_on(waiter.reply_cap, 6, nt_syscall_abi::NT_NATIVE_RETRY_REPLY,
            waiter.reply_mrs[1], waiter.reply_mrs[2], waiter.reply_mrs[3])
    } else {
        for index in 4..15 {
            set_reply_mr(index, waiter.reply_mrs[index]);
        }
        set_reply_mr(15, waiter.retry_ip);
        set_reply_mr(16, waiter.resume_sp);
        set_reply_mr(17, waiter.resume_flags);
        client_reply_on(waiter.reply_cap, 18, u64::from(waiter.service_number),
            waiter.reply_mrs[1], waiter.reply_mrs[2], waiter.reply_mrs[3])
    }
}

unsafe fn retire_local(nt_handler: &mut ExecNtHandler, identity: SynchronousFileRetryIdentity) {
    let waiter = {
        let view = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS))
            .retry_delivery(identity).expect("File retry retirement lost its exact owner");
        assert!(matches!(view.phase, SynchronousFileRetryPhase::Acknowledged { .. }));
        *view.waiter
    };
    // No IPC, allocation or callbacks occur between local pool retirement and ownership ACK.
    let local = match wait_reply_pool_mut().iter_mut()
        .find(|record| record.cap == waiter.reply_cap && record.used)
    {
        Some(record) => { record.used = false; Ok(()) }
        None => Err(0xC000_0008),
    };
    let retired = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
        .finish_retry(identity, local).expect("File retry local ACK lost its owner");
    if retired {
        RETIRED.fetch_add(1, Ordering::Relaxed);
        thread_wait_state_clear_badge_ready(nt_handler, waiter.badge);
    } else {
        report_failure(waiter, local.unwrap_err());
    }
}

pub(super) unsafe fn deliver_file(nt_handler: &mut ExecNtHandler, file_id: u64) {
    let Some(identity) = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS))
        .next_retry_for_file(file_id) else { return; };
    let phase = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS))
        .retry_delivery(identity).expect("selected File retry disappeared").phase;
    if matches!(phase, SynchronousFileRetryPhase::Acknowledged { .. }) {
        retire_local(nt_handler, identity);
        return;
    }
    let mut attempt = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
        .begin_retry(identity).expect("selected File retry changed before entry");
    let waiter = attempt.waiter();
    // The exact attempt stays owned by the table; no mutable global borrow crosses Reply.
    // Unknown capability ownership is a blocked invariant, not permission to send or recycle it.
    let result = if !wait_reply_pool_ref().iter()
        .any(|record| record.cap == waiter.reply_cap && record.used)
    {
        Err(0xC000_0008)
    } else if send(waiter) {
        Ok(())
    } else {
        Err(0xC000_0001)
    };
    (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS)).record_retry(&mut attempt,
        match result {
            Ok(()) => SynchronousFileRetryOutcome::Acknowledged,
            Err(status) => SynchronousFileRetryOutcome::Indeterminate(status),
        }).expect("File retry outcome lost its entered owner");
    if let Err(status) = result {
        report_failure(waiter, status);
        return;
    }
    DELIVERED.fetch_add(1, Ordering::Relaxed);
    retire_local(nt_handler, identity);
}

pub(super) fn counters() -> (u64, u64, u64) {
    (DELIVERED.load(Ordering::Relaxed), RETIRED.load(Ordering::Relaxed),
        FAILURES.load(Ordering::Relaxed))
}

/// Retry acknowledged local cleanup only. Failed/abandoned Reply is never selected for replay.
pub(super) unsafe fn redrive_local(nt_handler: &mut ExecNtHandler) {
    let mut previous_file = None;
    while let Some(identity) = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS))
        .next_acknowledged_retry_after(previous_file)
    {
        previous_file = Some((&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS))
            .retry_delivery(identity).expect("File local retry disappeared").waiter.file_id);
        retire_local(nt_handler, identity);
    }
}
