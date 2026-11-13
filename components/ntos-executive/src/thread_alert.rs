//! Native per-thread alert flag and exact retained reply ownership.

use crate::*;
use nt_user_host::thread_alert::{ParkedWait, ThreadAlerts, ThreadKey, WaitDecision, WakeStatus};

static mut ALERTS: ThreadAlerts = ThreadAlerts::new();

fn key(handler: &ExecNtHandler, tid: u64) -> Result<ThreadKey, u32> {
    let tid = nt_process::ThreadId::try_from(tid).map_err(|_| nt_process::STATUS_INVALID_CID)?;
    let lifetime = handler
        .pm
        .thread_lifetime(tid)
        .ok_or(nt_process::STATUS_INVALID_CID)?;
    Ok(ThreadKey {
        process_id: lifetime.process_id(),
        thread_id: lifetime.thread_id(),
        generation: lifetime.generation(),
    })
}

pub(super) unsafe fn alert(handler: &ExecNtHandler, tid: u64) -> u32 {
    let target = match key(handler, tid) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let Some(caller_pid) = handler.pm_pid_for_pi(handler.pi) else {
        return nt_process::STATUS_INVALID_CID;
    };
    if target.process_id != caller_pid {
        return nt_process::STATUS_ACCESS_DENIED;
    }
    match (&mut *core::ptr::addr_of_mut!(ALERTS)).alert(target) {
        Ok(()) => 0,
        Err(()) => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
    }
}

pub(super) unsafe fn begin_wait(handler: &mut ExecNtHandler, timeout_ptr: u64) -> u32 {
    let current = match key(handler, handler.current_tid) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let interval = match handler.wait_timeout_interval(timeout_ptr) {
        Ok(interval) => interval,
        Err(status) => return status,
    };
    let now = nt_time_snapshot();
    let deadline = nt_delay_execution::Deadline::from_nt_timeout(interval, now);
    match (&mut *core::ptr::addr_of_mut!(ALERTS)).begin_wait(current, deadline, now) {
        Ok(WaitDecision::Alerted) => 0x101,
        Ok(WaitDecision::TimedOut) => 0x102,
        Ok(WaitDecision::Park) => {
            handler.thread_alert_wait = Some(deadline);
            0x102
        }
        Err(()) => nt_fs::STATUS_INSUFFICIENT_RESOURCES,
    }
}

pub(super) unsafe fn park(
    handler: &mut ExecNtHandler,
    deadline: nt_delay_execution::Deadline,
    reply_cap: u64,
) -> bool {
    let Ok(key) = key(handler, handler.current_tid) else {
        return false;
    };
    if reply_cap == 0 {
        return false;
    }
    let Some(tcb) = handler.hosted_thread_tcb(handler.current_tid) else {
        return false;
    };
    let Some(caller) = handler.capture_provider_logical_caller(
        handler.pi,
        handler.current_tid,
        handler.current_badge,
        tcb,
    ) else {
        return false;
    };
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return false;
    };
    if (&mut *core::ptr::addr_of_mut!(ALERTS))
        .park(ParkedWait {
            key,
            caller,
            process_index: handler.pi,
            badge: handler.current_badge,
            reply_cap,
            deadline,
        })
        .is_err()
    {
        return false;
    }
    reply_park.commit();
    thread_wait_state_mark_badge_waiting(handler, handler.current_badge);
    true
}

pub(super) unsafe fn redrive(handler: &mut ExecNtHandler) -> u64 {
    let alerts = &mut *core::ptr::addr_of_mut!(ALERTS);
    alerts.expire_due(nt_time_snapshot());
    let mut completed = 0;
    while let Some((waiter, status)) = alerts.ready() {
        if key(handler, u64::from(waiter.key.thread_id)) != Ok(waiter.key) {
            // Teardown must first prove the target TCB stopped before releasing its Reply.
            alerts.finish_reply(waiter.key, false);
            break;
        }
        let current = handler.capture_provider_logical_caller(
            waiter.process_index,
            u64::from(waiter.key.thread_id),
            waiter.badge,
            waiter.caller.tcb(),
        );
        if !waiter.matches_caller(current) {
            // A busy published runtime may later re-admit this caller. Preserve its Reply.
            break;
        }
        let status = match status {
            WakeStatus::Alerted => 0x101,
            WakeStatus::TimedOut => 0x102,
        };
        let acknowledged = reply_parked_syscall(waiter.reply_cap, status);
        alerts.finish_reply(waiter.key, acknowledged);
        if acknowledged {
            release_reply_pool_cap(waiter.reply_cap);
            thread_wait_state_clear_badge_ready(handler, waiter.badge);
            completed += 1;
        }
    }
    completed
}

pub(super) unsafe fn next_deadline(now: nt_time::TimeSnapshot) -> Option<u64> {
    (&*core::ptr::addr_of!(ALERTS)).next_deadline(now)
}

pub(super) unsafe fn cancel_thread(handler: &ExecNtHandler, tid: u64) -> bool {
    let Some(key) = nt_process::ThreadId::try_from(tid)
        .ok()
        .and_then(|tid| handler.pm.thread_lifetime(tid))
        .map(|lifetime| ThreadKey {
            process_id: lifetime.process_id(),
            thread_id: lifetime.thread_id(),
            generation: lifetime.generation(),
        })
    else {
        return true;
    };
    let alerts = &mut *core::ptr::addr_of_mut!(ALERTS);
    if let Some(waiter) = alerts.parked(key) {
        if !cancel_parked_reply_transport(waiter.reply_cap) {
            return false;
        }
        release_reply_pool_cap(waiter.reply_cap);
        thread_wait_state_clear_badge(waiter.badge);
    }
    alerts.cancel(key);
    !alerts.has_thread_id(key.thread_id)
}
