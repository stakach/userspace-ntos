//! Route retained File acquisition owners without crossing filesystem domains.

use super::*;
use nt_io_manager::{FileIoWaitKey, FileIoWaitRoute};

pub(super) unsafe fn try_synchronous_file_wake_next(
    nt_handler: &mut ExecNtHandler,
    key: FileIoWaitKey,
) -> Result<bool, u32> {
    let cancellation =
        (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).cancellation_ownership(key);
    if cancellation.promoted != 0 {
        // The retained cancellation still owns this grant and its eventual wake.
        return Ok(true);
    }
    if (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).has_promoted_for_file(key) {
        synchronous_file_retry::deliver_file(nt_handler, key);
        return Ok(true);
    }
    let next = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).oldest_waiting_for_file(key);
    let Some((slot, waiter)) = next else {
        return Ok(match key {
            FileIoWaitKey::Hosted(file_id) => {
                let waiters = nt_handler.file_completion.io_waiter_count(file_id)?;
                if waiters != 0 {
                    return if waiters as usize == cancellation.waiting {
                        Ok(true)
                    } else {
                        Err(nt_fs::STATUS_DATA_ERROR)
                    };
                }
                if nt_handler
                    .file_completion
                    .promote_cleanup_if_ready(file_id)?
                {
                    start_file_cleanup(nt_handler, file_id);
                    true
                } else {
                    false
                }
            }
            // nt-fs transitions already attempt ready cleanup. Failed preparation remains owned
            // for the service-loop cleanup barrier, not an invariant failure or a second close.
            FileIoWaitKey::LocalOverlay(file_id) => {
                let waiters = crate::writable_fs::file_io_waiter_count(file_id)?;
                if waiters != 0 {
                    return if waiters as usize == cancellation.waiting {
                        Ok(true)
                    } else {
                        Err(nt_fs::STATUS_DATA_ERROR)
                    };
                }
                false
            }
        });
    };
    match waiter.route {
        FileIoWaitRoute::Hosted { file_id, .. } => nt_handler
            .file_completion
            .promote_io_waiter(file_id, waiter.tid),
        FileIoWaitRoute::LocalOverlay { file_object } => {
            crate::writable_fs::promote_file_io_waiter(file_object, waiter.tid)
        }
    }?;
    (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
        .promote_exact(slot, key, waiter.tid)
        .expect("synchronous File FIFO promotion lost exact waiter");
    synchronous_file_retry::deliver_file(nt_handler, key);
    Ok(true)
}

/// A later Busy or retained cancellation owner inherits the outstanding FIFO wake. Accepted
/// promotion transfers delivery to the retry table, even when that Reply remains uncertain.
pub(super) unsafe fn settle_synchronous_file_wake(
    nt_handler: &mut ExecNtHandler,
    key: FileIoWaitKey,
) -> Result<(), u32> {
    if let FileIoWaitKey::Hosted(file_id) = key {
        let owner = nt_handler.file_completion.io_lock_owner(file_id)?;
        let grant = nt_handler.file_completion.io_grant_owner(file_id)?;
        let fifo = &*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS);
        let cancellation = fifo.cancellation_ownership(key);
        if grant.is_some() && !fifo.has_promoted_for_file(key) && cancellation.promoted == 0 {
            return Err(nt_fs::STATUS_DATA_ERROR);
        }
        if owner.is_some() && grant.is_none() {
            let waiters = nt_handler.file_completion.io_waiter_count(file_id)?;
            if waiters != 0
                && fifo.oldest_waiting_for_file(key).is_none()
                && waiters as usize != cancellation.waiting
            {
                return Err(nt_fs::STATUS_DATA_ERROR);
            }
            return Ok(());
        }
    }
    try_synchronous_file_wake_next(nt_handler, key).map(|_| ())
}

unsafe fn synchronous_file_wake_next(nt_handler: &mut ExecNtHandler, key: FileIoWaitKey) -> bool {
    try_synchronous_file_wake_next(nt_handler, key)
        .expect("synchronous File wake lost its policy owner")
}

/// Existing terminal/current-syscall ownership is still hosted-only. Local admission must not
/// activate until retained local completion carries its domain through checked Busy retirement.
pub(crate) unsafe fn synchronous_file_release_and_wake(
    nt_handler: &mut ExecNtHandler,
    file_id: u64,
    owner_tid: u64,
) -> bool {
    let release = nt_handler
        .file_completion
        .release_io(file_id, owner_tid)
        .expect("synchronous File lock released by a stale owner");
    let woke = synchronous_file_wake_next(nt_handler, FileIoWaitKey::Hosted(file_id));
    if release.waiters != 0 {
        assert!(woke, "synchronous File waiter count has no FIFO owner");
    }
    woke
}
