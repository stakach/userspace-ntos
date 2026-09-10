//! Route retained File acquisition owners without crossing filesystem domains.

use super::*;
use nt_io_manager::{
    FileIoWaitKey, FileIoWaitRoute, SynchronousFileWaitState, SynchronousFileWaiter,
};

/// The caller has removed the exact FIFO owner or still owns an unpublished waiter.
/// Cancellation consumes the queued/granted reference according to its captured domain.
pub(crate) unsafe fn synchronous_file_cancel_waiter(
    nt_handler: &mut ExecNtHandler,
    waiter: SynchronousFileWaiter,
) {
    let remaining = match waiter.route {
        FileIoWaitRoute::Hosted { file_id, .. } => {
            let remaining = match waiter.state {
                SynchronousFileWaitState::Waiting => {
                    nt_handler.file_completion.cancel_io_waiter(file_id)
                }
                SynchronousFileWaitState::Promoted => nt_handler
                    .file_completion
                    .cancel_promoted_io(file_id, waiter.tid)
                    .map(|release| release.waiters),
            }
            .expect("File cancellation lost its hosted owner");
            nt_handler
                .release_hosted_file_waiter_reference(file_id)
                .expect("File cancellation lost its hosted reference");
            remaining
        }
        FileIoWaitRoute::LocalOverlay { file_object } => match waiter.state {
            SynchronousFileWaitState::Waiting => {
                crate::writable_fs::cancel_file_io_waiter(file_object)
            }
            SynchronousFileWaitState::Promoted => {
                crate::writable_fs::cancel_promoted_file_io(file_object, waiter.tid)
            }
        }
        .expect("File cancellation lost its local owner"),
    };
    if waiter.state == SynchronousFileWaitState::Promoted {
        // Local cancellation may have finished cleanup and retired the row when no waiter remains.
        // Hosted cleanup instead starts here after policy ownership becomes available.
        if remaining != 0 || matches!(waiter.key(), FileIoWaitKey::Hosted(_)) {
            let _ = synchronous_file_wake_next(nt_handler, waiter.key());
        }
    }
}

pub(super) unsafe fn try_synchronous_file_wake_next(
    nt_handler: &mut ExecNtHandler,
    key: FileIoWaitKey,
) -> Result<bool, u32> {
    if (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).has_promoted_for_file(key) {
        synchronous_file_retry::deliver_file(nt_handler, key);
        return Ok(true);
    }
    let next = (&*core::ptr::addr_of!(SYNCHRONOUS_FILE_WAITERS)).oldest_waiting_for_file(key);
    let Some((slot, waiter)) = next else {
        return Ok(match key {
            FileIoWaitKey::Hosted(file_id) => {
                if nt_handler.file_completion.io_waiter_count(file_id)? != 0 {
                    return Err(nt_fs::STATUS_DATA_ERROR);
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
                if crate::writable_fs::file_io_waiter_count(file_id)? != 0 {
                    return Err(nt_fs::STATUS_DATA_ERROR);
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
