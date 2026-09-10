//! Retained pending-File Busy release, followed by independently retryable wake work.

use super::*;
use nt_io_manager::{FileIoBusyOwner, FileIoWaitKey, PendingFileIo};

static FAILURES: AtomicU64 = AtomicU64::new(0);

fn report_failure(stage: &[u8], owner: FileIoBusyOwner, status: u32) {
    if FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[file-busy] retained ");
        print_str(stage);
        print_str(b" file=");
        match owner.key {
            FileIoWaitKey::Hosted(file_id) => {
                print_str(b"hosted/");
                print_u64(file_id);
            }
            FileIoWaitKey::LocalOverlay(file_id) => {
                print_str(b"overlay/");
                print_u64(file_id);
            }
        }
        print_str(b" tid=");
        print_u64(owner.tid);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
}

/// This transition neither invokes IPC nor releases the operation's independent File reference.
unsafe fn release_policy(
    nt_handler: &mut ExecNtHandler,
    owner: FileIoBusyOwner,
) -> Result<u32, u32> {
    match owner.key {
        FileIoWaitKey::Hosted(file_id) => {
            if nt_handler.file_completion.io_mode(file_id)? != owner.mode {
                return Err(nt_fs::STATUS_INVALID_PARAMETER);
            }
            nt_handler
                .file_completion
                .release_io(file_id, owner.tid)
                .map(|release| release.waiters)
        }
        // Local routes are typed, but shape validation still rejects Busy until retained
        // cancellation/rollback and the complete local admission lifecycle are implemented.
        FileIoWaitKey::LocalOverlay(_) => Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST),
    }
}

pub(super) unsafe fn release_if_ready(
    nt_handler: &mut ExecNtHandler,
    slot: usize,
    pending: PendingFileIo,
) {
    let Some(live) = (&*core::ptr::addr_of!(PENDING_FILE_IO))
        .get(slot)
        .filter(|live| live.irp_id == pending.irp_id)
    else {
        return;
    };
    let Some(busy) = live.busy.filter(|busy| busy.release_pending()) else {
        return;
    };
    let mut attempt = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
        .begin_busy_release_exact(slot, pending.irp_id)
        .expect("pending File release lost its exact ready owner");
    let result = release_policy(nt_handler, busy.owner());
    // No reentrant work occurs between policy release and recording its consumed receipt.
    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
        .record_busy_release(&mut attempt, result)
        .expect("pending File release outcome lost its entered owner");
    if let Err(status) = result {
        report_failure(b"release", busy.owner(), status);
    }
    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
}

/// Run outside the pending snapshot walk; return newly settled owners needing a finish pass.
pub(super) unsafe fn redrive_wakes(nt_handler: &mut ExecNtHandler) -> usize {
    let mut settled = 0;
    let mut previous = None;
    while let Some((slot, pending)) =
        (&*core::ptr::addr_of!(PENDING_FILE_IO)).next_busy_wake_after(previous)
    {
        previous = Some(slot);
        let busy = pending
            .busy
            .expect("pending File wake has no captured owner");
        let mut attempt = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
            .begin_busy_wake_exact(slot, pending.irp_id)
            .expect("pending File wake lost its exact ready owner");
        let result =
            synchronous_file_wait::settle_synchronous_file_wake(nt_handler, busy.owner().key);
        (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
            .record_busy_wake(&mut attempt, result)
            .expect("pending File wake outcome lost its entered owner");
        if let Err(status) = result {
            report_failure(b"wake", busy.owner(), status);
        } else {
            settled += 1;
        }
        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    }
    settled
}
