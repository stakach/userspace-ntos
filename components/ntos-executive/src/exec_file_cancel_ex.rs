//! `NtCancelIoFileEx`: cancel a process's requests on one File from any of its threads.

use super::*;

impl ExecNtHandler {
    /// `NtCancelIoFileEx(FileHandle, IoRequestToCancel, IoStatusBlock)`. Unlike `NtCancelIoFile`
    /// this selects requests issued by every thread of the calling process, optionally only the
    /// one whose IO_STATUS_BLOCK is `IoRequestToCancel`, and does not wait for them to complete:
    /// each cancelled request finishes through its own completion owner. Nothing selected is
    /// `STATUS_NOT_FOUND`.
    pub(super) unsafe fn nt_cancel_io_file_ex_service(&mut self, args: &[u64]) -> u32 {
        const STATUS_NOT_FOUND: u32 = 0xC000_0225;
        let file_handle = args[0];
        let request = (args[1] != 0).then_some(args[1]);
        let iosb = args[2];
        if iosb == 0 || !self.probe_user_output(iosb, 16) {
            return STATUS_ACCESS_VIOLATION;
        }
        let route = match self.cancel_target_for_handle(file_handle) {
            Ok(Some(file_id)) => PendingFileRoute::Hosted(file_id),
            Ok(None) => match self.local_file_object_for_handle(file_handle) {
                Ok(Some(file_object)) => PendingFileRoute::Local(file_object),
                Ok(None) => return STATUS_INVALID_HANDLE,
                Err(status) => return status,
            },
            Err(status) => return status,
        };
        let selected: alloc::vec::Vec<_> = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .process_file_requests(route, self.pi as u32, request)
            .collect();
        let mut cancelled = 0usize;
        let mut failure = None;
        for pending in selected.iter().copied() {
            let outcome = match pending.operation {
                nt_io_manager::PendingFileIoOperation::LocalByteLock(operation) => Ok(
                    nt_fs::ByteRangeWaitId::from_raw(operation.wait_id)
                        .is_some_and(|wait_id| self.byte_range_locks.cancel_wait(wait_id)),
                ),
                nt_io_manager::PendingFileIoOperation::LocalDirectoryNotify(operation) => {
                    match route.local_file_object() {
                        Some(file_object) => {
                            self.cancel_local_directory_notify(file_object, operation.notify_id)
                        }
                        None => Ok(false),
                    }
                }
                // These complete inline in the executive and expose no cancellation point.
                nt_io_manager::PendingFileIoOperation::OwnedInline(_)
                | nt_io_manager::PendingFileIoOperation::LocalBuffered(_)
                | nt_io_manager::PendingFileIoOperation::LocalFlush(_) => Ok(false),
                _ if pending.is_local() => Ok(false),
                _ => driver_launch::cancel_irp_if_pending(pending.irp_id),
            };
            match outcome {
                Ok(requested) => cancelled += requested as usize,
                // A request that could not be cancelled does not undo the ones that were.
                Err(status) => failure = failure.or(Some(status)),
            }
        }
        if cancelled != 0 {
            // Cancellation may complete inside the manager pump; make the completion owners
            // publish to the issuing threads without waiting for an unrelated event.
            self.publish_local_byte_lock_completions();
            crate::service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
            self.pipe_endpoint_progress = true;
        }
        let status = match (cancelled, failure) {
            (0, Some(status)) => status,
            (0, None) => STATUS_NOT_FOUND,
            _ => 0,
        };
        let _ = self.xas_try_write_buf(iosb, &status.to_le_bytes());
        let _ = self.xas_try_write_buf(iosb + 8, &0u64.to_le_bytes());
        print_str(b"[nt-cancel-io-file-ex] pi=");
        print_u64(self.pi as u64);
        print_str(b" tid=");
        print_u64(self.current_tid);
        print_str(b" handle=0x");
        print_hex(file_handle as u32);
        print_str(b" file=");
        crate::service_sec_image::print_pending_file_route(route);
        print_str(b" request=0x");
        print_hex((args[1] >> 32) as u32);
        print_hex(args[1] as u32);
        print_str(b" selected=");
        print_u64(selected.len() as u64);
        print_str(b" cancelled=");
        print_u64(cancelled as u64);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
        status
    }
}
