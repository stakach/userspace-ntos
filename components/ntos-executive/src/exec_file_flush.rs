//! Native local-file flush ownership and checked completion; hosted IRPs remain in their router.
use super::*;

impl ExecNtHandler {
    /// The caller probes IOSB before routing. None means a non-overlay handle owns the operation.
    pub(super) unsafe fn try_flush_overlay_file(&mut self, handle: u64, iosb: u64) -> Option<u32> {
        let process_handle = nt_process::Handle::try_from(handle).ok()?;
        let pid = self.pm_pid_for_pi(self.pi)?;
        let nt_process::HandleObject::OverlayFile(file_id) =
            self.pm.lookup_handle(pid, process_handle)?
        else {
            return None;
        };
        let file_object = LocalFileObject::Overlay(file_id);
        let Some(access) = self.pm.handle_access(pid, process_handle) else {
            return Some(STATUS_INVALID_HANDLE);
        };
        if !nt_fs::file_flush_access_allowed(access, false) {
            return Some(STATUS_ACCESS_DENIED);
        }
        let information = match crate::writable_fs::file_object_information(file_id) {
            Ok(information) => information,
            Err(status) => return Some(status),
        };
        let mode = if information.mode
            & (nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT)
            != 0
        {
            nt_io_manager::LocalFlushMode::SynchronousFile
        } else {
            nt_io_manager::LocalFlushMode::SynchronousApi
        };
        let Some(context) = self.loop_ctx else {
            return Some(STATUS_DEVICE_NOT_READY);
        };
        let request_id = match self.begin_retained_local_file_io(file_object) {
            Ok(request_id) => request_id,
            Err(status) => return Some(status),
        };
        let status = crate::service_sec_image::service_generic_section_writeback_file(
            &mut *context.generic_sections,
            file_id,
            context.scratch_base,
            Some(context),
        )
        .status;
        let completion = nt_io_manager::PendingLocalFlush::new(status, mode)
            .expect("local writeback unexpectedly returned a pending operation");
        // The backend has completed inline. This retained result is the kernel IOSB for the
        // synchronous-API mode; it needs no pending-driver event or user-visible File signal.
        assert!(self.pending_file_io_transfer.is_none());
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            route: PendingFileRoute::Local(file_object),
            irp_id: request_id,
            major: major::IRP_MJ_FLUSH_BUFFERS,
            operation: nt_io_manager::PendingFileIoOperation::LocalFlush(completion),
            pi: self.pi as u32,
            tid: self.current_tid,
            badge: self.current_badge,
            iosb_va: if completion.publishes_iosb() { iosb } else { 0 },
            signal_file: completion.signals_file(),
            completion_port_suppressed: true,
            event_obj_idx: u64::MAX,
            ..nt_io_manager::PendingFileIo::default()
        });
        self.pending_file_io_wait = true;
        Some(STATUS_PENDING)
    }
}
