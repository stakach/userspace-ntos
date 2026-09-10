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
        let file_object = LOCAL_OVERLAY_FILE_OBJECT_TAG | (file_id & LOCAL_ID_PAYLOAD_MASK);
        let Some(access) = self.pm.handle_access(pid, process_handle) else {
            return Some(STATUS_INVALID_HANDLE);
        };
        if !nt_fs::file_flush_access_allowed(access, false) {
            return Some(STATUS_ACCESS_DENIED);
        }
        let Some(context) = self.loop_ctx else {
            return Some(STATUS_DEVICE_NOT_READY);
        };
        if let Err(status) = self.begin_local_file_io(file_object) {
            return Some(status);
        }
        let mut status = crate::service_sec_image::service_generic_section_writeback_file(
            &mut *context.generic_sections,
            file_id,
            context.scratch_base,
            Some(context),
        )
        .status;
        // Copyout may fault and revisit the memory owner: the table borrow must have ended.
        if !self.write_current_iosb(iosb, status, 0) {
            status = STATUS_ACCESS_VIOLATION;
        }
        // Flush has no event argument and completes synchronously even for an async open.
        let completion = self.signal_local_file_completion(file_object);
        assert_eq!(completion, nt_fs::STATUS_SUCCESS);
        self.release_local_file_io_reference(file_object);
        Some(status)
    }
}
