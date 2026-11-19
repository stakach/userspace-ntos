//! File-object admission for `NtQuerySecurityObject` / `NtSetSecurityObject`.
//!
//! NT sends these to the file's device as `IRP_MJ_QUERY_SECURITY` /
//! `IRP_MJ_SET_SECURITY`. This module answers only what the driver's dispatch
//! table says about that major; `nt_security` owns what the I/O manager does with
//! a driver that has none.
use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

/// A driver that does implement the security major cannot be reached yet; report
/// the first few so a boot log names the device instead of a silent failure.
static UNDISPATCHED_REPORTS: AtomicU32 = AtomicU32::new(0);
const UNDISPATCHED_REPORT_LIMIT: u32 = 8;

impl ExecNtHandler {
    /// `None`: the handle is not a file object. Otherwise the status the file's
    /// driver gives the security `major`, after the handle's own access check.
    pub(super) fn file_security_driver_status(
        &self,
        handle: u64,
        required_access: u32,
        major: u8,
    ) -> Option<u32> {
        let process_handle = nt_process::Handle::try_from(handle).ok()?;
        let pid = self.pm_pid_for_pi(self.pi)?;
        let object = self.pm.lookup_handle(pid, process_handle)?;
        let device_id = match object {
            nt_process::HandleObject::RoutedFile { device_id, .. } => Some(device_id),
            // Files of the executive's own volume backends have no device stack.
            nt_process::HandleObject::File(_)
            | nt_process::HandleObject::DiskFile { .. }
            | nt_process::HandleObject::OverlayFile(_) => None,
            _ => return None,
        };
        let Some(granted) = self.pm.handle_access(pid, process_handle) else {
            return Some(STATUS_INVALID_HANDLE);
        };
        if granted & required_access != required_access {
            return Some(STATUS_ACCESS_DENIED);
        }
        let Some(device_id) = device_id else {
            return Some(STATUS_INVALID_DEVICE_REQUEST);
        };
        match driver_launch::registered_file_target(device_id, major) {
            Err(status) => Some(status),
            Ok(_) => {
                if UNDISPATCHED_REPORTS.fetch_add(1, Ordering::Relaxed) < UNDISPATCHED_REPORT_LIMIT {
                    crate::print_str(b"[file-security-undispatched] pi=");
                    crate::print_u64(self.pi as u64);
                    crate::print_str(b" tid=");
                    crate::print_u64(self.current_tid);
                    crate::print_str(b" device=");
                    crate::print_u64(device_id);
                    crate::print_str(b" major=");
                    crate::print_u64(major as u64);
                    crate::print_str(b" status=0xc0000002\n");
                }
                Some(0xC000_0002) // STATUS_NOT_IMPLEMENTED
            }
        }
    }
}
