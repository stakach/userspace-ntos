//! Retain an authenticated File route and access grant across reentrant user-memory access.

use super::*;

pub(super) struct HostedFileCapture {
    pub(super) route: HostedFileRoute,
    pub(super) granted_access: u32,
    _reference: Option<driver_launch::hosted_file_capture::Capture>,
}

impl ExecNtHandler {
    /// Read/write dispatch and pending publication share the original access and I/O mode.
    pub(super) fn capture_hosted_file_transfer(
        &self,
        handle: u64,
        writing: bool,
    ) -> Result<(HostedFileCapture, nt_io_completion::FileIoMode), u32> {
        let capture = self.capture_hosted_file(handle)?;
        let access_mask = if writing {
            nt_fs::FILE_WRITE_DATA
                | nt_fs::FILE_APPEND_DATA
                | nt_security::GENERIC_WRITE
                | nt_security::GENERIC_ALL
        } else {
            nt_fs::FILE_READ_DATA | nt_security::GENERIC_READ | nt_security::GENERIC_ALL
        };
        if capture.granted_access & access_mask == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mode = self.file_completion.io_mode(capture.route.file_id)?;
        Ok((capture, mode))
    }

    pub(super) fn capture_hosted_file(&self, handle: u64) -> Result<HostedFileCapture, u32> {
        if self.active_synchronous_file_retry.is_some() {
            let retry = self
                .synchronous_file_retry_for(handle)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let nt_io_manager::FileIoWaitRoute::Hosted {
                file_id,
                device_id,
                fs_context,
            } = retry.route
            else {
                return Err(STATUS_INVALID_DEVICE_REQUEST);
            };
            // The exact promoted waiter already holds the reference and Busy grant. Its
            // ingress owner, not this borrowed view, owns adoption or cancellation.
            return Ok(HostedFileCapture {
                route: HostedFileRoute {
                    file_id,
                    device_id,
                    fs_context,
                },
                granted_access: retry.granted_access,
                _reference: None,
            });
        }

        let process_handle =
            nt_process::Handle::try_from(handle).map_err(|_| STATUS_INVALID_HANDLE)?;
        let pid = self.pm_pid_for_pi(self.pi).ok_or(STATUS_INVALID_HANDLE)?;
        let (file_id, device_id) = match self.pm.lookup_handle(pid, process_handle) {
            Some(nt_process::HandleObject::RoutedFile { file_id, device_id }) => {
                (file_id, device_id)
            }
            Some(nt_process::HandleObject::DiskFile { .. })
            | Some(nt_process::HandleObject::Directory { .. })
            | Some(nt_process::HandleObject::OverlayFile(_)) => {
                return Err(STATUS_INVALID_DEVICE_REQUEST);
            }
            Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => return Err(STATUS_INVALID_HANDLE),
        };
        let granted_access = self
            .pm
            .handle_access(pid, process_handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        // These lookups and the canonical retain below are memory-only; no handle-table
        // mutation can interleave between the authenticated object and access snapshot.
        let reference =
            driver_launch::hosted_file_capture::capture(file_id, device_id, granted_access)?;
        Ok(HostedFileCapture {
            route: HostedFileRoute {
                file_id: reference.file_id(),
                device_id: reference.device_id(),
                fs_context: reference.fs_context(),
            },
            granted_access: reference.granted_access(),
            _reference: Some(reference),
        })
    }
}
