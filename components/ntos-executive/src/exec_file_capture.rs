//! Retain an authenticated File route and access grant across reentrant user-memory access.

use super::*;

pub(super) struct HostedFileCapture {
    pub(super) route: HostedFileRoute,
    pub(super) granted_access: u32,
    _reference: Option<driver_launch::hosted_file_capture::Capture>,
}

fn file_transfer_access_mask(writing: bool) -> u32 {
    if writing {
        nt_fs::FILE_WRITE_DATA | nt_fs::FILE_APPEND_DATA
            | nt_security::GENERIC_WRITE | nt_security::GENERIC_ALL
    } else {
        nt_fs::FILE_READ_DATA | nt_security::GENERIC_READ | nt_security::GENERIC_ALL
    }
}

/// Scheduling observation only. The delivered syscall must repeat normal File capture before
/// queuing an IRP; this does not acquire a File reference or authorize provider entry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RootIngressReadRouteObservation {
    pub child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
    pub route: HostedFileRoute,
    pub granted_access: u32,
    pub mode: nt_io_completion::FileIoMode,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootIngressReadPreflight {
    Accepted(RootIngressReadRouteObservation),
    Unsupported,
    Changed,
}

impl ExecNtHandler {
    /// Classify a selected child from its exact runtime, never this handler's previous `pi`.
    /// Unknown routes are unsupported; a changed child or prior observation cannot be replayed.
    pub(crate) fn root_ingress_read_preflight(
        &self,
        child: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
        handle: u64,
        expected: Option<RootIngressReadRouteObservation>,
    ) -> RootIngressReadPreflight {
        use nt_user_host::process_identity::ProcessGeneration;
        let ProcessGeneration::Hosted(generation) = child.process.generation else {
            return RootIngressReadPreflight::Unsupported;
        };
        if self.hosted_process_generation(child.pi) != Some(generation)
            || self.capture_thread_process_identity(child.pi, child.tid) != Some(child.process)
            || !self.admit_hosted_thread_ingress(child.badge)
                .is_ok_and(|runtime| runtime.binding() == child)
        {
            return RootIngressReadPreflight::Changed;
        }
        let Some(pid) = self.pm_pid_for_pi(child.pi).filter(|pid| *pid == child.process.pid)
        else { return RootIngressReadPreflight::Changed; };
        let unsupported = if expected.is_some() {
            RootIngressReadPreflight::Changed
        } else {
            RootIngressReadPreflight::Unsupported
        };
        let Ok(typed_handle) = nt_process::Handle::try_from(handle) else { return unsupported; };
        let Some(granted_access) = self.pm.handle_access(pid, typed_handle) else {
            return unsupported;
        };
        if granted_access & file_transfer_access_mask(false) == 0 {
            return unsupported;
        }
        let Some(route) = self.hosted_file_route_for_pid(pid, handle) else { return unsupported; };
        let Ok(mode) = self.file_completion.io_mode(route.file_id) else { return unsupported; };
        if crate::driver_launch::registered_file_target(
            route.device_id, nt_io_abi::major::IRP_MJ_READ,
        ) != Ok(crate::driver_launch::RegisteredFileTarget::DriverPeer) {
            return unsupported;
        }
        let observed = RootIngressReadRouteObservation {
            child, route, granted_access, mode,
        };
        if expected.is_some_and(|prior| prior != observed) {
            RootIngressReadPreflight::Changed
        } else {
            RootIngressReadPreflight::Accepted(observed)
        }
    }

    /// Only fresh local requests may enter the local router. A promoted hosted request keeps
    /// its original grant even if the handle now names a local File or has already closed.
    pub(super) fn capture_hosted_file_unless_local(
        &self,
        handle: u64,
    ) -> Result<Option<HostedFileCapture>, u32> {
        self.capture_hosted_file_unless_local_with_access(handle, |_| true)
    }

    pub(super) fn capture_hosted_file_unless_local_with_access(
        &self,
        handle: u64,
        access_granted: impl Fn(nt_types::AccessMask) -> bool,
    ) -> Result<Option<HostedFileCapture>, u32> {
        if self.active_synchronous_file_retry.is_none()
            && self.local_file_object_for_handle(handle)?.is_some()
        {
            return Ok(None);
        }
        self.capture_hosted_file_with_access(handle, access_granted)
            .map(Some)
    }

    /// Read/write dispatch and pending publication share the original access and I/O mode.
    pub(super) fn capture_hosted_file_transfer(
        &self,
        handle: u64,
        writing: bool,
    ) -> Result<(HostedFileCapture, nt_io_completion::FileIoMode), u32> {
        let capture = self.capture_hosted_file(handle)?;
        let access_mask = file_transfer_access_mask(writing);
        if capture.granted_access & access_mask == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let mode = self.file_completion.io_mode(capture.route.file_id)?;
        Ok((capture, mode))
    }

    pub(super) fn capture_hosted_file(&self, handle: u64) -> Result<HostedFileCapture, u32> {
        self.capture_hosted_file_with_access(handle, |_| true)
    }

    /// Check File type and access before route support; retries use only their retained grant.
    pub(super) fn capture_hosted_file_with_access(
        &self,
        handle: u64,
        access_granted: impl Fn(nt_types::AccessMask) -> bool,
    ) -> Result<HostedFileCapture, u32> {
        if self.active_synchronous_file_retry.is_some() {
            let retry = self
                .synchronous_file_retry_for(handle)
                .ok_or(STATUS_INVALID_HANDLE)?;
            if !access_granted(nt_types::AccessMask::from_bits_retain(retry.granted_access)) {
                return Err(STATUS_ACCESS_DENIED);
            }
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
        let object = match self.pm.lookup_handle(pid, process_handle) {
            Some(
                object @ (nt_process::HandleObject::RoutedFile { .. }
                | nt_process::HandleObject::File(_)
                | nt_process::HandleObject::DiskFile { .. }
                | nt_process::HandleObject::Directory { .. }
                | nt_process::HandleObject::OverlayFile(_)),
            ) => object,
            Some(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
            None => return Err(STATUS_INVALID_HANDLE),
        };
        let granted_access = self
            .pm
            .handle_access(pid, process_handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !access_granted(nt_types::AccessMask::from_bits_retain(granted_access)) {
            return Err(STATUS_ACCESS_DENIED);
        }
        let nt_process::HandleObject::RoutedFile { file_id, device_id } = object else {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        };
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
