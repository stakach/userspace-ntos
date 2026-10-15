//! Scalar capture and exact completion-Event ownership across File Busy acquisition.

use super::*;
use nt_io_manager::{FileTransferEvent, FileTransferParameters};
use nt_kernel_exec::EventLeaseKind;

pub(super) fn validate_transfer_input_extent(address: u64, length: usize, alignment: u64) -> Result<(), u32> {
    nt_compat_exports::memory::validate_user_probe(address, length as u64, alignment)
        .map_err(|error| match error {
            nt_compat_exports::memory::UserProbeError::DatatypeMisalignment => 0x8000_0002,
            _ => STATUS_ACCESS_VIOLATION,
        })
}

impl ExecNtHandler {
    pub(super) fn retained_file_transfer_parameters(
        &self,
        handle: u64,
        route: Option<HostedFileRoute>,
    ) -> Result<Option<FileTransferParameters>, u32> {
        if self.active_synchronous_file_retry.is_none() {
            return Ok(None);
        }
        let waiter = self.synchronous_file_retry_for(handle).ok_or(STATUS_INVALID_PARAMETER)?;
        let route = route.ok_or(STATUS_INVALID_PARAMETER)?;
        if waiter.route != (nt_io_manager::FileIoWaitRoute::Hosted {
            file_id: route.file_id, device_id: route.device_id, fs_context: route.fs_context,
        }) || self.file_completion.io_mode(route.file_id)? != waiter.mode {
            return Err(STATUS_INVALID_PARAMETER);
        }
        waiter.transfer_parameters
            .map(Some)
            .ok_or(STATUS_INVALID_PARAMETER)
    }

    fn validate_transfer_event(&self, event: FileTransferEvent) -> Result<usize, u32> {
        let id = self.event_objects.event_for_lease(event.lease, EventLeaseKind::Operation)
            .map_err(|_| STATUS_INVALID_HANDLE)?;
        let snapshot = self.event_objects.snapshot(id).map_err(|_| STATUS_INVALID_HANDLE)?;
        if id != event.id || snapshot.native_identity != event.native_identity {
            return Err(STATUS_INVALID_HANDLE);
        }
        usize::try_from(event.native_identity).map_err(|_| STATUS_INVALID_HANDLE)
    }

    /// Reset only on original admission. A promoted request uses its retained Event, not a handle.
    pub(super) fn prepare_transfer_event(
        &mut self,
        file_handle: u64,
        event_handle: u64,
    ) -> Result<Option<usize>, u32> {
        if self.active_synchronous_file_retry.is_some() {
            let waiter = self.synchronous_file_retry_for(file_handle).ok_or(STATUS_INVALID_PARAMETER)?;
            return waiter.transfer_event.map(|event| self.validate_transfer_event(event)).transpose();
        }
        assert!(self.current_file_transfer_event.is_none());
        let Some(handle) = nt_io_completion::normalize_io_event_handle(event_handle) else {
            return Ok(None);
        };
        let (id, index) = self.event_object_for_handle_in_pi(self.pi, handle, EVENT_MODIFY_STATE)?;
        let lease = self.event_objects.acquire_wait(id, EventLeaseKind::Operation)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let event = FileTransferEvent { id, lease, native_identity: index as u64 };
        // Publish ownership before the signal mutation. No process-handle lookup follows this.
        self.current_file_transfer_event = Some(event);
        self.events.reset_existing(index as u64).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(Some(index))
    }

    pub(crate) fn release_transfer_event(&mut self, event: FileTransferEvent) {
        self.validate_transfer_event(event).expect("File transfer lost its exact Event lease");
        if let Some(retired) = self.event_objects.release_wait(event.lease, EventLeaseKind::Operation)
            .expect("File transfer consumed its Event lease twice")
        {
            self.finalize_retired_event_object(retired);
        }
    }

    pub(crate) fn release_current_transfer_event(&mut self) {
        if let Some(event) = self.current_file_transfer_event.take() {
            self.release_transfer_event(event);
        }
        self.current_file_transfer_parameters = None;
    }
}
