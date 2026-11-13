//! FileModeInformation is an executive-owned mutation, never a filesystem driver operation.

use super::*;

impl ExecNtHandler {
    pub(crate) unsafe fn commit_owned_file_mode_request(
        &mut self,
        route: PendingFileRoute,
        requested: u32,
        tid: u64,
    ) -> Result<(), driver_launch::FileModePreparationError> {
        match route {
            PendingFileRoute::Hosted(file_id) => {
                let device_id = driver_launch::owned_hosted_file_metadata(file_id)?.device_id.raw();
                let mut prepared = driver_launch::prepare_hosted_file_mode(file_id, device_id, requested)?;
                let previous = prepared.previous_io_mode()?;
                let next = prepared.next_io_mode()?;
                self.file_completion.update_io_mode_with(
                    file_id, device_id, tid, previous, next, || prepared.set_owned_file_mode(),
                ).map_err(Into::into)
            }
            PendingFileRoute::Local(LocalFileObject::Overlay(file_object)) => {
                crate::writable_fs::set_file_mode(file_object, requested).map_err(Into::into)
            }
            _ => Err(driver_launch::FileModePreparationError::Status(STATUS_INVALID_HANDLE)),
        }
    }

    pub(super) fn probe_file_mode_input_extent(&self, input: u64, length: usize) -> Result<(), u32> {
        if input & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if input == 0 || input.checked_add(length as u64)
            .is_none_or(|end| end > USER_ADDRESS_LIMIT)
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(())
    }

    /// The pending File owner has already admitted every page. This read cannot dispatch a
    /// provider or consume a guard; a lost resident backing is a terminal capture fault.
    pub(crate) unsafe fn capture_file_mode_resident_input(
        &mut self, input: u64, length: usize,
    ) -> Result<u32, u32> {
        let process = self.capture_thread_process_identity(self.pi, self.current_tid)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let payload = nt_io_manager::capture_set_information_payload(length, |payload| {
            let chunks = nt_address_space::page_chunks(input, length)
                .ok_or(nt_status::NtStatus::ACCESS_VIOLATION)?;
            let mut copied = 0usize;
            for chunk in chunks {
                self.copy_read_resident_page(self.pi, process,
                    chunk.page_base + chunk.page_offset as u64,
                    &mut payload[copied..copied + chunk.length])
                    .map_err(|status| nt_status::NtStatus(status as i32))?;
                copied += chunk.length;
            }
            Ok(())
        }).map_err(|status| status.raw() as u32)?;
        let value = payload.get(..4).and_then(|bytes| bytes.try_into().ok())
            .ok_or(nt_fs::STATUS_INFO_LENGTH_MISMATCH)?;
        Ok(u32::from_le_bytes(value))
    }

    pub(super) unsafe fn try_set_file_mode_information(
        &mut self,
        handle: u64,
        iosb: u64,
        input: u64,
        length: usize,
        information_class: u32,
        capture: Option<&file_capture::HostedFileCapture>,
    ) -> Option<u32> {
        if information_class != nt_fs::FILE_MODE_INFORMATION {
            return None;
        }
        let (wait_route, route, grant) = if let Some(capture) = capture {
            (
                nt_io_manager::FileIoWaitRoute::Hosted {
                    file_id: capture.route.file_id,
                    device_id: capture.route.device_id,
                    fs_context: capture.route.fs_context,
                },
                PendingFileRoute::Hosted(capture.route.file_id),
                capture.granted_access,
            )
        } else if let Some(retry) = self.synchronous_file_retry_for(handle) {
            let nt_io_manager::FileIoWaitRoute::LocalOverlay { file_object } = retry.route else {
                return Some(STATUS_INVALID_PARAMETER);
            };
            // A promoted FIFO operation owns its original route and grant even after handle close.
            (retry.route, PendingFileRoute::Local(LocalFileObject::Overlay(file_object)),
                retry.granted_access)
        } else {
            let local = match self.local_file_io_route_for(handle) {
                Ok(Some(local)) => local,
                Ok(None) => return Some(STATUS_INVALID_HANDLE),
                Err(status) => return Some(status),
            };
            let LocalFileObject::Overlay(file_object) = local.file_object else {
                // Legacy readonly bodies do not yet own the required synchronous Busy FIFO.
                // Do not bypass serialization or dispatch a fake filesystem mode operation.
                return Some(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
            };
            let Some(grant) = self.hosted_file_access_for(handle) else {
                return Some(STATUS_INVALID_HANDLE);
            };
            (
                nt_io_manager::FileIoWaitRoute::LocalOverlay { file_object },
                PendingFileRoute::Local(local.file_object),
                grant,
            )
        };
        let request_id = match self.reserve_local_file_io_delivery() {
            Ok(request_id) => request_id,
            Err(status) => return Some(status),
        };
        match self.prepare_owned_file_io(wait_route, handle, grant) {
            Ok(true) => {}
            Ok(false) => return Some(STATUS_PENDING),
            Err(status) => return Some(status),
        }
        assert!(self.pending_file_io_transfer.is_none());
        // The first page admission and File signal reset run only after the post-action parks
        // this exact Reply. No user read or mode mutation can escape the pending owner.
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            route,
            irp_id: request_id,
            major: major::IRP_MJ_SET_INFORMATION,
            operation: nt_io_manager::PendingFileIoOperation::OwnedModeInputCapture(
                nt_io_manager::PendingOwnedModeInputCapture {
                    input_va: input,
                    length,
                    next_page: input & !(nt_address_space::PAGE_SIZE - 1),
                    pending_page: 0,
                    pending_token: 0,
                    signal_reset: false,
                }),
            pi: self.pi as u32,
            tid: self.current_tid,
            badge: self.current_badge,
            iosb_va: iosb,
            signal_file: true,
            completion_port_suppressed: true,
            event_obj_idx: u64::MAX,
            ..nt_io_manager::PendingFileIo::default()
        });
        self.pending_file_io_wait = true;
        Some(STATUS_PENDING)
    }
}
