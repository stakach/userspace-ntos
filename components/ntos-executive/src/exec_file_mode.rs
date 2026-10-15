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
        if input.checked_add(length as u64)
            .is_none_or(|end| end > USER_ADDRESS_LIMIT)
        {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(())
    }

    unsafe fn capture_file_mode_input(&mut self, input: u64, length: usize) -> Result<u32, u32> {
        let payload = nt_io_manager::capture_set_information_payload(length, |payload| {
            let chunks = nt_address_space::page_chunks(input, length)
                .ok_or(nt_status::NtStatus::ACCESS_VIOLATION)?;
            for chunk in chunks {
                self.prepare_copy_page(self.pi, chunk.page_base, nt_address_space::FaultAccess::Read)
                    .map_err(|status| nt_status::NtStatus(status as i32))?;
            }
            self.read_file_mode_input_checked(input, payload)
                .map_err(|status| nt_status::NtStatus(status as i32))
        }).map_err(|status| status.raw() as u32)?;
        Ok(u32::from_le_bytes(payload[..4].try_into().unwrap()))
    }

    unsafe fn read_file_mode_input_checked(&self, input: u64, payload: &mut [u8]) -> Result<(), u32> {
        // Page preparation above preserves the first GUARD/NOACCESS refusal. Once every
        // page is admitted, failure to read its exact resident backing remains an AV.
        if self.xas_read(input, payload) { Ok(()) } else { Err(STATUS_ACCESS_VIOLATION) }
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
        let captured = (|| -> Result<u32, u32> {
            match wait_route {
                nt_io_manager::FileIoWaitRoute::Hosted { file_id, .. } => {
                    self.file_completion.set_signaled(file_id, false)?;
                }
                nt_io_manager::FileIoWaitRoute::LocalOverlay { file_object } => {
                    crate::writable_fs::set_file_signaled(file_object, false)?;
                }
            }
            self.capture_file_mode_input(input, length)
        })();
        let capture_failed = captured.is_err();
        let (operation, status) = match captured {
            Ok(requested) => match self.commit_owned_file_mode_request(route, requested, self.current_tid) {
                Err(driver_launch::FileModePreparationError::Busy) => (
                    nt_io_manager::PendingFileIoOperation::OwnedModePrecommit(
                        nt_io_manager::PendingOwnedModePrecommit { requested_mode: requested }),
                    STATUS_PENDING,
                ),
                result => {
                    let status = match result {
                        Ok(()) => nt_fs::STATUS_SUCCESS,
                        Err(driver_launch::FileModePreparationError::Status(status)) => status,
                        Err(driver_launch::FileModePreparationError::Busy) => unreachable!(),
                    };
                    (nt_io_manager::PendingFileIoOperation::OwnedInline(
                        nt_io_manager::PendingOwnedInline { status, information: 0 }), status)
                }
            },
            Err(status) => (nt_io_manager::PendingFileIoOperation::OwnedInline(
                nt_io_manager::PendingOwnedInline { status, information: 0 }), status),
        };
        let policy = nt_io_manager::SetInformationCompletionPolicy::immediate_driver();
        assert!(self.pending_file_io_transfer.is_none());
        // Publication precedes every user store. Its original result cannot replay the mutation.
        self.pending_file_io_transfer = Some(nt_io_manager::PendingFileIo {
            route,
            irp_id: request_id,
            major: major::IRP_MJ_SET_INFORMATION,
            operation,
            pi: self.pi as u32,
            tid: self.current_tid,
            badge: self.current_badge,
            iosb_va: if !capture_failed && (status == STATUS_PENDING || policy.publishes_iosb(status)) { iosb } else { 0 },
            signal_file: !capture_failed && (status == STATUS_PENDING || policy.signals_file(status)),
            completion_port_suppressed: true,
            event_obj_idx: u64::MAX,
            ..nt_io_manager::PendingFileIo::default()
        });
        self.pending_file_io_wait = true;
        Some(STATUS_PENDING)
    }
}
