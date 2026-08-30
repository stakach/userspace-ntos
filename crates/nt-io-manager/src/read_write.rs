//! Read / write requests + the shared synchronous request path (spec §14, §17.3).
//!
//! A read or write references the client's File handle through the Object Manager
//! (access-checked), stages a buffered `SystemBuffer`, builds and dispatches an
//! `IRP_MJ_READ` / `IRP_MJ_WRITE`, and completes it. v0.1 uses the buffered model
//! (`METHOD_BUFFERED`) and completes synchronously.

use alloc::vec;
use alloc::vec::Vec;

use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, ObjectId};

use crate::dispatch::DispatchOutcome;
use crate::irp::{BufferAccess, IoBufferRef, IoParameters, IrpState, ReadWriteParameters};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, FileId, IoManager, IrpId};

pub const FILE_WRITE_TO_END_OF_FILE: i64 = -1;
pub const FILE_USE_FILE_POINTER_POSITION: i64 = -2;

/// Concrete offset selected by the I/O Manager for a regular local file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedFileOffset {
    Absolute(u64),
    Current(u64),
    EndOfFile(u64),
}

impl ResolvedFileOffset {
    pub const fn value(self) -> u64 {
        match self {
            Self::Absolute(value) | Self::Current(value) | Self::EndOfFile(value) => value,
        }
    }

    pub const fn advances_current_position(self) -> bool {
        matches!(self, Self::Current(_))
    }
}

/// Resolve `NtReadFile.ByteOffset` after the FILE_OBJECT mode is known. An asynchronous regular
/// file must supply an offset; the file-pointer sentinel is valid only for synchronous I/O.
pub fn resolve_regular_file_read_offset(
    byte_offset: Option<i64>,
    synchronous: bool,
    current: u64,
) -> Result<ResolvedFileOffset, NtStatus> {
    match byte_offset {
        None if synchronous => Ok(ResolvedFileOffset::Current(current)),
        None => Err(NtStatus::INVALID_PARAMETER),
        Some(FILE_USE_FILE_POINTER_POSITION) if synchronous => {
            Ok(ResolvedFileOffset::Current(current))
        }
        Some(value) if value >= 0 => Ok(ResolvedFileOffset::Absolute(value as u64)),
        Some(_) => Err(NtStatus::INVALID_PARAMETER),
    }
}

/// Resolve `NtWriteFile.ByteOffset` for a regular local file. Append-only access overrides the
/// caller's otherwise-valid offset, matching the I/O Manager's `FILE_APPEND_DATA` contract.
pub fn resolve_regular_file_write_offset(
    byte_offset: Option<i64>,
    synchronous: bool,
    current: u64,
    end_of_file: u64,
    append_only: bool,
) -> Result<ResolvedFileOffset, NtStatus> {
    if byte_offset.is_some_and(|value| value < FILE_USE_FILE_POINTER_POSITION) {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if append_only {
        return Ok(ResolvedFileOffset::EndOfFile(end_of_file));
    }
    match byte_offset {
        None if synchronous => Ok(ResolvedFileOffset::Current(current)),
        None => Err(NtStatus::INVALID_PARAMETER),
        Some(FILE_USE_FILE_POINTER_POSITION) if synchronous => {
            Ok(ResolvedFileOffset::Current(current))
        }
        Some(FILE_WRITE_TO_END_OF_FILE) => Ok(ResolvedFileOffset::EndOfFile(end_of_file)),
        Some(value) if value >= 0 => Ok(ResolvedFileOffset::Absolute(value as u64)),
        Some(_) => Err(NtStatus::INVALID_PARAMETER),
    }
}

/// Validate that a requested transfer can be represented by the NT `ULONG` length fields.
pub(crate) fn validate_transfer(len: usize) -> Result<(), NtStatus> {
    u32::try_from(len)
        .map(|_| ())
        .map_err(|_| NtStatus::INVALID_PARAMETER)
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Read from an open file into `out`, returning the byte count (spec §17.3).
    pub fn read(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        offset: u64,
        out: &mut [u8],
    ) -> Result<u64, NtStatus> {
        validate_transfer(out.len())?;
        let (file_id, device_id) =
            self.reference_open_file(client, handle, AccessMask::GENERIC_READ)?;
        let mut sysbuf: Vec<u8> = vec![0u8; out.len()];
        let params = IoParameters::Read(ReadWriteParameters {
            length: out.len() as u32,
            key: 0,
            offset,
        });
        let info = self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_READ,
            params,
            &mut sysbuf,
        )?;
        let n = (info as usize).min(out.len());
        out[..n].copy_from_slice(&sysbuf[..n]);
        Ok(info)
    }

    /// Write `data` to an open file, returning the byte count (spec §17.3).
    pub fn write(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, NtStatus> {
        validate_transfer(data.len())?;
        let (file_id, device_id) =
            self.reference_open_file(client, handle, AccessMask::GENERIC_WRITE)?;
        let mut sysbuf: Vec<u8> = data.to_vec();
        let params = IoParameters::Write(ReadWriteParameters {
            length: data.len() as u32,
            key: 0,
            offset,
        });
        self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_WRITE,
            params,
            &mut sysbuf,
        )
    }

    /// Flush an open file's buffers (`IRP_MJ_FLUSH_BUFFERS`, spec §17.1).
    pub fn flush(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let (file_id, device_id) = self.reference_open_file(client, handle, AccessMask::empty())?;
        let mut empty: [u8; 0] = [];
        self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_FLUSH_BUFFERS,
            IoParameters::FlushBuffers,
            &mut empty,
        )
        .map(|_| ())
    }

    // --- shared request path (used by read/write/device-control) -----------

    /// Reference a File by handle for `client` (access-checked via the Object
    /// Manager), returning its `FileId`. Does not constrain the file state — used
    /// by close, which runs after cleanup.
    pub(crate) fn reference_file(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        required_access: AccessMask,
    ) -> Result<FileId, NtStatus> {
        let file_object = self
            .port
            .reference_file_by_handle(client, handle, required_access)?;
        self.find_file_by_object(file_object)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    /// Reference an **open** File by handle for `client`, returning its
    /// `(FileId, DeviceId)`. The FileRecord must be in the `Open` state, else
    /// `STATUS_FILE_CLOSED` (spec §23.1).
    pub(crate) fn reference_open_file(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        required_access: AccessMask,
    ) -> Result<(FileId, DeviceId), NtStatus> {
        let file_id = self.reference_file(client, handle, required_access)?;
        let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        if !file.state.is_open() {
            return Err(NtStatus::FILE_CLOSED);
        }
        Ok((file_id, file.device_id))
    }

    /// Reference an open File by handle and return the canonical file/device/object identities.
    pub fn reference_open_file_details(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        required_access: AccessMask,
    ) -> Result<(FileId, DeviceId, ObjectId), NtStatus> {
        let (file_id, device_id) = self.reference_open_file(client, handle, required_access)?;
        let file_object = self
            .file(file_id)
            .ok_or(NtStatus::INVALID_HANDLE)?
            .object_id;
        Ok((file_id, device_id, file_object))
    }

    /// Build an IRP for `major` with `params` + `system_buffer`, dispatch it, and
    /// complete it synchronously, returning `IoStatus.Information`.
    pub(crate) fn build_and_dispatch_sync(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        major: u8,
        params: IoParameters,
        system_buffer: &mut [u8],
    ) -> Result<u64, NtStatus> {
        let (input_len, output_len) = params.buffered_lengths(system_buffer.len());
        self.build_and_dispatch_sync_with_transfer_buffers(
            client,
            device_id,
            file_id,
            major,
            params,
            input_len,
            output_len,
            system_buffer,
            None,
            None,
            None,
        )
    }

    pub(crate) fn build_and_dispatch_sync_with_transfer_buffers(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
        direct_buffer: Option<&mut [u8]>,
        type3_input_buffer: Option<&mut [u8]>,
        user_buffer: Option<&mut [u8]>,
    ) -> Result<u64, NtStatus> {
        let (irp_id, outcome) = self.build_and_dispatch_with_transfer_buffers(
            client,
            device_id,
            file_id,
            major,
            params,
            input_len,
            output_len,
            system_buffer,
            direct_buffer,
            type3_input_buffer,
            user_buffer,
        )?;
        self.complete_sync(irp_id, outcome)
    }

    pub(crate) fn build_and_dispatch_external_with_transfer_buffers(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
        direct_buffer: Option<&mut [u8]>,
        type3_input_buffer: Option<&mut [u8]>,
        user_buffer: Option<&mut [u8]>,
    ) -> Result<crate::ExternalDispatchResult, NtStatus> {
        let (irp_id, outcome) = self.build_and_dispatch_with_transfer_buffers(
            client,
            device_id,
            file_id,
            major,
            params,
            input_len,
            output_len,
            system_buffer,
            direct_buffer,
            type3_input_buffer,
            user_buffer,
        )?;
        Ok(self.complete_external_dispatch(irp_id, outcome))
    }

    fn build_and_dispatch_with_transfer_buffers(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        major: u8,
        params: IoParameters,
        input_len: u32,
        output_len: u32,
        system_buffer: &mut [u8],
        direct_buffer: Option<&mut [u8]>,
        type3_input_buffer: Option<&mut [u8]>,
        user_buffer: Option<&mut [u8]>,
    ) -> Result<(IrpId, Result<DispatchOutcome, NtStatus>), NtStatus> {
        let driver_id = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        let mut irp =
            self.build_irp_record(client, driver_id, device_id, file_id, major, params)?;
        let buffer_len = [
            system_buffer.len(),
            direct_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
            type3_input_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
            user_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
        .min(u32::MAX as usize) as u32;
        irp.buffer = Some(IoBufferRef {
            buffer_id: 0,
            offset: 0,
            len: buffer_len,
            input_len,
            output_len,
            access: BufferAccess::ReadWrite,
        });
        let irp_id = self.allocate_irp(irp)?;
        self.irp_mut(irp_id)
            .unwrap()
            .transition(IrpState::Initialized);
        self.irp_mut(irp_id)
            .unwrap()
            .transition(IrpState::Dispatched);
        let current_driver_id = self
            .irp(irp_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .current_stack()
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        let outcome = self.dispatch_to_driver_with_transfer_buffers(
            current_driver_id,
            irp_id,
            system_buffer,
            direct_buffer,
            type3_input_buffer,
            user_buffer,
        );
        Ok((irp_id, outcome))
    }

    /// Apply a synchronous dispatch outcome to `irp_id`, freeing it, and return
    /// the information count (or the error status).
    pub(crate) fn complete_sync(
        &mut self,
        irp_id: IrpId,
        outcome: Result<DispatchOutcome, NtStatus>,
    ) -> Result<u64, NtStatus> {
        if self
            .irp(irp_id)
            .map(|irp| irp.state != IrpState::Dispatched)
            .unwrap_or(true)
        {
            return Err(NtStatus::PENDING);
        }
        match outcome {
            Ok(DispatchOutcome::Completed {
                status,
                information,
                ..
            }) if status.is_success() => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.transition(IrpState::Completing);
                    irp.transition(IrpState::Completed);
                    irp.status = status;
                    irp.information = information;
                }
                self.free_irp(irp_id);
                Ok(information)
            }
            Ok(DispatchOutcome::Completed { status, .. }) => {
                self.fail_irp(irp_id, status);
                Err(status)
            }
            Ok(DispatchOutcome::Failed { status }) => {
                self.fail_irp(irp_id, status);
                Err(status)
            }
            Ok(DispatchOutcome::Pending) => {
                // v0.1 request paths are synchronous; the completion engine will
                // drive pending IRPs in a later milestone.
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.transition(IrpState::Pending);
                }
                Err(NtStatus::PENDING)
            }
            Err(status) => {
                self.fail_irp(irp_id, status);
                Err(status)
            }
        }
    }

    fn fail_irp(&mut self, irp_id: IrpId, status: NtStatus) {
        if let Some(irp) = self.irp_mut(irp_id) {
            irp.status = status;
            irp.transition(IrpState::Failed);
        }
        self.free_irp(irp_id);
    }

    fn find_file_by_object(&self, obj: ObjectId) -> Option<FileId> {
        self.files
            .iter()
            .find(|(_, f)| f.object_id == obj)
            .map(|(id, _)| id)
    }
}

#[cfg(test)]
mod offset_tests {
    use super::*;

    #[test]
    fn regular_read_offsets_require_nt_synchronous_file_pointer_semantics() {
        assert_eq!(
            resolve_regular_file_read_offset(None, true, 41),
            Ok(ResolvedFileOffset::Current(41))
        );
        assert_eq!(
            resolve_regular_file_read_offset(Some(-2), true, 42),
            Ok(ResolvedFileOffset::Current(42))
        );
        assert_eq!(
            resolve_regular_file_read_offset(Some(7), false, 42),
            Ok(ResolvedFileOffset::Absolute(7))
        );
        assert_eq!(
            resolve_regular_file_read_offset(None, false, 42),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            resolve_regular_file_read_offset(Some(-1), true, 42),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            resolve_regular_file_read_offset(Some(-2), false, 42),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn regular_write_offsets_distinguish_current_eof_and_append_only() {
        assert_eq!(
            resolve_regular_file_write_offset(None, true, 10, 20, false),
            Ok(ResolvedFileOffset::Current(10))
        );
        assert_eq!(
            resolve_regular_file_write_offset(Some(-2), true, 11, 20, false),
            Ok(ResolvedFileOffset::Current(11))
        );
        assert_eq!(
            resolve_regular_file_write_offset(Some(-1), false, 11, 21, false),
            Ok(ResolvedFileOffset::EndOfFile(21))
        );
        assert_eq!(
            resolve_regular_file_write_offset(Some(7), false, 11, 22, true),
            Ok(ResolvedFileOffset::EndOfFile(22))
        );
        assert_eq!(
            resolve_regular_file_write_offset(None, false, 11, 22, false),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            resolve_regular_file_write_offset(Some(-3), true, 11, 22, true),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }
}
