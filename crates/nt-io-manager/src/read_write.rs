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

    /// Position follows completed synchronous data transfer, not the source of its offset.
    /// Admission failures and zero-length requests do not move it. A late output fault does not
    /// undo accepted bytes; callers invoke this once at the backing-transfer completion boundary.
    pub fn completion_position(
        self,
        synchronous: bool,
        requested: usize,
        status: u32,
        transferred: usize,
    ) -> Result<Option<u64>, NtStatus> {
        if transferred > requested {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if !synchronous
            || requested == 0
            || (transferred == 0 && status != 0 && status != 0xc000_0011)
        {
            return Ok(None);
        }
        self.value()
            .checked_add(transferred as u64)
            .map(Some)
            .ok_or(NtStatus::INVALID_PARAMETER)
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

/// The `ByteOffset` an NtReadFile/NtWriteFile IRP carries (NT5 read.c/write.c, ReactOS iofunc.c).
/// Append-only access gives drivers `FILE_WRITE_TO_END_OF_FILE`. A synchronous File transferred
/// without a ByteOffset uses its file pointer, which only the FILE_OBJECT's owner knows: the IRP
/// carries `FILE_USE_FILE_POINTER_POSITION` for that owner to resolve. An asynchronous File has
/// no file pointer to use, so it must supply an offset unless it is a pipe or mailslot.
pub fn transfer_irp_byte_offset(
    byte_offset: Option<i64>,
    synchronous: bool,
    append_only: bool,
    pipe_or_mailslot: bool,
) -> Result<u64, NtStatus> {
    if byte_offset.is_none() && !synchronous && !pipe_or_mailslot {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if append_only {
        return Ok(FILE_WRITE_TO_END_OF_FILE as u64);
    }
    Ok(match byte_offset {
        Some(value) => value as u64,
        None if synchronous => FILE_USE_FILE_POINTER_POSITION as u64,
        None => 0,
    })
}

/// Resolve the file-pointer sentinel where the FILE_OBJECT lives, before any driver sees it: a
/// synchronous File's transfer uses its `CurrentByteOffset` (NT5 read.c/write.c). An asynchronous
/// File's sentinel reaches its driver unchanged.
pub const fn resolve_file_object_byte_offset(
    irp_offset: u64,
    synchronous_file: bool,
    current_byte_offset: u64,
) -> u64 {
    if synchronous_file && irp_offset == FILE_USE_FILE_POINTER_POSITION as u64 {
        current_byte_offset
    } else {
        irp_offset
    }
}

/// Whether a completed transfer moves the File's `CurrentByteOffset`. A synchronous File's
/// position follows its transfers, but paging I/O never moves it (ReactOS vfatfs rw.c, NT5
/// fastfat read.c/write.c: `SynchronousIo && !PagingIo`).
pub const fn transfer_moves_file_position(
    synchronous_file: bool,
    request_flags: crate::irp_request_flags::IrpRequestFlags,
) -> bool {
    synchronous_file && !request_flags.is_paging_io()
}

/// Bytes a paging write may transfer. Paging I/O never extends a file (NT5 fastfat write.c):
/// a write starting at or beyond EOF transfers nothing and one crossing it is clipped.
pub fn paging_write_length(offset: u64, length: usize, end_of_file: u64) -> usize {
    let available = end_of_file.saturating_sub(offset);
    usize::try_from(available).map_or(length, |available| length.min(available))
}

/// Resolve `NtWriteFile.ByteOffset` for a regular local file. Append-only access overrides the
/// caller's captured offset value for buffered I/O. Asynchronous files still require a pointer.
pub fn resolve_regular_file_write_offset(
    byte_offset: Option<i64>,
    synchronous: bool,
    current: u64,
    end_of_file: u64,
    append_only: bool,
) -> Result<ResolvedFileOffset, NtStatus> {
    if byte_offset.is_none() && !synchronous {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    if append_only {
        return Ok(ResolvedFileOffset::EndOfFile(end_of_file));
    }
    if byte_offset.is_some_and(|value| value < FILE_USE_FILE_POINTER_POSITION) {
        return Err(NtStatus::INVALID_PARAMETER);
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
    /// Dispatch a kernel-built, File-less READ to exactly `device_id`.
    ///
    /// The caller owns `output` until terminal delivery. A pending result keeps the
    /// canonical IRP alive; consume its output with `copy_completed_irp_output`
    /// before `acknowledge_completed_irp_strict`.
    pub fn read_exact_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<crate::ExternalDispatchResult, NtStatus> {
        validate_transfer(output.len())?;
        let flags = self.device(device_id).ok_or(NtStatus::INVALID_PARAMETER)?.flags;
        let mut empty = [];
        let params = IoParameters::Read(ReadWriteParameters {
            length: output.len() as u32,
            key: 0,
            offset,
        });
        if flags.contains(crate::DeviceFlags::BUFFERED_IO) {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client, device_id, None, major::IRP_MJ_READ, params, 0,
                output.len() as u32, output, None, None, None,
            )
        } else if flags.contains(crate::DeviceFlags::DIRECT_IO) {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client, device_id, None, major::IRP_MJ_READ, params, 0,
                output.len() as u32, &mut empty, Some(output), None, None,
            )
        } else {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client, device_id, None, major::IRP_MJ_READ, params, 0,
                output.len() as u32, &mut empty, None, None, Some(output),
            )
        }
    }

    /// Dispatch a kernel-built, File-less WRITE to exactly `device_id`.
    /// `input` is copied into request-owned transfer storage before driver entry.
    pub fn write_exact_device(
        &mut self,
        client: ClientId,
        device_id: DeviceId,
        offset: u64,
        input: &[u8],
    ) -> Result<crate::ExternalDispatchResult, NtStatus> {
        validate_transfer(input.len())?;
        let flags = self.device(device_id).ok_or(NtStatus::INVALID_PARAMETER)?.flags;
        let params = IoParameters::Write(ReadWriteParameters {
            length: input.len() as u32,
            key: 0,
            offset,
        });
        let mut transfer = Vec::new();
        transfer
            .try_reserve_exact(input.len())
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        transfer.extend_from_slice(input);
        let mut empty = [];
        if flags.contains(crate::DeviceFlags::BUFFERED_IO) {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client, device_id, None, major::IRP_MJ_WRITE, params,
                input.len() as u32, 0, &mut transfer, None, None, None,
            )
        } else if flags.contains(crate::DeviceFlags::DIRECT_IO) {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client, device_id, None, major::IRP_MJ_WRITE, params,
                input.len() as u32, 0, &mut empty, Some(&mut transfer), None, None,
            )
        } else {
            self.build_and_dispatch_external_to_exact_device_with_transfer_buffers(
                client, device_id, None, major::IRP_MJ_WRITE, params,
                input.len() as u32, 0, &mut empty, None, None, Some(&mut transfer),
            )
        }
    }

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
            false,
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
            false,
        )?;
        Ok(self.complete_external_dispatch(irp_id, outcome))
    }

    /// Dispatch a kernel-built request beginning at the exact supplied device object.
    pub(crate) fn build_and_dispatch_external_to_exact_device_with_transfer_buffers(
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
            true,
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
        exact_device: bool,
    ) -> Result<(IrpId, Result<DispatchOutcome, NtStatus>), NtStatus> {
        let driver_id = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        let mut irp = if exact_device {
            self.build_irp_record_at_device(client, device_id, file_id, major, params)?
        } else {
            self.build_irp_record(client, driver_id, device_id, file_id, major, params)?
        };
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
        let captured_input_len = input_len as usize;
        if let Some(input) = system_buffer.get(..captured_input_len).or_else(|| {
            type3_input_buffer
                .as_deref()
                .and_then(|buffer| buffer.get(..captured_input_len))
        }) {
            irp.set_request_input_fingerprint(input);
        }
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
    fn paging_transfers_never_move_the_file_position() {
        use crate::irp_request_flags::{IrpRequestFlags, PagingTransfer};
        // ReactOS vfatfs rw.c and NT5 fastfat read.c/write.c: `SynchronousIo && !PagingIo`.
        assert!(transfer_moves_file_position(true, IrpRequestFlags::NONE));
        assert!(!transfer_moves_file_position(false, IrpRequestFlags::NONE));
        for transfer in [
            PagingTransfer::Read,
            PagingTransfer::SynchronousWrite,
            PagingTransfer::AsynchronousWrite,
        ] {
            assert!(!transfer_moves_file_position(true, IrpRequestFlags::paging(transfer)));
            assert!(!transfer_moves_file_position(false, IrpRequestFlags::paging(transfer)));
        }
    }

    #[test]
    fn paging_writes_never_extend_the_file() {
        // NT5 fastfat write.c: a paging write is clipped to FileSize, never extending it.
        assert_eq!(paging_write_length(0, 0x1000, 0x1800), 0x1000);
        assert_eq!(paging_write_length(0x1000, 0x1000, 0x1800), 0x800);
        assert_eq!(paging_write_length(0x1800, 0x1000, 0x1800), 0);
        assert_eq!(paging_write_length(0x9000, 0x1000, 0x1800), 0);
        assert_eq!(paging_write_length(u64::MAX, 0x1000, u64::MAX), 0);
    }

    #[test]
    fn completion_position_uses_file_mode_not_offset_source() {
        for offset in [
            ResolvedFileOffset::Current(50),
            ResolvedFileOffset::Absolute(50),
            ResolvedFileOffset::EndOfFile(50),
        ] {
            assert_eq!(offset.completion_position(true, 10, 0, 4), Ok(Some(54)));
            assert_eq!(offset.completion_position(false, 10, 0, 4), Ok(None));
        }
    }

    #[test]
    fn completion_distinguishes_zero_request_eof_and_failed_transfer() {
        let offset = ResolvedFileOffset::Absolute(50);
        assert_eq!(offset.completion_position(true, 0, 0, 0), Ok(None));
        assert_eq!(
            offset.completion_position(true, 10, 0xc000_0011, 0),
            Ok(Some(50))
        );
        assert_eq!(
            offset.completion_position(true, 10, 0xc000_0005, 0),
            Ok(None)
        );
        assert_eq!(
            offset.completion_position(true, 10, 0xc000_0005, 3),
            Ok(Some(53))
        );
    }

    #[test]
    fn completion_rejects_impossible_progress_or_offset_overflow() {
        assert_eq!(
            ResolvedFileOffset::Absolute(50).completion_position(true, 10, 0, 11),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            ResolvedFileOffset::Current(u64::MAX).completion_position(true, 1, 0, 1),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn buffered_append_ignores_offset_value_but_async_requires_offset_pointer() {
        assert_eq!(
            resolve_regular_file_write_offset(None, false, 10, 20, true),
            Err(NtStatus::INVALID_PARAMETER)
        );
        for value in [i64::MIN, -3, -2, -1, 0, 99] {
            assert_eq!(
                resolve_regular_file_write_offset(Some(value), false, 10, 20, true),
                Ok(ResolvedFileOffset::EndOfFile(20))
            );
        }
        assert_eq!(
            resolve_regular_file_write_offset(Some(-3), true, 10, 20, false),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn a_synchronous_transfer_without_an_offset_names_the_file_pointer() {
        let carried = transfer_irp_byte_offset(None, true, false, false).unwrap();
        // The FILE_OBJECT's owner resolves what it was handed against the position it keeps.
        assert_eq!(
            resolve_regular_file_read_offset(Some(carried as i64), true, 4096),
            Ok(ResolvedFileOffset::Current(4096))
        );
        assert_eq!(
            resolve_regular_file_write_offset(Some(carried as i64), true, 4096, 8192, false),
            Ok(ResolvedFileOffset::Current(4096))
        );
        assert_eq!(resolve_file_object_byte_offset(carried, true, 4096), 4096);
        // An explicit offset is carried as given, including the caller's own sentinels.
        for explicit in [0, 7, FILE_WRITE_TO_END_OF_FILE, FILE_USE_FILE_POINTER_POSITION] {
            for synchronous in [false, true] {
                assert_eq!(
                    transfer_irp_byte_offset(Some(explicit), synchronous, false, false),
                    Ok(explicit as u64)
                );
            }
        }
    }

    #[test]
    fn an_asynchronous_transfer_needs_an_offset_unless_it_is_a_pipe_or_mailslot() {
        // ReactOS iofunc.c NtReadFile/NtWriteFile; NT5 read.c/write.c.
        assert_eq!(
            transfer_irp_byte_offset(None, false, false, false),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            transfer_irp_byte_offset(None, false, true, false),
            Err(NtStatus::INVALID_PARAMETER),
            "append-only access does not excuse a missing offset"
        );
        assert_eq!(transfer_irp_byte_offset(None, false, false, true), Ok(0));
    }

    #[test]
    fn append_only_writes_carry_write_to_end_of_file() {
        // NT5 write.c: append-only access gives drivers FILE_WRITE_TO_END_OF_FILE.
        for offset in [None, Some(0), Some(77), Some(FILE_USE_FILE_POINTER_POSITION)] {
            assert_eq!(
                transfer_irp_byte_offset(offset, true, true, false),
                Ok(FILE_WRITE_TO_END_OF_FILE as u64)
            );
        }
        assert_eq!(
            transfer_irp_byte_offset(Some(5), false, true, false),
            Ok(FILE_WRITE_TO_END_OF_FILE as u64)
        );
    }

    #[test]
    fn only_a_synchronous_file_object_substitutes_its_current_byte_offset() {
        let pointer = FILE_USE_FILE_POINTER_POSITION as u64;
        assert_eq!(resolve_file_object_byte_offset(pointer, true, 0x1234), 0x1234);
        assert_eq!(resolve_file_object_byte_offset(pointer, false, 0x1234), pointer);
        for explicit in [0, 99, FILE_WRITE_TO_END_OF_FILE as u64] {
            assert_eq!(resolve_file_object_byte_offset(explicit, true, 0x1234), explicit);
        }
    }

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
            Ok(ResolvedFileOffset::EndOfFile(22))
        );
    }
}
