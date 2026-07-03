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
use crate::irp::{
    BufferAccess, IoBufferRef, IoParameters, IoStackLocation, IrpRecord, IrpState,
    ReadWriteParameters,
};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, FileId, IoManager, IrpId};

/// The largest single buffered transfer v0.1 accepts.
pub(crate) const MAX_TRANSFER: usize = 64 * 1024;

/// Validate a requested transfer length (spec §14.1, buffer bounds).
pub(crate) fn validate_transfer(len: usize) -> Result<(), NtStatus> {
    if len > MAX_TRANSFER {
        Err(NtStatus::INVALID_PARAMETER)
    } else {
        Ok(())
    }
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
        let mut irp = IrpRecord::new(client, device_id, file_id, major);
        let mut sl = IoStackLocation::new(major, device_id, file_id);
        sl.parameters = params;
        irp.stack.push(sl);
        irp.buffer = Some(IoBufferRef {
            buffer_id: 0,
            offset: 0,
            len: system_buffer.len() as u32,
            access: BufferAccess::ReadWrite,
        });
        let irp_id = self.allocate_irp(irp);
        self.irp_mut(irp_id)
            .unwrap()
            .transition(IrpState::Initialized);
        self.irp_mut(irp_id)
            .unwrap()
            .transition(IrpState::Dispatched);
        let outcome = self.dispatch(irp_id, system_buffer);
        self.complete_sync(irp_id, outcome)
    }

    /// Apply a synchronous dispatch outcome to `irp_id`, freeing it, and return
    /// the information count (or the error status).
    pub(crate) fn complete_sync(
        &mut self,
        irp_id: IrpId,
        outcome: Result<DispatchOutcome, NtStatus>,
    ) -> Result<u64, NtStatus> {
        match outcome {
            Ok(DispatchOutcome::Completed {
                status,
                information,
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
