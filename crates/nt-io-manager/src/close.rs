//! Cleanup and close (spec section 12.2).
//!
//! Cleanup releases use of an open handle. Close releases the Object Manager
//! handle immediately, but the canonical FILE_OBJECT record remains alive while
//! any IRP, including an unacknowledged completion, still references it. The
//! driver receives exactly one `IRP_MJ_CLOSE` after those references drain.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue};

use crate::file::FileState;
use crate::irp::IoParameters;
use crate::object_port::ObjectManagerPort;
use crate::{FileId, IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Dispatch `IRP_MJ_CLEANUP`. A pending cleanup retains its file reference;
    /// acknowledgement advances the file to `CleanupComplete`.
    pub fn cleanup(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let (file_id, device_id) = self.reference_open_file(client, handle, AccessMask::empty())?;
        self.file_mut(file_id)
            .expect("referenced file")
            .transition(FileState::CleanupPending);
        let mut empty: [u8; 0] = [];
        let result = self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_CLEANUP,
            IoParameters::Cleanup,
            &mut empty,
        );
        if result != Err(NtStatus::PENDING) {
            self.file_mut(file_id)
                .expect("cleanup keeps file live")
                .transition(FileState::CleanupComplete);
        }
        result.map(|_| ())
    }

    /// Release the user-visible handle and begin final FILE_OBJECT close. Driver
    /// close is deferred while canonical IRPs still reference the file.
    pub fn close(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let file_id = self.reference_file(client, handle, AccessMask::empty())?;
        let state = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?.state;
        if !matches!(
            state,
            FileState::Open | FileState::CleanupPending | FileState::CleanupComplete
        ) {
            return Err(NtStatus::FILE_CLOSED);
        }
        self.port.close_handle(client, handle)?;
        self.file_mut(file_id)
            .expect("validated file")
            .transition(FileState::ClosePending);
        self.finish_deferred_file_close(file_id)?;
        Ok(())
    }

    /// Complete a close whose outstanding IRP references have drained. This is
    /// called both by `close` and by completion acknowledgement.
    pub(crate) fn finish_deferred_file_close(&mut self, file_id: FileId) -> Result<(), NtStatus> {
        let (client, device_id, refs, close_dispatched) = match self.file(file_id) {
            Some(file) if file.state == FileState::ClosePending => (
                file.client_id,
                file.device_id,
                file.outstanding_irp_refs,
                file.close_dispatched,
            ),
            _ => return Ok(()),
        };

        if refs != 0 {
            self.file_mut(file_id)
                .expect("file still live")
                .close_deferred = true;
            return Ok(());
        }

        if close_dispatched {
            self.file_mut(file_id)
                .expect("file still live")
                .transition(FileState::Closed);
            self.release_file_record(file_id)?;
            return Ok(());
        }

        {
            let file = self.file_mut(file_id).expect("file still live");
            file.close_deferred = false;
            file.close_dispatched = true;
        }
        let mut empty: [u8; 0] = [];
        let result = self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_CLOSE,
            IoParameters::Close,
            &mut empty,
        );
        let refs = self
            .file(file_id)
            .map(|file| file.outstanding_irp_refs)
            .unwrap_or(0);
        if result == Err(NtStatus::PENDING) || refs != 0 {
            if let Some(file) = self.file_mut(file_id) {
                file.close_deferred = true;
            }
            return Ok(());
        }
        if let Some(file) = self.file_mut(file_id) {
            file.transition(FileState::Closed);
        }
        self.release_file_record(file_id)?;
        Ok(())
    }

    pub(crate) fn release_file_record(&mut self, file_id: FileId) -> Result<(), NtStatus> {
        let (client, reference, refs) = self
            .file(file_id)
            .map(|file| {
                (
                    file.client_id,
                    file.object_reference,
                    file.outstanding_irp_refs,
                )
            })
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if refs != 0 {
            return Err(NtStatus::DELETE_PENDING);
        }
        if reference != 0 {
            self.port.release_object_reference(client, reference)?;
            self.file_mut(file_id)
                .expect("validated file")
                .object_reference = 0;
        }
        self.remove_file(file_id).ok_or(NtStatus::DELETE_PENDING)?;
        Ok(())
    }

    /// A client disconnected or faulted. Canonical records owned by that client
    /// are invalidated before the Object Manager reaps its handles.
    pub fn disconnect_client(&mut self, client: ClientId) -> Result<(), NtStatus> {
        let irps: Vec<IrpId> = self
            .irps
            .iter()
            .filter(|(_, irp)| irp.client_id == client)
            .map(|(id, _)| id)
            .collect();
        for id in irps {
            self.free_irp(id);
        }
        let files: Vec<FileId> = self
            .files
            .iter()
            .filter(|(_, file)| file.client_id == client)
            .map(|(id, _)| id)
            .collect();
        for id in files {
            self.release_file_record(id)?;
        }
        self.port.close_client(client)
    }
}
