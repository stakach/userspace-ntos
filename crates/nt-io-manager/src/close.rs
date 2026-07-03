//! Cleanup + close (spec §12.2). Cleanup runs when the user-visible handle is
//! released (`IRP_MJ_CLEANUP`); close runs at the final dereference
//! (`IRP_MJ_CLOSE`), releasing the Object Manager handle + File object and
//! dropping the I/O Manager's FileRecord. v0.1 keeps the two distinct even where a
//! simple device could collapse them.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue};

use crate::file::FileState;
use crate::irp::IoParameters;
use crate::object_port::ObjectManagerPort;
use crate::{FileId, IoManager, IrpId};

impl<P: ObjectManagerPort> IoManager<P> {
    /// Cleanup an open file (`IRP_MJ_CLEANUP`): the user handle is being released.
    /// After this the file is no longer usable for reads/writes.
    pub fn cleanup(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let (file_id, device_id) = self.reference_open_file(client, handle, AccessMask::empty())?;
        self.file_mut(file_id)
            .unwrap()
            .transition(FileState::CleanupPending);
        let mut empty: [u8; 0] = [];
        let _ = self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_CLEANUP,
            IoParameters::Cleanup,
            &mut empty,
        );
        self.file_mut(file_id)
            .unwrap()
            .transition(FileState::CleanupComplete);
        Ok(())
    }

    /// Close a file (`IRP_MJ_CLOSE`): the final dereference. Notifies the driver,
    /// releases the Object Manager handle (reaping the File object), and drops the
    /// FileRecord. Valid after cleanup, or directly on an open file.
    pub fn close(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let file_id = self.reference_file(client, handle, AccessMask::empty())?;
        let device_id = self
            .file(file_id)
            .ok_or(NtStatus::INVALID_HANDLE)?
            .device_id;
        self.file_mut(file_id)
            .unwrap()
            .transition(FileState::ClosePending);
        let mut empty: [u8; 0] = [];
        let _ = self.build_and_dispatch_sync(
            client,
            device_id,
            Some(file_id),
            major::IRP_MJ_CLOSE,
            IoParameters::Close,
            &mut empty,
        );
        self.file_mut(file_id)
            .unwrap()
            .transition(FileState::Closed);
        // Release the Object Manager handle (reaps the File object) + drop record.
        let _ = self.port.close_handle(client, handle);
        self.remove_file(file_id);
        Ok(())
    }

    /// A client disconnected or faulted (spec §16.6 client side): free its
    /// in-flight IRPs + drop its FileRecords, then close the client at the Object
    /// Manager (which reaps its handles + File objects). Unrelated clients are
    /// unaffected.
    pub fn disconnect_client(&mut self, client: ClientId) -> Result<(), NtStatus> {
        let irps: Vec<IrpId> = self
            .irps
            .iter()
            .filter(|(_, i)| i.client_id == client)
            .map(|(id, _)| id)
            .collect();
        for id in irps {
            self.free_irp(id);
        }
        let files: Vec<FileId> = self
            .files
            .iter()
            .filter(|(_, f)| f.client_id == client)
            .map(|(id, _)| id)
            .collect();
        for id in files {
            self.remove_file(id);
        }
        self.port.close_client(client)
    }
}
