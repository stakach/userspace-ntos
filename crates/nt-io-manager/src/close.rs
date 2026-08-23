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

use crate::dispatch::DispatchOutcome;
use crate::file::FileState;
use crate::irp::{IoParameters, IoStackLocation, IrpRecord, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{FileId, IoManager, IrpId};

enum LifecycleDispatch {
    Completed(Result<u64, NtStatus>),
    Pending,
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Release the final host-owned handle to a canonical File. Integration
    /// hosts use this when their process handle table is outside the Object
    /// Manager port. CLEANUP is issued once, CLOSE waits for every IRP ACK, and
    /// the File record remains live across pending or retryable lifecycle work.
    pub fn release_external_file(
        &mut self,
        client: ClientId,
        file_id: FileId,
    ) -> Result<(), NtStatus> {
        let state = {
            let file = self.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
            if file.client_id != client {
                return Err(NtStatus::INVALID_HANDLE);
            }
            file.state
        };
        match state {
            FileState::Allocated | FileState::Closed => return self.release_file_record(file_id),
            FileState::CreateIrpDispatched => {
                // No process handle was published for a pending external create. Relinquishing the
                // File therefore abandons that exact create IRP and keeps the File alive only until
                // the driver's terminal completion is acknowledged.
                let create_irp = self
                    .irps
                    .iter()
                    .find(|(_, irp)| {
                        irp.file_id == Some(file_id) && crate::is_create_major(irp.major)
                    })
                    .map(|(irp_id, _)| irp_id);
                let file = self.file_mut(file_id).expect("validated external File");
                file.transition(FileState::ClosePending);
                file.close_deferred = true;
                if let Some(irp_id) = create_irp {
                    self.abandon_irp_delivery(client, irp_id)?;
                }
                if self.finish_deferred_file_close(file_id).is_err() {
                    self.schedule_deferred_file_close(file_id);
                }
                return Ok(());
            }
            FileState::Open => {
                let file = self.file_mut(file_id).expect("validated external File");
                file.transition(FileState::CleanupPending);
                file.close_deferred = true;
            }
            FileState::CleanupPending | FileState::CleanupComplete => {
                self.file_mut(file_id)
                    .expect("validated external File")
                    .close_deferred = true;
            }
            FileState::ClosePending => {}
        }
        if self.finish_deferred_file_close(file_id).is_err() {
            self.schedule_deferred_file_close(file_id);
        }
        Ok(())
    }

    /// Dispatch `IRP_MJ_CLEANUP`. A pending cleanup retains its file reference;
    /// acknowledgement advances the file to `CleanupComplete`.
    pub fn cleanup(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let (file_id, device_id) = self.reference_open_file(client, handle, AccessMask::empty())?;
        self.file_mut(file_id)
            .expect("referenced file")
            .transition(FileState::CleanupPending);
        match self.dispatch_lifecycle_irp_once(
            client,
            device_id,
            file_id,
            major::IRP_MJ_CLEANUP,
            IoParameters::Cleanup,
        ) {
            Err(status) => {
                self.file_mut(file_id)
                    .expect("rejected cleanup keeps file live")
                    .transition(FileState::Open);
                Err(status)
            }
            Ok(LifecycleDispatch::Completed(result)) => {
                let file = self.file_mut(file_id).expect("cleanup keeps file live");
                file.cleanup_dispatched = true;
                file.transition(FileState::CleanupComplete);
                result.map(|_| ())
            }
            Ok(LifecycleDispatch::Pending) => {
                self.file_mut(file_id)
                    .expect("pending cleanup keeps file live")
                    .cleanup_dispatched = true;
                Err(NtStatus::PENDING)
            }
        }
    }

    /// Release the user-visible handle and begin the canonical CLEANUP -> CLOSE
    /// lifecycle. Driver close is deferred while canonical IRPs still reference
    /// the file.
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
        let file = self.file_mut(file_id).expect("validated file");
        match state {
            FileState::Open => {
                file.transition(FileState::CleanupPending);
            }
            FileState::CleanupPending | FileState::CleanupComplete => {}
            _ => unreachable!("validated close state changed without concurrency"),
        }
        file.close_deferred = true;
        if self.finish_deferred_file_close(file_id).is_err() {
            self.schedule_deferred_file_close(file_id);
        }
        Ok(())
    }

    /// Complete a close whose outstanding IRP references have drained. This is
    /// called both by `close` and by completion acknowledgement.
    pub(crate) fn finish_deferred_file_close(&mut self, file_id: FileId) -> Result<(), NtStatus> {
        let state = match self.file(file_id) {
            Some(file) => file.state,
            None => return Ok(()),
        };
        if state == FileState::CleanupPending {
            let (client, device_id, dispatched) = {
                let file = self.file(file_id).expect("checked above");
                (file.client_id, file.device_id, file.cleanup_dispatched)
            };
            if !dispatched {
                match self.dispatch_lifecycle_irp_once(
                    client,
                    device_id,
                    file_id,
                    major::IRP_MJ_CLEANUP,
                    IoParameters::Cleanup,
                )? {
                    LifecycleDispatch::Completed(_) => {
                        let file = self.file_mut(file_id).expect("cleanup keeps file live");
                        file.cleanup_dispatched = true;
                        file.transition(FileState::CleanupComplete);
                    }
                    LifecycleDispatch::Pending => {
                        self.file_mut(file_id)
                            .expect("pending cleanup keeps file live")
                            .cleanup_dispatched = true;
                        return Ok(());
                    }
                }
            } else {
                return Ok(());
            }
        }
        if self
            .file(file_id)
            .is_some_and(|file| file.state == FileState::CleanupComplete && file.close_deferred)
        {
            self.file_mut(file_id)
                .expect("checked above")
                .transition(FileState::ClosePending);
        }
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
            return self.release_file_record(file_id);
        }

        self.file_mut(file_id)
            .expect("file still live")
            .close_deferred = false;
        match self.dispatch_lifecycle_irp_once(
            client,
            device_id,
            file_id,
            major::IRP_MJ_CLOSE,
            IoParameters::Close,
        )? {
            LifecycleDispatch::Completed(_) => {
                self.file_mut(file_id)
                    .expect("close keeps file live")
                    .close_dispatched = true;
            }
            LifecycleDispatch::Pending => {
                let file = self
                    .file_mut(file_id)
                    .expect("pending close keeps file live");
                file.close_dispatched = true;
                file.close_deferred = true;
                return Ok(());
            }
        }
        let refs = self
            .file(file_id)
            .map(|file| file.outstanding_irp_refs)
            .unwrap_or(0);
        if refs != 0 {
            if let Some(file) = self.file_mut(file_id) {
                file.close_deferred = true;
            }
            return Ok(());
        }
        self.release_file_record(file_id)?;
        Ok(())
    }

    /// Publish one canonical lifecycle IRP. The outer `Result` means the backend never accepted the
    /// request; `Completed` and `Pending` both prove that the driver dispatch boundary was crossed.
    fn dispatch_lifecycle_irp_once(
        &mut self,
        client: ClientId,
        device_id: crate::DeviceId,
        file_id: FileId,
        major: u8,
        parameters: IoParameters,
    ) -> Result<LifecycleDispatch, NtStatus> {
        // Lifecycle completions have no external delivery consumer. Reserve
        // manager ownership before crossing the driver boundary so a pending
        // result can never be stranded by a later allocation failure.
        self.reserve_manager_owned_irp_slot()?;
        let driver_id = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        let mut irp = IrpRecord::new(client, device_id, Some(file_id), major);
        irp.driver_id = driver_id;
        irp.user_data = self
            .file(file_id)
            .and_then(|file| file.driver_context)
            .unwrap_or(0);
        let mut stack = IoStackLocation::new(major, device_id, Some(file_id));
        stack.parameters = parameters;
        irp.stack.push(stack);
        let irp_id = self.allocate_irp(irp)?;
        self.irp_mut(irp_id)
            .expect("just allocated")
            .transition(IrpState::Initialized);
        self.irp_mut(irp_id)
            .expect("just allocated")
            .transition(IrpState::Dispatched);

        let mut empty: [u8; 0] = [];
        let outcome = self.dispatch_to_driver(driver_id, irp_id, &mut empty);
        if self
            .irp(irp_id)
            .is_none_or(|irp| irp.state != IrpState::Dispatched)
        {
            self.claim_manager_owned_irp(client, irp_id)?;
            return Ok(LifecycleDispatch::Pending);
        }

        match outcome {
            Err(status) => {
                let _ = self.complete_sync(irp_id, Err(status));
                Err(status)
            }
            Ok(outcome @ DispatchOutcome::Pending) => {
                let _ = self.complete_sync(irp_id, Ok(outcome));
                self.claim_manager_owned_irp(client, irp_id)?;
                Ok(LifecycleDispatch::Pending)
            }
            Ok(outcome) => {
                let result = self.complete_sync(irp_id, Ok(outcome));
                Ok(LifecycleDispatch::Completed(result))
            }
        }
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

    /// A client disconnected or faulted. Its live IRPs are abandoned through cancellation and
    /// terminal ACK; File objects remain strongly referenced through real CLEANUP/CLOSE dispatch.
    pub fn disconnect_client(&mut self, client: ClientId) -> Result<(), NtStatus> {
        let irps: Vec<IrpId> = self
            .irps
            .iter()
            .filter(|(_, irp)| irp.client_id == client)
            .map(|(id, _)| id)
            .collect();
        for id in irps {
            if self
                .irp(id)
                .is_some_and(|irp| matches!(irp.major, major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE))
            {
                continue;
            }
            self.abandon_irp_delivery(client, id)?;
        }
        let files: Vec<FileId> = self
            .files
            .iter()
            .filter(|(_, file)| file.client_id == client)
            .map(|(id, _)| id)
            .collect();
        for id in files {
            let state = self.file(id).expect("enumerated file").state;
            match state {
                FileState::Allocated => {
                    self.release_file_record(id)?;
                    continue;
                }
                FileState::CreateIrpDispatched => {
                    let file = self.file_mut(id).expect("enumerated file");
                    file.transition(FileState::ClosePending);
                    file.close_deferred = true;
                }
                FileState::Open => {
                    let file = self.file_mut(id).expect("enumerated file");
                    file.transition(FileState::CleanupPending);
                    file.close_deferred = true;
                }
                FileState::CleanupPending | FileState::CleanupComplete => {
                    self.file_mut(id).expect("enumerated file").close_deferred = true;
                }
                FileState::ClosePending => {}
                FileState::Closed => {
                    self.release_file_record(id)?;
                    continue;
                }
            }
            if self.finish_deferred_file_close(id).is_err() {
                self.schedule_deferred_file_close(id);
            }
        }
        if !self.disconnected_client_retries.contains(&client) {
            self.disconnected_client_retries.push(client);
        }
        self.pump();
        Ok(())
    }
}
