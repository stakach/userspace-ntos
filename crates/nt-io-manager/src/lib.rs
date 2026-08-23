//! # `nt-io-manager` — the NT I/O Manager core
//!
//! Host-testable, `no_std` + `alloc` implementation of the I/O Manager's canonical
//! state: driver / device / file / IRP records held in generation-protected
//! [`GenStore`]s, with the file + IRP lifecycle state machines. The Object Manager
//! integration (a trait), the dispatch backend, and the open/read/write/IOCTL
//! request paths are layered on in later milestones. Single-threaded (`&mut
//! self`); no `unsafe`.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use nt_status::NtStatus;
use nt_types::{ClientId, NtPath, ObjectId};

mod cancel;
mod cancel_wait;
mod close;
mod complete;
mod device;
mod device_control;
mod dispatch;
mod driver;
mod driver_host;
mod driver_peer;
mod external_dispatch;
mod fault;
mod file;
mod irp;
mod mock_driver;
mod object_port;
mod open;
mod pending_io;
mod pipe;
mod projection;
mod read_write;
mod retained_completion;
mod store;
mod synchronous_io;
mod wdm_x64;

pub use cancel::FileThreadIrpDrainState;
pub use cancel_wait::{
    PendingFileIrpDrain, PendingFileIrpDrainReservation, PendingFileIrpDrainTable,
    FILE_IRP_DRAIN_IOSB_PUBLISHED, FILE_IRP_DRAIN_REPLY_CLAIMED, FILE_IRP_DRAIN_REPLY_PUBLISHED,
};
pub use complete::CompletedIrp;
pub use device::{DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType};
pub use dispatch::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IrpProjection,
};
pub use driver::{
    DeviceList, DispatchTarget, DriverBackendId, DriverFlags, DriverPeerId, DriverRecord,
    DriverUnloadState, MajorFunctionTable, MockDispatchId,
};
pub use driver_host::{DriverHostRoutine, MvpStatus};
pub use driver_peer::{
    DriverPeerBackend, DriverPeerTransport, MockDriverPeer, MockPeerControl, PeerTransferBuffers,
};
pub use external_dispatch::ExternalDispatchResult;
pub use file::{CreateOptions, FileFlags, FileRecord, FileState, ShareAccess};
pub use irp::{
    BufferAccess, CancelState, CreateParameters, DeviceControlParameters, InformationParameters,
    IoBufferRef, IoParameters, IoStackLocation, IrpRecord, IrpState, ReadWriteParameters,
    StackControl, StackFlags,
};
pub use mock_driver::{IoctlBehavior, MockDriverBackend};
pub use object_port::{MockObjectPort, ObjectManagerPort};
pub use pending_io::{
    PendingFileCreate, PendingFileIo, PendingFileIoOperation, PendingFileIoReservation,
    PendingFileIoTable, IO_DELIVERY_APC_PUBLISHED, IO_DELIVERY_BACKEND_ACKED,
    IO_DELIVERY_BUFFER_PUBLISHED, IO_DELIVERY_CREATE_COMMITTED, IO_DELIVERY_EVENT_PUBLISHED,
    IO_DELIVERY_FILE_LOCK_RELEASED, IO_DELIVERY_FILE_PUBLISHED, IO_DELIVERY_HANDLE_PUBLISHED,
    IO_DELIVERY_IOCP_PUBLISHED, IO_DELIVERY_IOSB_PUBLISHED, IO_DELIVERY_REPLY_CLAIMED,
    IO_DELIVERY_REPLY_PUBLISHED,
};
pub use pipe::{
    decode_pipe_wait_name, decode_pipe_wait_request, pipe_endpoint_end, pipe_endpoint_file_id,
    pipe_endpoint_primary_context, pipe_name_hash, pipe_server_file_id_for_endpoint, AsyncListen,
    AsyncListenTable, PipeConnection, PipeEnd, PipeFcb, PipeFidName, PipeFidNameTable, PipeHandle,
    PipeInformation, PipeNameWaiter, PipeNameWaiterTable, PipeParams, PipePreconnectedServerTable,
    PipeRegistry, PipeServerAvailability, PipeServerAvailabilityTable, PipeState, PipeWaitRequest,
    FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_CLIENT_END,
    FILE_PIPE_COMPLETE_OPERATION, FILE_PIPE_FULL_DUPLEX, FILE_PIPE_INBOUND, FILE_PIPE_MESSAGE_MODE,
    FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_OUTBOUND, FILE_PIPE_QUEUE_OPERATION, FILE_PIPE_SERVER_END,
    STATUS_INSTANCE_NOT_AVAILABLE, STATUS_INVALID_PIPE_STATE, STATUS_PIPE_BUSY,
    STATUS_PIPE_CONNECTED, STATUS_PIPE_DISCONNECTED, STATUS_PIPE_LISTENING,
    STATUS_PIPE_NOT_AVAILABLE,
};
pub use retained_completion::{RetainedCompletion, RetainedCompletionError, RetainedIrpCompletion};
pub use store::{GenStore, IoId};
pub use synchronous_io::{
    SynchronousFileWaitState, SynchronousFileWaitTable, SynchronousFileWaiter,
};
pub use wdm_x64::{
    write_wdm_device_object, write_wdm_driver_object, write_wdm_file_object,
    write_wdm_io_stack_location, write_wdm_irp, write_wdm_open_device_projection,
    WdmDeviceObjectInit, WdmDriverObjectInit, WdmFileObjectInit, WdmIoStackLocationInit,
    WdmIoStackParameters, WdmIrpInit, WdmLayoutError, WdmOpenDeviceProjectionInit,
    WDM_X64_DEVICE_OBJECT_SIZE, WDM_X64_DRIVER_EXTENSION_OFFSET, WDM_X64_DRIVER_EXTENSION_SIZE,
    WDM_X64_DRIVER_MAJOR_FUNCTION_OFFSET, WDM_X64_DRIVER_OBJECT_SIZE, WDM_X64_DRIVER_UNLOAD_OFFSET,
    WDM_X64_FILE_OBJECT_SIZE, WDM_X64_IO_STACK_LOCATION_SIZE, WDM_X64_IO_TYPE_DEVICE,
    WDM_X64_IO_TYPE_DRIVER, WDM_X64_IO_TYPE_FILE, WDM_X64_IRP_SIZE,
};

#[cfg(feature = "object-manager")]
pub use object_port::ObjectManagerLibraryPort;

// Re-export the canonical id types + Driver Host projections from one place.
pub use nt_io_abi::{
    DeviceId, DeviceObjectProjection, DriverId, DriverObjectProjection, FileId,
    FileObjectProjection, IoRequestId, IrpId,
};

#[inline]
pub(crate) const fn is_create_major(major: u8) -> bool {
    matches!(
        major,
        nt_io_abi::major::IRP_MJ_CREATE
            | nt_io_abi::major::IRP_MJ_CREATE_NAMED_PIPE
            | nt_io_abi::major::IRP_MJ_CREATE_MAILSLOT
    )
}

/// The canonical I/O Manager (spec §6): owns the driver / device / file / IRP
/// stores, the registered dispatch backends, and the port to the Object Manager
/// (`P`). Single-threaded (`&mut self`).
#[derive(Default)]
pub struct IoManager<P> {
    drivers: GenStore<DriverId, DriverRecord>,
    devices: GenStore<DeviceId, DeviceRecord>,
    files: GenStore<FileId, FileRecord>,
    irps: GenStore<IrpId, IrpRecord>,
    completed_irps: VecDeque<IrpId>,
    manager_owned_irps: Vec<IrpId>,
    cancel_dispatch_retries: Vec<IrpId>,
    rejected_completion_acks: Vec<(usize, IrpId)>,
    deferred_file_close_retries: Vec<FileId>,
    disconnected_client_retries: Vec<ClientId>,
    port: P,
    backends: Vec<Box<dyn DriverDispatchBackend>>,
}

impl<P> IoManager<P> {
    /// A fresh I/O Manager over Object Manager port `port`.
    pub fn new(port: P) -> Self {
        Self {
            drivers: GenStore::new(),
            devices: GenStore::new(),
            files: GenStore::new(),
            irps: GenStore::new(),
            completed_irps: VecDeque::new(),
            manager_owned_irps: Vec::new(),
            cancel_dispatch_retries: Vec::new(),
            rejected_completion_acks: Vec::new(),
            deferred_file_close_retries: Vec::new(),
            disconnected_client_retries: Vec::new(),
            port,
            backends: Vec::new(),
        }
    }

    /// Borrow the Object Manager port.
    pub fn port(&self) -> &P {
        &self.port
    }
    /// Mutably borrow the Object Manager port.
    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    /// Register a dispatch backend, returning its registry index.
    pub fn register_backend(&mut self, backend: Box<dyn DriverDispatchBackend>) -> usize {
        self.backends.push(backend);
        self.backends.len() - 1
    }

    // --- Drivers -----------------------------------------------------------

    /// Register a driver record, assigning + returning its id.
    pub fn register_driver(&mut self, record: DriverRecord) -> DriverId {
        let id = self.drivers.insert(record);
        self.drivers.get_mut(id).expect("just inserted").id = id;
        id
    }

    pub fn driver(&self, id: DriverId) -> Option<&DriverRecord> {
        self.drivers.get(id)
    }
    pub fn driver_mut(&mut self, id: DriverId) -> Option<&mut DriverRecord> {
        self.drivers.get_mut(id)
    }
    pub fn remove_driver(&mut self, id: DriverId) -> Option<DriverRecord> {
        self.drivers.remove(id)
    }
    pub fn driver_count(&self) -> usize {
        self.drivers.len()
    }

    /// Resolve a driver by its Object Manager `Driver` object id.
    pub fn driver_id_by_object_id(&self, object_id: ObjectId) -> Option<DriverId> {
        self.drivers
            .iter()
            .find(|(_, d)| d.object_id == object_id)
            .map(|(id, _)| id)
    }

    /// Resolve a driver by its canonical NT object path.
    pub fn driver_id_by_name(&self, name: &NtPath) -> Option<DriverId> {
        self.drivers
            .iter()
            .find(|(_, d)| &d.name == name)
            .map(|(id, _)| id)
    }

    /// Mark a driver unload requested and mark its devices delete-pending. This mutates only
    /// canonical I/O Manager records; Object Manager namespace teardown is owned by the caller or by
    /// the Object Manager-backed APIs in `open.rs`.
    pub fn request_driver_unload_records(&mut self, driver: DriverId) -> Result<(), NtStatus> {
        let devices: Vec<DeviceId> = self.devices_of(driver).to_vec();
        let record = self.driver_mut(driver).ok_or(NtStatus::INVALID_PARAMETER)?;
        if record.unload_state == DriverUnloadState::Unloaded {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        record.unload_state = DriverUnloadState::UnloadRequested;
        for device in devices {
            if let Some(record) = self.device_mut(device) {
                record.delete_pending = true;
            }
        }
        Ok(())
    }

    /// Return whether a driver can be removed without changing I/O Manager state.
    pub fn can_destroy_driver(&self, driver: DriverId) -> Result<(), NtStatus> {
        if self.driver(driver).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self
            .devices_of(driver)
            .iter()
            .any(|device| self.device_has_live_files(*device) || self.has_upper_attachment(*device))
        {
            return Err(NtStatus::DELETE_PENDING);
        }
        Ok(())
    }

    /// Remove driver/device records after the caller has run any required driver-owned unload
    /// routine and torn down Object Manager names.
    pub fn remove_driver_records_after_unload(
        &mut self,
        driver: DriverId,
    ) -> Result<DriverRecord, NtStatus> {
        self.request_driver_unload_records(driver)?;
        self.can_destroy_driver(driver)?;
        let devices: Vec<DeviceId> = self.devices_of(driver).to_vec();
        for device in devices {
            self.delete_device(device)?;
        }
        let mut record = self
            .remove_driver(driver)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        record.unload_state = DriverUnloadState::Unloaded;
        Ok(record)
    }

    // --- Devices -----------------------------------------------------------

    /// Add a device record, assigning its id + `top_of_stack` (v0.1: itself) and
    /// linking it into the owning driver's device list.
    pub fn add_device(&mut self, record: DeviceRecord) -> DeviceId {
        let driver_id = record.driver_id;
        let id = self.devices.insert(record);
        if let Some(d) = self.devices.get_mut(id) {
            d.id = id;
            d.top_of_stack = id;
        }
        if let Some(drv) = self.drivers.get_mut(driver_id) {
            drv.devices.push(id);
        }
        id
    }

    pub fn device(&self, id: DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(id)
    }
    pub fn device_mut(&mut self, id: DeviceId) -> Option<&mut DeviceRecord> {
        self.devices.get_mut(id)
    }
    pub fn remove_device(&mut self, id: DeviceId) -> Option<DeviceRecord> {
        let record = self.devices.remove(id)?;
        if let Some(driver) = self.drivers.get_mut(record.driver_id) {
            driver.devices.retain(|device| *device != id);
        }
        self.clear_attachment_edges(id);
        self.recompute_device_stacks();
        Some(record)
    }
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Resolve a device by its Object Manager `Device` object id.
    pub fn device_id_by_object_id(&self, object_id: ObjectId) -> Option<DeviceId> {
        self.devices
            .iter()
            .find(|(_, d)| d.object_id == object_id)
            .map(|(id, _)| id)
    }

    /// Resolve a named device by its canonical NT path.
    pub fn device_id_by_name(&self, name: &NtPath) -> Option<DeviceId> {
        self.devices
            .iter()
            .find(|(_, d)| d.name.as_ref() == Some(name))
            .map(|(id, _)| id)
    }

    /// The devices owned by a driver (empty for an unknown driver).
    pub fn devices_of(&self, driver: DriverId) -> &[DeviceId] {
        self.drivers
            .get(driver)
            .map(|d| d.devices.as_slice())
            .unwrap_or(&[])
    }

    /// Attach `source` above the current top of `target`'s device stack, returning the lower device
    /// that `source` attached to. This is the canonical record-level half of
    /// `IoAttachDeviceToDeviceStack`; guest-visible WDM pointers are translated by the driver host.
    pub fn attach_device_to_stack(
        &mut self,
        source: DeviceId,
        target: DeviceId,
    ) -> Result<DeviceId, NtStatus> {
        if source == target {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let (source_delete_pending, source_attached) = match self.device(source) {
            Some(device) => (device.delete_pending, device.attached_to.is_some()),
            None => return Err(NtStatus::INVALID_PARAMETER),
        };
        let lower = match self.device(target) {
            Some(device) if !device.delete_pending => {
                if self.device(device.top_of_stack).is_some() {
                    device.top_of_stack
                } else {
                    target
                }
            }
            Some(_) => return Err(NtStatus::DELETE_PENDING),
            None => return Err(NtStatus::INVALID_PARAMETER),
        };
        if source_delete_pending || self.device(lower).map(|d| d.delete_pending).unwrap_or(true) {
            return Err(NtStatus::DELETE_PENDING);
        }
        if source_attached || self.has_upper_attachment(source) || lower == source {
            return Err(NtStatus::INVALID_PARAMETER);
        }

        self.device_mut(source)
            .expect("validated source")
            .attached_to = Some(lower);
        self.recompute_device_stacks();
        Ok(lower)
    }

    /// Detach `source` from the lower device it is attached to, returning that lower device.
    pub fn detach_device_from_stack(&mut self, source: DeviceId) -> Result<DeviceId, NtStatus> {
        let lower = match self.device(source) {
            Some(device) => device.attached_to.ok_or(NtStatus::INVALID_PARAMETER)?,
            None => return Err(NtStatus::INVALID_PARAMETER),
        };
        self.device_mut(source)
            .expect("validated source")
            .attached_to = None;
        self.recompute_device_stacks();
        Ok(lower)
    }

    /// Delete a device record when no open file references or upper attachments remain. If the
    /// device is still referenced, mark it delete-pending and leave the record live.
    pub fn delete_device(&mut self, id: DeviceId) -> Result<DeviceRecord, NtStatus> {
        if let Err(status) = self.can_delete_device(id) {
            if status == NtStatus::DELETE_PENDING {
                if let Some(device) = self.device_mut(id) {
                    device.delete_pending = true;
                }
            }
            return Err(status);
        }
        if self
            .device(id)
            .and_then(|device| device.attached_to)
            .is_some()
        {
            let _ = self.detach_device_from_stack(id);
        }
        self.remove_device(id).ok_or(NtStatus::INVALID_PARAMETER)
    }

    /// Return whether a device can be removed without changing I/O Manager state.
    pub fn can_delete_device(&self, id: DeviceId) -> Result<(), NtStatus> {
        if self.device(id).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.device_has_live_files(id) || self.has_upper_attachment(id) {
            return Err(NtStatus::DELETE_PENDING);
        }
        Ok(())
    }

    /// Mark a device delete-pending if open file references or upper attachments still block removal.
    pub fn mark_device_delete_pending(&mut self, id: DeviceId) -> Result<(), NtStatus> {
        match self.can_delete_device(id) {
            Ok(()) => Ok(()),
            Err(NtStatus::DELETE_PENDING) => {
                if let Some(device) = self.device_mut(id) {
                    device.delete_pending = true;
                }
                Err(NtStatus::DELETE_PENDING)
            }
            Err(status) => Err(status),
        }
    }

    fn clear_attachment_edges(&mut self, removed: DeviceId) {
        let ids = self.devices.ids();
        for id in ids {
            if let Some(device) = self.devices.get_mut(id) {
                if device.attached_to == Some(removed) {
                    device.attached_to = None;
                    device.stack_size = 1;
                    device.top_of_stack = id;
                }
            }
        }
    }

    fn has_upper_attachment(&self, lower: DeviceId) -> bool {
        self.devices
            .iter()
            .any(|(_, device)| device.attached_to == Some(lower))
    }

    fn device_has_live_files(&self, id: DeviceId) -> bool {
        self.files
            .iter()
            .any(|(_, file)| file.device_id == id && !file.state.is_closed())
    }

    fn recompute_device_stacks(&mut self) {
        let ids = self.devices.ids();
        let mut updates = Vec::new();
        for id in ids.iter().copied() {
            updates.push((
                id,
                self.device_stack_size(id),
                self.device_top_of_stack(id, &ids),
            ));
        }
        for (id, stack_size, top_of_stack) in updates {
            if let Some(device) = self.devices.get_mut(id) {
                device.stack_size = stack_size;
                device.top_of_stack = top_of_stack;
            }
        }
    }

    fn device_stack_size(&self, id: DeviceId) -> u8 {
        let mut size = 1u8;
        let mut current = id;
        let mut guard = 0usize;
        while guard < self.device_count() {
            let Some(lower) = self.device(current).and_then(|device| device.attached_to) else {
                break;
            };
            if self.device(lower).is_none() || lower == current {
                break;
            }
            size = size.saturating_add(1);
            current = lower;
            guard += 1;
        }
        size
    }

    fn device_top_of_stack(&self, id: DeviceId, ids: &[DeviceId]) -> DeviceId {
        let mut top = id;
        let mut guard = 0usize;
        while guard < ids.len() {
            let Some(upper) = ids.iter().copied().find(|candidate| {
                self.device(*candidate)
                    .and_then(|device| device.attached_to)
                    == Some(top)
            }) else {
                break;
            };
            if upper == top {
                break;
            }
            top = upper;
            guard += 1;
        }
        top
    }

    // --- Files -------------------------------------------------------------

    /// Add a file record, assigning + returning its id.
    pub fn add_file(&mut self, record: FileRecord) -> FileId {
        let id = self.files.insert(record);
        self.files.get_mut(id).expect("just inserted").id = id;
        id
    }

    pub fn file(&self, id: FileId) -> Option<&FileRecord> {
        self.files.get(id)
    }
    pub fn file_mut(&mut self, id: FileId) -> Option<&mut FileRecord> {
        self.files.get_mut(id)
    }
    pub(crate) fn remove_file(&mut self, id: FileId) -> Option<FileRecord> {
        if self
            .files
            .get(id)
            .map(|file| file.outstanding_irp_refs != 0)
            .unwrap_or(false)
        {
            return None;
        }
        self.files.remove(id)
    }
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    // --- IRPs --------------------------------------------------------------

    /// Allocate an IRP record, assigning + returning its id.
    pub fn allocate_irp(&mut self, mut record: IrpRecord) -> Result<IrpId, NtStatus> {
        if let Some(file_id) = record.file_id {
            let file = self.files.get(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
            let file_driver = self
                .devices
                .get(file.device_id)
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .driver_id;
            let valid_state = match record.major {
                major if is_create_major(major) => file.state == FileState::Allocated,
                nt_io_abi::major::IRP_MJ_CLEANUP => file.state == FileState::CleanupPending,
                nt_io_abi::major::IRP_MJ_CLOSE => file.state == FileState::ClosePending,
                _ => file.state == FileState::Open,
            };
            if file.client_id != record.client_id
                || file_driver != record.driver_id
                || (record.device_id != DeviceId::NULL && file.device_id != record.device_id)
                || !valid_state
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if !is_create_major(record.major) {
                record.user_data = file.driver_context.unwrap_or(0);
            }
            let file = self.files.get_mut(file_id).expect("validated file");
            file.outstanding_irp_refs = file
                .outstanding_irp_refs
                .checked_add(1)
                .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
        }
        let id = self.irps.insert(record);
        self.irps.get_mut(id).expect("just inserted").id = id;
        Ok(id)
    }

    pub fn irp(&self, id: IrpId) -> Option<&IrpRecord> {
        self.irps.get(id)
    }
    pub fn irp_mut(&mut self, id: IrpId) -> Option<&mut IrpRecord> {
        self.irps.get_mut(id)
    }
    pub fn free_irp(&mut self, id: IrpId) -> Option<IrpRecord> {
        let record = self.irps.remove(id)?;
        self.completed_irps.retain(|queued| *queued != id);
        if let Some(file_id) = record.file_id {
            if let Some(file) = self.files.get_mut(file_id) {
                file.outstanding_irp_refs = file
                    .outstanding_irp_refs
                    .checked_sub(1)
                    .expect("canonical FILE_OBJECT IRP reference underflow");
            }
        }
        Some(record)
    }
    pub fn irp_count(&self) -> usize {
        self.irps.len()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use nt_io_abi::{ioctl, major};
    use nt_status::NtStatus;
    use nt_types::{AccessMask, ClientId, HandleValue, NtPath, ObjectId};
    use proptest::prelude::*;

    fn path(s: &str) -> NtPath {
        NtPath::parse_str(s).unwrap()
    }

    fn io() -> IoManager<MockObjectPort> {
        IoManager::new(MockObjectPort::new())
    }

    fn a_driver(om: &mut IoManager<MockObjectPort>) -> DriverId {
        om.register_driver(DriverRecord::new(
            ObjectId::NULL,
            path("\\Driver\\Test"),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ))
    }

    fn a_device(om: &mut IoManager<MockObjectPort>, driver: DriverId) -> DeviceId {
        om.add_device(DeviceRecord::new(
            ObjectId::NULL,
            driver,
            Some(path("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        ))
    }

    fn named_device(om: &mut IoManager<MockObjectPort>, driver: DriverId, name: &str) -> DeviceId {
        om.add_device(DeviceRecord::new(
            ObjectId::NULL,
            driver,
            Some(path(name)),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        ))
    }

    #[test]
    fn driver_device_registration() {
        let mut om = io();
        let drv = a_driver(&mut om);
        assert_eq!(om.driver(drv).unwrap().id, drv);
        assert_eq!(om.driver_count(), 1);

        let dev = a_device(&mut om, drv);
        let d = om.device(dev).unwrap();
        assert_eq!(d.id, dev);
        assert_eq!(d.driver_id, drv);
        assert_eq!(d.top_of_stack, dev);
        assert_eq!(om.devices_of(drv), &[dev]);
        assert!(d.is_buffered_io());
    }

    #[test]
    fn driver_device_records_resolve_by_object_id_and_name() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);
        let driver_obj = ObjectId(0x111);
        let device_obj = ObjectId(0x222);
        om.driver_mut(drv).unwrap().object_id = driver_obj;
        om.device_mut(dev).unwrap().object_id = device_obj;

        assert_eq!(om.driver_id_by_object_id(driver_obj), Some(drv));
        assert_eq!(om.driver_id_by_name(&path("\\Driver\\Test")), Some(drv));
        assert_eq!(om.device_id_by_object_id(device_obj), Some(dev));
        assert_eq!(om.device_id_by_name(&path("\\Device\\Test0")), Some(dev));
        assert_eq!(om.driver_id_by_name(&path("\\Driver\\Missing")), None);
        assert_eq!(om.device_id_by_name(&path("\\Device\\Missing")), None);
        assert_eq!(om.driver_id_by_object_id(ObjectId(0x333)), None);
        assert_eq!(om.device_id_by_object_id(ObjectId(0x333)), None);
    }

    #[test]
    fn stale_ids_are_rejected() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);

        assert!(om.remove_device(dev).is_some());
        assert!(om.device(dev).is_none()); // stale id no longer resolves
        assert!(om.remove_device(dev).is_none()); // double remove is a no-op
        assert!(om.devices_of(drv).is_empty());

        // Reusing the slot yields a fresh id; the old id stays stale.
        let dev2 = a_device(&mut om, drv);
        assert_ne!(dev2, dev);
        assert!(om.device(dev).is_none());
        assert!(om.device(dev2).is_some());
        assert_eq!(om.devices_of(drv), &[dev2]);
    }

    #[test]
    fn attach_and_detach_device_stack_updates_all_top_links() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let lower = named_device(&mut om, drv, "\\Device\\Lower");
        let filter = named_device(&mut om, drv, "\\Device\\Filter");
        let upper = named_device(&mut om, drv, "\\Device\\Upper");

        assert_eq!(om.attach_device_to_stack(filter, lower), Ok(lower));
        assert_eq!(om.device(filter).unwrap().attached_to, Some(lower));
        assert_eq!(om.device(filter).unwrap().stack_size, 2);
        assert_eq!(om.device(lower).unwrap().top_of_stack, filter);
        assert_eq!(om.device(filter).unwrap().top_of_stack, filter);

        assert_eq!(om.attach_device_to_stack(upper, lower), Ok(filter));
        assert_eq!(om.device(upper).unwrap().attached_to, Some(filter));
        assert_eq!(om.device(upper).unwrap().stack_size, 3);
        assert_eq!(om.device(lower).unwrap().top_of_stack, upper);
        assert_eq!(om.device(filter).unwrap().top_of_stack, upper);
        assert_eq!(om.device(upper).unwrap().top_of_stack, upper);

        assert_eq!(om.detach_device_from_stack(upper), Ok(filter));
        assert_eq!(om.device(upper).unwrap().attached_to, None);
        assert_eq!(om.device(upper).unwrap().top_of_stack, upper);
        assert_eq!(om.device(upper).unwrap().stack_size, 1);
        assert_eq!(om.device(lower).unwrap().top_of_stack, filter);
        assert_eq!(om.device(filter).unwrap().top_of_stack, filter);
    }

    #[test]
    fn delete_device_marks_pending_until_references_detach() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let lower = named_device(&mut om, drv, "\\Device\\Lower");
        let upper = named_device(&mut om, drv, "\\Device\\Upper");
        assert_eq!(om.attach_device_to_stack(upper, lower), Ok(lower));

        assert_eq!(
            om.delete_device(lower).err(),
            Some(NtStatus::DELETE_PENDING)
        );
        assert!(om.device(lower).unwrap().delete_pending);
        assert!(om.device(lower).is_some());

        assert_eq!(om.detach_device_from_stack(upper), Ok(lower));
        assert!(om.delete_device(upper).is_ok());
        assert!(om.device(upper).is_none());
        assert!(!om.devices_of(drv).contains(&upper));

        assert!(om.delete_device(lower).is_ok());
        assert!(om.device(lower).is_none());
        assert!(om.devices_of(drv).is_empty());
    }

    #[test]
    fn delete_device_waits_for_open_files() {
        let mut om = io();
        let client = om.register_client();
        let drv = om
            .create_driver(&path("\\Driver\\Refs"), Box::new(MockDriverBackend::new()))
            .unwrap();
        let dev = om
            .create_device(
                drv,
                Some(&path("\\Device\\Refs")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let _handle = om
            .open(
                client,
                &path("\\Device\\Refs"),
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();

        assert_eq!(
            om.can_delete_device(dev).err(),
            Some(NtStatus::DELETE_PENDING)
        );
        assert_eq!(om.delete_device(dev).err(), Some(NtStatus::DELETE_PENDING));
        assert!(om.device(dev).unwrap().delete_pending);
    }

    #[test]
    fn destroy_device_removes_object_manager_route() {
        let mut om = io();
        let drv = om
            .create_driver(
                &path("\\Driver\\DeleteOne"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let dev = om
            .create_device(
                drv,
                Some(&path("\\Device\\DeleteOne")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();

        assert!(om.destroy_device(dev).is_ok());
        assert!(om.device(dev).is_none());
        assert!(om.devices_of(drv).is_empty());
        assert_eq!(
            om.port_mut()
                .open_device_object(&path("\\Device\\DeleteOne")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn destroy_driver_removes_devices_and_driver_record() {
        let mut om = io();
        let drv = om
            .create_driver(
                &path("\\Driver\\Unloadable"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let dev0 = om
            .create_device(
                drv,
                Some(&path("\\Device\\Unload0")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let dev1 = om
            .create_device(
                drv,
                Some(&path("\\Device\\Unload1")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();

        let record = om.destroy_driver(drv).unwrap();
        assert_eq!(record.unload_state, DriverUnloadState::Unloaded);
        assert!(om.driver(drv).is_none());
        assert!(om.device(dev0).is_none());
        assert!(om.device(dev1).is_none());
        assert_eq!(
            om.port_mut().open_device_object(&path("\\Device\\Unload0")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            om.port_mut().open_device_object(&path("\\Device\\Unload1")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn destroy_driver_waits_for_open_device_references() {
        let mut om = io();
        let client = om.register_client();
        let drv = om
            .create_driver(&path("\\Driver\\Busy"), Box::new(MockDriverBackend::new()))
            .unwrap();
        let dev = om
            .create_device(
                drv,
                Some(&path("\\Device\\Busy")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let _handle = om
            .open(
                client,
                &path("\\Device\\Busy"),
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();

        assert_eq!(om.destroy_driver(drv).err(), Some(NtStatus::DELETE_PENDING));
        assert_eq!(
            om.driver(drv).unwrap().unload_state,
            DriverUnloadState::UnloadRequested
        );
        assert!(om.device(dev).unwrap().delete_pending);
        assert_eq!(
            om.port_mut().open_device_object(&path("\\Device\\Busy")),
            Ok(om.device(dev).unwrap().object_id)
        );
    }

    #[test]
    fn null_and_cross_store_ids_never_resolve() {
        let mut om = io();
        assert!(om.driver(DriverId::NULL).is_none());
        assert!(om.device(DeviceId::NULL).is_none());
        assert!(om.file(FileId::NULL).is_none());
        assert!(om.irp(IrpId::NULL).is_none());

        let drv = a_driver(&mut om);
        // A device id with the driver's bit pattern must not resolve as a device.
        assert!(om.device(DeviceId(drv.raw())).is_none());
    }

    #[test]
    fn file_lifecycle_transitions() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);
        let fid = om.add_file(FileRecord::new(
            ObjectId::NULL,
            ClientId(1),
            dev,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            Some(path("\\Device\\Test0")),
        ));

        let f = om.file_mut(fid).unwrap();
        assert_eq!(f.state, FileState::Allocated);
        assert!(f.transition(FileState::CreateIrpDispatched));
        assert!(f.transition(FileState::Open));
        assert!(f.state.is_open());
        assert!(!f.transition(FileState::Allocated)); // illegal
        assert!(f.transition(FileState::CleanupPending));
        assert!(f.transition(FileState::CleanupComplete));
        assert!(f.transition(FileState::ClosePending));
        assert!(f.transition(FileState::Closed));
        assert!(f.state.is_closed());
        assert!(!f.transition(FileState::Open)); // closed is terminal
    }

    #[test]
    fn irp_lifecycle_transitions() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);
        let iid = om
            .allocate_irp(IrpRecord::new(ClientId(1), dev, None, major::IRP_MJ_CREATE))
            .unwrap();

        let irp = om.irp_mut(iid).unwrap();
        assert_eq!(irp.state, IrpState::Allocated);
        assert_eq!(irp.status, NtStatus::PENDING);
        assert!(!irp.transition(IrpState::Completed)); // can't skip to completion
        assert!(irp.transition(IrpState::Initialized));
        assert!(irp.transition(IrpState::Dispatched));
        assert!(irp.transition(IrpState::Completing));
        assert!(irp.transition(IrpState::Completed));
        assert!(irp.state.is_final());
        assert!(!irp.transition(IrpState::Completed)); // no double-completion
        assert!(irp.transition(IrpState::Freed));
    }

    #[test]
    fn irp_pending_then_cancel_path() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);
        let iid = om
            .allocate_irp(IrpRecord::new(ClientId(1), dev, None, major::IRP_MJ_READ))
            .unwrap();
        let irp = om.irp_mut(iid).unwrap();
        assert!(irp.transition(IrpState::Initialized));
        assert!(irp.transition(IrpState::Dispatched));
        assert!(irp.transition(IrpState::Pending));
        assert!(irp.transition(IrpState::CancelRequested));
        assert!(irp.transition(IrpState::Cancelled));
        assert!(irp.transition(IrpState::Freed));
    }

    #[test]
    fn major_function_table() {
        let mut t = MajorFunctionTable::new();
        assert_eq!(t.get(major::IRP_MJ_CREATE), DispatchTarget::Unsupported);
        t.set(
            major::IRP_MJ_CREATE,
            DispatchTarget::Mock(MockDispatchId(7)),
        );
        assert_eq!(
            t.get(major::IRP_MJ_CREATE),
            DispatchTarget::Mock(MockDispatchId(7))
        );
        assert_eq!(t.get(0xff), DispatchTarget::Unsupported); // out of range
        t.set_all(DispatchTarget::DriverPeer(DriverPeerId(3)));
        assert_eq!(
            t.get(major::IRP_MJ_DEVICE_CONTROL),
            DispatchTarget::DriverPeer(DriverPeerId(3))
        );
        t.retarget(DispatchTarget::DriverPeer(DriverPeerId(9)));
        assert_eq!(
            t.get(major::IRP_MJ_DEVICE_CONTROL),
            DispatchTarget::DriverPeer(DriverPeerId(9))
        );
        t.retarget(DispatchTarget::Kernel(DriverBackendId(11)));
        assert_eq!(
            t.get(major::IRP_MJ_DEVICE_CONTROL),
            DispatchTarget::Kernel(DriverBackendId(11))
        );
    }

    #[test]
    fn driver_peer_create_uses_object_port_and_supplied_major_table() {
        let mut om = io();
        let mut dispatch = MajorFunctionTable::new();
        dispatch.set(
            major::IRP_MJ_DEVICE_CONTROL,
            DispatchTarget::DriverPeer(DriverPeerId(0)),
        );
        let driver = om
            .create_driver_peer_with_major_table(
                &path("\\Driver\\Peer"),
                Box::new(MockDriverBackend::new()),
                dispatch,
            )
            .unwrap();
        let record = om.driver(driver).unwrap();
        assert_ne!(record.object_id, ObjectId::NULL);
        assert_eq!(
            record.dispatch.get(major::IRP_MJ_DEVICE_CONTROL),
            DispatchTarget::DriverPeer(DriverPeerId(record.backend.0))
        );
        assert_eq!(
            record.dispatch.get(major::IRP_MJ_CREATE),
            DispatchTarget::Unsupported
        );
    }

    #[test]
    fn kernel_driver_create_uses_kernel_backend_target() {
        let mut om = io();
        let mut dispatch = MajorFunctionTable::new();
        dispatch.set(
            major::IRP_MJ_DEVICE_CONTROL,
            DispatchTarget::Kernel(DriverBackendId(0)),
        );
        let driver = om
            .create_kernel_driver_with_major_table(
                &path("\\Driver\\KernelVideo"),
                Box::new(MockDriverBackend::new()),
                dispatch,
            )
            .unwrap();
        let record = om.driver(driver).unwrap();
        assert_ne!(record.object_id, ObjectId::NULL);
        assert_eq!(
            record.dispatch.get(major::IRP_MJ_DEVICE_CONTROL),
            DispatchTarget::Kernel(record.backend)
        );
        assert_eq!(
            record.dispatch.get(major::IRP_MJ_CREATE),
            DispatchTarget::Unsupported
        );
    }

    proptest! {
        /// Random insert/remove sequences keep the store consistent: every live
        /// id resolves, every removed id stays stale, and the count matches.
        #[test]
        fn store_stays_consistent(ops in prop::collection::vec(any::<bool>(), 0..200)) {
            let mut store: GenStore<IrpId, u64> = GenStore::new();
            let mut live: std::vec::Vec<(IrpId, u64)> = std::vec::Vec::new();
            let mut stale: std::vec::Vec<IrpId> = std::vec::Vec::new();
            let mut counter = 0u64;

            for insert in ops {
                if insert || live.is_empty() {
                    let val = counter;
                    counter += 1;
                    let id = store.insert(val);
                    prop_assert_eq!(store.get(id), Some(&val));
                    live.push((id, val));
                } else {
                    let (id, val) = live.remove(live.len() / 2);
                    prop_assert_eq!(store.remove(id), Some(val));
                    stale.push(id);
                }
                // Invariants after every op.
                prop_assert_eq!(store.len(), live.len());
                for (id, val) in &live {
                    prop_assert_eq!(store.get(*id), Some(val));
                }
                for id in &stale {
                    prop_assert!(store.get(*id).is_none());
                }
            }
        }
    }

    // --- Object Manager port (Milestone 3) ---------------------------------

    #[test]
    fn mock_port_device_open_and_symlink() {
        let mut port = MockObjectPort::new();
        // Create a named device + a DOS-devices symlink to it.
        let dev = port
            .create_device_object(Some(&path("\\Device\\Test0")), 100)
            .unwrap();
        port.create_symbolic_link(&path("\\??\\Test0"), &path("\\Device\\Test0"))
            .unwrap();

        // Open by direct path and via the symlink both resolve to the device.
        assert_eq!(port.open_device_object(&path("\\Device\\Test0")), Ok(dev));
        assert_eq!(port.open_device_object(&path("\\??\\Test0")), Ok(dev));
        assert_eq!(
            port.open_device_object(&path("\\Device\\Missing")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert!(port.reference_device(dev).is_ok());
    }

    #[test]
    fn mock_port_file_handle_lifecycle() {
        let mut port = MockObjectPort::new();
        let client = port.register_client();
        let dev = port
            .create_device_object(Some(&path("\\Device\\Test0")), 1)
            .unwrap();

        let (file, handle) = port
            .create_file_object_and_handle(client, dev, 7, AccessMask::GENERIC_READ)
            .unwrap();

        // Reference within granted access succeeds; beyond it is denied.
        assert_eq!(
            port.reference_file_by_handle(client, handle, AccessMask::GENERIC_READ),
            Ok(file)
        );
        assert_eq!(
            port.reference_file_by_handle(client, handle, AccessMask::GENERIC_WRITE),
            Err(NtStatus::ACCESS_DENIED)
        );
        // Another client cannot use this handle.
        let other = port.register_client();
        assert_eq!(
            port.reference_file_by_handle(other, handle, AccessMask::GENERIC_READ),
            Err(NtStatus::INVALID_HANDLE)
        );
        // Close makes it stale.
        assert!(port.close_handle(client, handle).is_ok());
        assert_eq!(
            port.reference_file_by_handle(client, handle, AccessMask::GENERIC_READ),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    #[test]
    fn mock_port_bad_device_and_symlink_errors() {
        let mut port = MockObjectPort::new();
        let client = port.register_client();
        // File-and-handle against an unknown device object fails.
        assert_eq!(
            port.create_file_object_and_handle(client, ObjectId(999), 1, AccessMask::empty()),
            Err(NtStatus::INVALID_PARAMETER)
        );
        // reference_device rejects a non-device id.
        assert_eq!(
            port.reference_device(ObjectId(999)),
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        );
        // Duplicate symlink + delete of a missing link.
        port.create_symbolic_link(&path("\\??\\A"), &path("\\Device\\A"))
            .unwrap();
        assert_eq!(
            port.create_symbolic_link(&path("\\??\\A"), &path("\\Device\\A")),
            Err(NtStatus::OBJECT_NAME_COLLISION)
        );
        assert!(port.delete_symbolic_link(&path("\\??\\A")).is_ok());
        assert_eq!(
            port.delete_symbolic_link(&path("\\??\\A")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
    }

    // --- Mock driver backend (Milestone 4) ---------------------------------

    fn projection(major: u8, parameters: IoParameters) -> IrpProjection {
        IrpProjection {
            irp_id: IrpId::new(1, 1),
            device_id: DeviceId::new(1, 1),
            file_id: None,
            major,
            minor: 0,
            parameters,
            buffer: None,
            user_data: 0,
            requestor_tid: 0,
        }
    }

    fn ctx<'a>(buf: &'a mut [u8]) -> DispatchContext<'a> {
        DispatchContext::new(DriverId::NULL, ClientId(1), buf)
    }

    #[test]
    fn mock_create_sync_and_failure() {
        let mut d = MockDriverBackend::new();
        let mut buf = [0u8; 0];
        let create = || {
            projection(
                major::IRP_MJ_CREATE,
                IoParameters::Create(Default::default()),
            )
        };
        assert_eq!(
            d.dispatch_irp(ctx(&mut buf), &create()).unwrap(),
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            }
        );
        d.set_create_status(NtStatus::ACCESS_DENIED);
        assert_eq!(
            d.dispatch_irp(ctx(&mut buf), &create()).unwrap(),
            DispatchOutcome::Failed {
                status: NtStatus::ACCESS_DENIED
            }
        );
    }

    #[test]
    fn mock_read_returns_fixed_data() {
        let mut d = MockDriverBackend::new().with_read_data(b"hello");
        let mut buf = [0u8; 16];
        let out = d
            .dispatch_irp(
                ctx(&mut buf),
                &projection(
                    major::IRP_MJ_READ,
                    IoParameters::Read(ReadWriteParameters {
                        length: 5,
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        assert_eq!(
            out,
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 5,
                file_context: None,
            }
        );
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn mock_write_records_bytes() {
        let mut d = MockDriverBackend::new();
        let mut buf = *b"payload!";
        let out = d
            .dispatch_irp(
                ctx(&mut buf),
                &projection(
                    major::IRP_MJ_WRITE,
                    IoParameters::Write(ReadWriteParameters {
                        length: 8,
                        ..Default::default()
                    }),
                ),
            )
            .unwrap();
        assert_eq!(
            out,
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 8,
                file_context: None,
            }
        );
        assert_eq!(d.written(), b"payload!");
    }

    #[test]
    fn mock_ioctl_echo_and_status() {
        let mut d = MockDriverBackend::new();
        let dc = IoParameters::DeviceControl(DeviceControlParameters {
            ioctl_code: 0,
            input_len: 8,
            output_len: 8,
        });
        let mut buf = *b"in-data-more";
        assert_eq!(
            d.dispatch_irp(
                ctx(&mut buf),
                &projection(major::IRP_MJ_DEVICE_CONTROL, dc.clone())
            )
            .unwrap(),
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 8,
                file_context: None,
            }
        );
        d.set_ioctl(IoctlBehavior::Status(NtStatus::NOT_SUPPORTED));
        let mut buf2 = [0u8; 4];
        assert_eq!(
            d.dispatch_irp(
                ctx(&mut buf2),
                &projection(major::IRP_MJ_DEVICE_CONTROL, dc)
            )
            .unwrap(),
            DispatchOutcome::Failed {
                status: NtStatus::NOT_SUPPORTED
            }
        );
    }

    #[test]
    fn mock_pending_then_complete() {
        let mut d = MockDriverBackend::new();
        d.set_force_pending(true);
        let mut buf = [0u8; 0];
        let irp = IrpId::new(1, 5);
        let mut p = projection(major::IRP_MJ_READ, IoParameters::Read(Default::default()));
        p.irp_id = irp;
        assert_eq!(
            d.dispatch_irp(ctx(&mut buf), &p).unwrap(),
            DispatchOutcome::Pending
        );
        assert!(d.is_pending(irp));
        assert_eq!(
            d.complete_pending(irp, NtStatus::SUCCESS, 42).unwrap(),
            DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 42,
                file_context: None,
            }
        );
        assert!(!d.is_pending(irp));
        assert!(d.complete_pending(irp, NtStatus::SUCCESS, 0).is_err());
    }

    #[test]
    fn mock_pending_then_cancel() {
        let mut d = MockDriverBackend::new();
        d.set_force_pending(true);
        let mut buf = [0u8; 0];
        let irp = IrpId::new(1, 6);
        let mut p = projection(major::IRP_MJ_WRITE, IoParameters::Write(Default::default()));
        p.irp_id = irp;
        d.dispatch_irp(ctx(&mut buf), &p).unwrap();
        assert!(d.cancel_irp(irp).is_ok());
        assert!(d.was_cancelled(irp));
        assert!(!d.is_pending(irp));
        assert!(d.cancel_irp(irp).is_err());
    }

    #[test]
    fn mock_error_injection_and_unsupported_major() {
        let mut d = MockDriverBackend::new();
        d.inject_error(Some(NtStatus::DEVICE_NOT_CONNECTED));
        let mut buf = [0u8; 0];
        assert_eq!(
            d.dispatch_irp(
                ctx(&mut buf),
                &projection(
                    major::IRP_MJ_CREATE,
                    IoParameters::Create(Default::default())
                )
            )
            .unwrap(),
            DispatchOutcome::Failed {
                status: NtStatus::DEVICE_NOT_CONNECTED
            }
        );
        d.inject_error(None);
        assert_eq!(
            d.dispatch_irp(
                ctx(&mut buf),
                &projection(major::IRP_MJ_PNP, IoParameters::Pnp)
            )
            .unwrap(),
            DispatchOutcome::Failed {
                status: NtStatus::INVALID_DEVICE_REQUEST
            }
        );
    }

    // --- Open / create path (Milestone 5) ----------------------------------

    fn setup_device(om: &mut IoManager<MockObjectPort>) -> ClientId {
        let client = om.register_client();
        let driver = om
            .create_driver(&path("\\Driver\\Test"), Box::new(MockDriverBackend::new()))
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        om.create_symbolic_link(&path("\\??\\Test0"), &path("\\Device\\Test0"))
            .unwrap();
        client
    }

    #[test]
    fn io_manager_deletes_symbolic_link_through_port() {
        let mut om = IoManager::new(MockObjectPort::new());
        let _client = setup_device(&mut om);

        assert!(om
            .port_mut()
            .open_device_object(&path("\\??\\Test0"))
            .is_ok());
        assert!(om.delete_symbolic_link(&path("\\??\\Test0")).is_ok());
        assert_eq!(
            om.port_mut().open_device_object(&path("\\??\\Test0")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            om.delete_symbolic_link(&path("\\??\\Test0")),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
    }

    fn open_read(
        om: &mut IoManager<MockObjectPort>,
        client: ClientId,
        p: &str,
    ) -> Result<HandleValue, NtStatus> {
        om.open(
            client,
            &path(p),
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            0,
        )
    }

    #[test]
    fn open_by_path_and_symlink() {
        let mut om = io();
        let client = setup_device(&mut om);
        let h1 = open_read(&mut om, client, "\\Device\\Test0").unwrap();
        assert_eq!(om.file_count(), 1);
        assert_eq!(om.irp_count(), 0); // create IRP freed on completion
        let h2 = open_read(&mut om, client, "\\??\\Test0").unwrap();
        assert_ne!(h1, h2);
        assert_eq!(om.file_count(), 2);
    }

    #[test]
    fn open_file_details_reference_canonical_file_and_device() {
        let mut om = io();
        let client = setup_device(&mut om);
        let handle = open_read(&mut om, client, "\\Device\\Test0").unwrap();
        let (file_id, device_id, file_object) = om
            .reference_open_file_details(client, handle, AccessMask::GENERIC_READ)
            .unwrap();

        let file = om.file(file_id).unwrap();
        assert_eq!(file.device_id, device_id);
        assert_eq!(file.object_id, file_object);
        assert_ne!(file_object, ObjectId::NULL);
        assert_eq!(
            om.reference_open_file_details(client, handle, AccessMask::GENERIC_WRITE),
            Err(NtStatus::ACCESS_DENIED)
        );
    }

    #[test]
    fn open_unknown_path_rejected() {
        let mut om = io();
        let client = setup_device(&mut om);
        assert_eq!(
            open_read(&mut om, client, "\\Device\\Missing"),
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(om.file_count(), 0);
    }

    #[test]
    fn open_create_failure_cleans_up() {
        let mut om = io();
        let client = om.register_client();
        let mut bad = MockDriverBackend::new();
        bad.set_create_status(NtStatus::ACCESS_DENIED);
        let driver = om
            .create_driver(&path("\\Driver\\Bad"), Box::new(bad))
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Bad0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        assert_eq!(
            open_read(&mut om, client, "\\Device\\Bad0"),
            Err(NtStatus::ACCESS_DENIED)
        );
        assert_eq!(om.file_count(), 0); // FileRecord removed
        assert_eq!(om.irp_count(), 0); // IRP freed
    }

    // --- Read / write / device-control (Milestone 6) -----------------------

    fn open_device_with(
        mock: MockDriverBackend,
        access: AccessMask,
    ) -> (IoManager<MockObjectPort>, ClientId, HandleValue) {
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(&path("\\Driver\\Test"), Box::new(mock))
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = om
            .open(
                client,
                &path("\\Device\\Test0"),
                access,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        (om, client, handle)
    }

    fn any_ioctl(function: u32, method: u32) -> u32 {
        ioctl::ctl_code(0x22, function, method, ioctl::FILE_ANY_ACCESS)
    }

    #[test]
    fn read_returns_driver_data() {
        let (mut om, client, handle) = open_device_with(
            MockDriverBackend::new().with_read_data(b"hello"),
            AccessMask::GENERIC_READ,
        );
        let mut out = [0u8; 16];
        let n = om.read(client, handle, 0, &mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out[..5], b"hello");
        assert_eq!(om.irp_count(), 0); // request IRP freed
    }

    #[test]
    fn write_then_read_round_trips() {
        let (mut om, client, handle) = open_device_with(
            MockDriverBackend::new(),
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        );
        assert_eq!(om.write(client, handle, 0, b"world").unwrap(), 5);
        let mut out = [0u8; 8];
        let n = om.read(client, handle, 0, &mut out).unwrap();
        assert_eq!(&out[..n as usize], b"world");
    }

    #[test]
    fn ioctl_echo_round_trips() {
        let (mut om, client, handle) =
            open_device_with(MockDriverBackend::new(), AccessMask::GENERIC_READ);
        let code = any_ioctl(0x800, ioctl::METHOD_BUFFERED);
        let mut out = [0u8; 8];
        let n = om
            .device_control(client, handle, code, b"ping", &mut out)
            .unwrap();
        assert_eq!(&out[..n as usize], b"ping");
    }

    #[test]
    fn ioctl_direct_and_neither_methods_round_trip() {
        let (mut om, client, handle) =
            open_device_with(MockDriverBackend::new(), AccessMask::GENERIC_READ);
        for method in [
            ioctl::METHOD_IN_DIRECT,
            ioctl::METHOD_OUT_DIRECT,
            ioctl::METHOD_NEITHER,
        ] {
            let code = any_ioctl(0x801 + method, method);
            let mut out = [0u8; 8];
            let n = om
                .device_control(client, handle, code, b"pong", &mut out)
                .unwrap();
            assert_eq!(n, 4);
            assert_eq!(&out[..n as usize], b"pong");
        }
    }

    #[test]
    fn ioctl_fixed_status() {
        let mut mock = MockDriverBackend::new();
        mock.set_ioctl(IoctlBehavior::Status(NtStatus::INVALID_DEVICE_REQUEST));
        let (mut om, client, handle) = open_device_with(mock, AccessMask::GENERIC_READ);
        let code = any_ioctl(0x802, ioctl::METHOD_BUFFERED);
        let mut out = [0u8; 8];
        assert_eq!(
            om.device_control(client, handle, code, b"x", &mut out),
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        );
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct RecordedDispatch {
        driver_id: DriverId,
        client_id: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        major: u8,
        user_data: u64,
        requestor_tid: u64,
        parameters: IoParameters,
        input_len: u32,
        output_len: u32,
        buffer: std::vec::Vec<u8>,
    }

    struct RecordingBackend {
        seen: std::rc::Rc<std::cell::RefCell<std::vec::Vec<RecordedDispatch>>>,
        status: NtStatus,
        information: u64,
        file_context: Option<u64>,
        output: std::vec::Vec<u8>,
    }

    impl DriverDispatchBackend for RecordingBackend {
        fn dispatch_irp(
            &mut self,
            ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            self.seen.borrow_mut().push(RecordedDispatch {
                driver_id: ctx.driver_id,
                client_id: ctx.client_id,
                device_id: irp.device_id,
                file_id: irp.file_id,
                major: irp.major,
                user_data: irp.user_data,
                requestor_tid: irp.requestor_tid,
                parameters: irp.parameters.clone(),
                input_len: irp.buffer.map(|b| b.input_len).unwrap_or(0),
                output_len: irp.buffer.map(|b| b.output_len).unwrap_or(0),
                buffer: ctx.system_buffer.to_vec(),
            });
            let n = self.output.len().min(ctx.system_buffer.len());
            ctx.system_buffer[..n].copy_from_slice(&self.output[..n]);
            Ok(DispatchOutcome::Completed {
                status: self.status,
                information: self.information,
                file_context: self.file_context,
            })
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            Err(NtStatus::INVALID_PARAMETER)
        }
    }

    fn external_recording_driver(
        om: &mut IoManager<MockObjectPort>,
        driver_path: &str,
        status: NtStatus,
        information: u64,
        output: &[u8],
    ) -> (
        DriverId,
        std::rc::Rc<std::cell::RefCell<std::vec::Vec<RecordedDispatch>>>,
    ) {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(std::vec::Vec::new()));
        let idx = om.register_backend(Box::new(RecordingBackend {
            seen: seen.clone(),
            status,
            information,
            file_context: None,
            output: output.to_vec(),
        }));
        let target = DispatchTarget::DriverPeer(DriverPeerId(idx as u64));
        let mut dispatch = MajorFunctionTable::new();
        dispatch.set_all(target);
        let driver = om.register_driver(DriverRecord::new(
            ObjectId::NULL,
            path(driver_path),
            DriverBackendId(idx as u64),
            dispatch,
        ));
        (driver, seen)
    }

    #[test]
    fn external_device_dispatch_preserves_raw_status_and_cookie() {
        let mut om = io();
        let warning = NtStatus(0x8000_0005u32 as i32); // STATUS_BUFFER_OVERFLOW.
        let (driver, seen) =
            external_recording_driver(&mut om, "\\Driver\\External", warning, 3, b"out");
        let device = om.add_device(DeviceRecord::new(
            ObjectId::NULL,
            driver,
            Some(path("\\Device\\External0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        ));
        let mut buf = *b"input";
        let params = IoParameters::SetInformation(InformationParameters {
            info_class: 23,
            length: buf.len() as u32,
        });

        let result = om
            .build_and_dispatch_external_to_device(
                ClientId(44),
                device,
                None,
                0xABCD,
                77,
                major::IRP_MJ_SET_INFORMATION,
                params.clone(),
                buf.len() as u32,
                0,
                &mut buf,
            )
            .unwrap();

        assert_eq!(
            result,
            ExternalDispatchResult::Completed {
                status: warning,
                information: 3,
                file_context: None,
            }
        );
        assert_eq!(&buf[..3], b"out");
        assert_eq!(om.irp_count(), 0);
        let seen = seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            RecordedDispatch {
                driver_id: driver,
                client_id: ClientId(44),
                device_id: device,
                file_id: None,
                major: major::IRP_MJ_SET_INFORMATION,
                user_data: 0xABCD,
                requestor_tid: 77,
                parameters: params,
                input_len: 5,
                output_len: 0,
                buffer: b"input".to_vec(),
            }
        );
    }

    #[test]
    fn external_driver_dispatch_supports_driver_without_device() {
        let mut om = io();
        let (driver, seen) =
            external_recording_driver(&mut om, "\\Driver\\NoDevice", NtStatus::SUCCESS, 4, b"pong");
        let params = IoParameters::DeviceControl(DeviceControlParameters {
            ioctl_code: 0x222000,
            input_len: 4,
            output_len: 4,
        });
        let mut buf = *b"ping";

        let result = om
            .build_and_dispatch_external_to_driver(
                ClientId(55),
                driver,
                None,
                0x1234,
                88,
                major::IRP_MJ_DEVICE_CONTROL,
                params,
                4,
                4,
                &mut buf,
            )
            .unwrap();

        assert_eq!(
            result,
            ExternalDispatchResult::Completed {
                status: NtStatus::SUCCESS,
                information: 4,
                file_context: None,
            }
        );
        assert_eq!(&buf, b"pong");
        assert_eq!(om.irp_count(), 0);
        let seen = seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].device_id, DeviceId::NULL);
        assert_eq!(seen[0].driver_id, driver);
        assert_eq!(seen[0].user_data, 0x1234);
        assert_eq!(seen[0].requestor_tid, 88);
        assert_eq!((seen[0].input_len, seen[0].output_len), (4, 4));
    }

    #[test]
    fn external_file_keeps_one_canonical_identity_from_create_through_close() {
        let mut om = io();
        let client = ClientId(66);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(std::vec::Vec::new()));
        let backend = RecordingBackend {
            seen: seen.clone(),
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: Some(0xCCB0),
            output: std::vec::Vec::new(),
        };
        let driver = om
            .create_driver(&path("\\Driver\\ExternalFile"), Box::new(backend))
            .unwrap();
        let device = om
            .create_device(
                driver,
                Some(&path("\\Device\\ExternalFile0")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let file_id = om
            .allocate_external_file(
                client,
                device,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                Some(path("\\Device\\ExternalFile0\\name")),
            )
            .unwrap();
        assert_eq!(om.file(file_id).unwrap().state, FileState::Allocated);

        let mut empty = [];
        let create = om
            .build_and_dispatch_external_to_device(
                client,
                device,
                Some(file_id),
                0xDEAD,
                77,
                major::IRP_MJ_CREATE,
                IoParameters::Create(CreateParameters::default()),
                0,
                0,
                &mut empty,
            )
            .unwrap();
        assert_eq!(
            create,
            ExternalDispatchResult::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: Some(0xCCB0),
            }
        );
        assert_eq!(om.external_file_context(client, file_id), Ok(Some(0xCCB0)));

        let mut data = [0u8; 1];
        om.build_and_dispatch_external_to_device(
            client,
            device,
            Some(file_id),
            0xBAD0,
            78,
            major::IRP_MJ_READ,
            IoParameters::Read(ReadWriteParameters {
                length: 1,
                key: 0,
                offset: 0,
            }),
            0,
            1,
            &mut data,
        )
        .unwrap();
        om.release_external_file(client, file_id).unwrap();
        assert!(om.file(file_id).is_none());

        let seen = seen.borrow();
        assert_eq!(
            seen.iter()
                .map(|entry| entry.major)
                .collect::<std::vec::Vec<_>>(),
            [
                major::IRP_MJ_CREATE,
                major::IRP_MJ_READ,
                major::IRP_MJ_CLEANUP,
                major::IRP_MJ_CLOSE,
            ]
        );
        assert!(seen.iter().all(|entry| entry.file_id == Some(file_id)));
        assert_eq!(seen[0].user_data, 0);
        assert!(seen[1..].iter().all(|entry| entry.user_data == 0xCCB0));
    }

    #[test]
    fn external_named_pipe_create_uses_the_canonical_file_lifecycle() {
        let mut om = io();
        let client = ClientId(67);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(std::vec::Vec::new()));
        let driver = om
            .create_driver(
                &path("\\Driver\\ExternalNamedPipe"),
                Box::new(RecordingBackend {
                    seen: seen.clone(),
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: Some(0xCCB1),
                    output: std::vec::Vec::new(),
                }),
            )
            .unwrap();
        let device = om
            .create_device(
                driver,
                Some(&path("\\Device\\ExternalNamedPipe0")),
                DeviceType::NAMED_PIPE,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let file_id = om
            .allocate_external_file(
                client,
                device,
                AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
                ShareAccess::READ | ShareAccess::WRITE,
                CreateOptions::empty(),
                Some(path("\\pipe\\svc")),
            )
            .unwrap();
        let mut empty = [];
        assert_eq!(
            om.build_and_dispatch_external_to_device(
                client,
                device,
                Some(file_id),
                0xDEAD,
                79,
                major::IRP_MJ_CREATE_NAMED_PIPE,
                IoParameters::Create(CreateParameters::default()),
                0,
                0,
                &mut empty,
            ),
            Ok(ExternalDispatchResult::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: Some(0xCCB1),
            })
        );
        assert_eq!(om.external_file_context(client, file_id), Ok(Some(0xCCB1)));
        om.release_external_file(client, file_id).unwrap();
        assert!(om.file(file_id).is_none());
        let seen = seen.borrow();
        assert_eq!(
            seen.iter()
                .map(|entry| entry.major)
                .collect::<std::vec::Vec<_>>(),
            [
                major::IRP_MJ_CREATE_NAMED_PIPE,
                major::IRP_MJ_CLEANUP,
                major::IRP_MJ_CLOSE,
            ]
        );
        assert!(seen.iter().all(|entry| entry.file_id == Some(file_id)));
        assert_eq!(seen[0].user_data, 0);
        assert!(seen[1..].iter().all(|entry| entry.user_data == 0xCCB1));
    }

    #[test]
    fn io_on_bad_handle_rejected() {
        let (mut om, client, _handle) =
            open_device_with(MockDriverBackend::new(), AccessMask::GENERIC_READ);
        let mut out = [0u8; 4];
        assert_eq!(
            om.read(client, HandleValue(9999), 0, &mut out),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    #[test]
    fn write_on_read_only_handle_denied() {
        let (mut om, client, handle) =
            open_device_with(MockDriverBackend::new(), AccessMask::GENERIC_READ);
        assert_eq!(
            om.write(client, handle, 0, b"nope"),
            Err(NtStatus::ACCESS_DENIED)
        );
    }

    // --- Completion / cancellation engine + cleanup/close ------------------

    #[test]
    fn external_pending_dispatch_retains_canonical_irp() {
        let mut om = io();
        let client = om.register_client();
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let driver = om
            .create_driver(&path("\\Driver\\ExternalPending"), Box::new(mock))
            .unwrap();
        let mut buffer = [0u8; 4];
        let result = om
            .build_and_dispatch_external_to_driver(
                client,
                driver,
                None,
                0xCAFE,
                99,
                major::IRP_MJ_DEVICE_CONTROL,
                IoParameters::DeviceControl(DeviceControlParameters {
                    ioctl_code: 0x222000,
                    input_len: 4,
                    output_len: 4,
                }),
                4,
                4,
                &mut buffer,
            )
            .unwrap();
        let irp_id = match result {
            ExternalDispatchResult::Pending { irp_id } => irp_id,
            other => panic!("expected pending external dispatch, got {other:?}"),
        };
        let irp = om.irp(irp_id).unwrap();
        assert_eq!(irp.state, IrpState::Pending);
        assert_eq!(irp.driver_id, driver);
        assert_eq!((irp.user_data, irp.requestor_tid), (0xCAFE, 99));

        om.cancel(client, irp_id).unwrap();
        assert_eq!(om.irp(irp_id).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.pump(), 1);
        assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::CANCELLED);
        om.acknowledge_completed_irp(irp_id).unwrap();
        assert!(om.irp(irp_id).is_none());
    }

    #[test]
    fn completion_publication_authenticates_driver_and_terminal_status() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let (mut om, _client, irp) = pending_read(mock);
        let owner = om.irp(irp).unwrap().driver_id;
        let other = om
            .create_driver(
                &path("\\Driver\\OtherCompletionSource"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let completion = DriverCompletion {
            irp_id: irp,
            status: NtStatus::SUCCESS,
            information: 1,
            file_context: None,
        };
        assert!(!om.publish_driver_completion(other, completion));
        assert!(!om.publish_driver_completion(
            owner,
            DriverCompletion {
                status: NtStatus::PENDING,
                ..completion
            }
        ));
        assert_eq!(om.irp(irp).unwrap().state, IrpState::Pending);
        assert!(om.publish_driver_completion(owner, completion));
        assert!(!om.publish_driver_completion(owner, completion));
        om.acknowledge_completed_irp(irp).unwrap();
    }

    #[test]
    fn external_dispatch_rejects_stale_file_identity() {
        let (mut om, client, handle) =
            open_device_with(MockDriverBackend::new(), AccessMask::GENERIC_READ);
        let (file_id, device_id) = om
            .reference_open_file(client, handle, AccessMask::GENERIC_READ)
            .unwrap();
        let driver_id = om.device(device_id).unwrap().driver_id;
        om.close(client, handle).unwrap();
        let mut buffer = [0u8; 1];
        assert_eq!(
            om.build_and_dispatch_external_to_driver(
                client,
                driver_id,
                Some(file_id),
                0,
                0,
                major::IRP_MJ_READ,
                IoParameters::Read(ReadWriteParameters {
                    length: 1,
                    key: 0,
                    offset: 0,
                }),
                0,
                1,
                &mut buffer,
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    #[derive(Default)]
    struct PendingCreateBackend {
        ready: std::vec::Vec<DriverCompletion>,
    }

    impl DriverDispatchBackend for PendingCreateBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            if is_create_major(irp.major) {
                Ok(DispatchOutcome::Pending)
            } else {
                Ok(DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                })
            }
        }

        fn cancel_irp(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
            self.ready.push(DriverCompletion {
                irp_id,
                status: NtStatus::CANCELLED,
                information: 0,
                file_context: None,
            });
            Ok(())
        }

        fn poll_completion(&mut self) -> Option<DriverCompletion> {
            self.ready.pop()
        }
    }

    struct CompletingCreateBackend;

    impl DriverDispatchBackend for CompletingCreateBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            if is_create_major(irp.major) {
                Ok(DispatchOutcome::Pending)
            } else {
                Ok(DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                })
            }
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            Ok(())
        }
    }

    #[test]
    fn pending_create_is_cancelled_and_retained_until_ack() {
        let mut om = io();
        let client = om.register_client();
        om.create_driver(
            &path("\\Driver\\PendingCreate"),
            Box::new(PendingCreateBackend::default()),
        )
        .and_then(|driver| {
            om.create_device(
                driver,
                Some(&path("\\Device\\PendingCreate0")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
        })
        .unwrap();
        assert_eq!(
            open_read(&mut om, client, "\\Device\\PendingCreate0"),
            Err(NtStatus::PENDING)
        );
        let irp = om.pending_irps()[0];
        let file_id = om.irp(irp).unwrap().file_id.unwrap();
        assert_eq!(om.irp(irp).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.file(file_id).unwrap().state, FileState::ClosePending);
        assert_eq!(om.port().retained_reference_count(), 1);
        assert_eq!(om.pump(), 1);
        assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::CANCELLED);
        om.acknowledge_completed_irp(irp).unwrap();
        assert!(om.file(file_id).is_none());
        assert_eq!(om.port().retained_reference_count(), 0);
    }

    fn pending_external_create() -> (IoManager<MockObjectPort>, ClientId, DriverId, FileId, IrpId) {
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(
                &path("\\Driver\\CompletingCreate"),
                Box::new(CompletingCreateBackend),
            )
            .unwrap();
        let device = om
            .create_device(
                driver,
                Some(&path("\\Device\\CompletingCreate0")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let file_id = om
            .allocate_external_file(
                client,
                device,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                None,
            )
            .unwrap();
        let pending = om
            .build_and_dispatch_external_to_device(
                client,
                device,
                Some(file_id),
                0,
                81,
                major::IRP_MJ_CREATE,
                IoParameters::Create(CreateParameters::default()),
                0,
                0,
                &mut [],
            )
            .unwrap();
        let irp_id = match pending {
            ExternalDispatchResult::Pending { irp_id } => irp_id,
            other => panic!("expected pending create, got {other:?}"),
        };
        (om, client, driver, file_id, irp_id)
    }

    #[test]
    fn pending_create_publishes_open_file_and_context_before_ack() {
        let (mut om, _client, driver, file_id, irp_id) = pending_external_create();

        assert!(om.publish_driver_completion(
            driver,
            DriverCompletion {
                irp_id,
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: Some(0xCAFE),
            }
        ));
        let file = om.file(file_id).unwrap();
        assert_eq!(file.state, FileState::Open);
        assert_eq!(file.driver_context, Some(0xCAFE));
        assert_eq!(om.completed_irp(irp_id).unwrap().file_context, Some(0xCAFE));

        om.acknowledge_completed_irp(irp_id).unwrap();
        assert_eq!(om.file(file_id).unwrap().state, FileState::Open);
    }

    #[test]
    fn pending_failed_create_closes_before_ack_and_retires_on_release() {
        let (mut om, client, driver, file_id, irp_id) = pending_external_create();

        assert!(om.publish_driver_completion(
            driver,
            DriverCompletion {
                irp_id,
                status: NtStatus::ACCESS_DENIED,
                information: 0,
                file_context: None,
            }
        ));
        assert_eq!(om.file(file_id).unwrap().state, FileState::Closed);
        om.acknowledge_completed_irp(irp_id).unwrap();
        om.release_external_file(client, file_id).unwrap();
        assert!(om.file(file_id).is_none());
    }

    #[test]
    fn released_pending_create_that_completes_successfully_closes_with_context() {
        let (mut om, client, driver, file_id, irp_id) = pending_external_create();

        om.release_external_file(client, file_id).unwrap();
        assert_eq!(om.file(file_id).unwrap().state, FileState::ClosePending);
        assert!(om.publish_driver_completion(
            driver,
            DriverCompletion {
                irp_id,
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: Some(0xBEEF),
            }
        ));
        let file = om.file(file_id).unwrap();
        assert_eq!(file.state, FileState::ClosePending);
        assert_eq!(file.driver_context, Some(0xBEEF));

        om.acknowledge_completed_irp(irp_id).unwrap();
        assert!(om.file(file_id).is_none());
    }

    #[test]
    fn releasing_pending_external_named_pipe_create_cancels_and_retires_file() {
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(
                &path("\\Driver\\PendingExternalPipe"),
                Box::new(PendingCreateBackend::default()),
            )
            .unwrap();
        let device = om
            .create_device(
                driver,
                Some(&path("\\Device\\PendingExternalPipe0")),
                DeviceType::NAMED_PIPE,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let file_id = om
            .allocate_external_file(
                client,
                device,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                Some(path("\\pipe\\pending")),
            )
            .unwrap();
        let mut empty = [];
        let pending = om
            .build_and_dispatch_external_to_device(
                client,
                device,
                Some(file_id),
                0,
                80,
                major::IRP_MJ_CREATE_NAMED_PIPE,
                IoParameters::Create(CreateParameters::default()),
                0,
                0,
                &mut empty,
            )
            .unwrap();
        let irp_id = match pending {
            ExternalDispatchResult::Pending { irp_id } => irp_id,
            other => panic!("expected pending named-pipe create, got {other:?}"),
        };
        om.release_external_file(client, file_id).unwrap();
        assert_eq!(om.file(file_id).unwrap().state, FileState::ClosePending);
        assert_eq!(om.irp(irp_id).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.pump(), 1);
        assert!(om.file(file_id).is_none());
        assert!(om.irp(irp_id).is_none());
        assert!(om.next_completed_irp().is_none());
    }

    fn pending_read(mock: MockDriverBackend) -> (IoManager<MockObjectPort>, ClientId, IrpId) {
        let (mut om, client, handle) = open_device_with(mock, AccessMask::GENERIC_READ);
        let mut out = [0u8; 8];
        assert_eq!(om.read(client, handle, 0, &mut out), Err(NtStatus::PENDING));
        let irp = om.pending_irps()[0];
        (om, client, irp)
    }

    #[test]
    fn pending_read_completes_via_pump() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        mock.set_pending_completion(NtStatus::SUCCESS, 4);
        let (mut om, _client, irp) = pending_read(mock);
        assert_eq!(om.pending_irps().len(), 1);
        assert_eq!(om.pump(), 1); // driver's completion is delivered
        assert!(om.pending_irps().is_empty());
        assert_eq!(om.irp(irp).unwrap().state, IrpState::Completed);
        assert_eq!(
            om.next_completed_irp(),
            Some(CompletedIrp {
                id: irp,
                client_id: om.irp(irp).unwrap().client_id,
                driver_id: om.irp(irp).unwrap().driver_id,
                file_id: om.irp(irp).unwrap().file_id,
                device_id: om.irp(irp).unwrap().device_id,
                major: major::IRP_MJ_READ,
                user_data: 0,
                requestor_tid: 0,
                status: NtStatus::SUCCESS,
                information: 4,
                file_context: None,
            })
        );
        om.acknowledge_completed_irp(irp).unwrap();
        assert!(om.irp(irp).is_none());
    }

    #[test]
    fn cancel_pending_irp() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true); // no completion queued
        let (mut om, client, irp) = pending_read(mock);
        om.cancel(client, irp).unwrap();
        assert_eq!(om.irp(irp).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.pump(), 1);
        assert!(om.pending_irps().is_empty());
        assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::CANCELLED);
        om.acknowledge_completed_irp(irp).unwrap();
        assert!(om.irp(irp).is_none());
    }

    #[test]
    fn cancel_file_thread_io_targets_exact_thread_and_drains_after_ack() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let (mut om, client, handle) = open_device_with(mock, AccessMask::GENERIC_READ);
        let mut out = [0u8; 1];
        assert_eq!(om.read(client, handle, 0, &mut out), Err(NtStatus::PENDING));
        assert_eq!(om.read(client, handle, 1, &mut out), Err(NtStatus::PENDING));
        assert_eq!(om.read(client, handle, 2, &mut out), Err(NtStatus::PENDING));
        let first_file = om
            .reference_open_file(client, handle, AccessMask::GENERIC_READ)
            .unwrap()
            .0;
        let first_device = om.file(first_file).unwrap().device_id;
        let driver = om.device(first_device).unwrap().driver_id;
        let _second_device = om
            .create_device(
                driver,
                Some(&path("\\Device\\Test1")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let second_handle = om
            .open(
                client,
                &path("\\Device\\Test1"),
                AccessMask::GENERIC_READ,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        assert_eq!(
            om.read(client, second_handle, 0, &mut out),
            Err(NtStatus::PENDING)
        );
        let irps = om.pending_irps();
        let file_id = om.irp(irps[0]).unwrap().file_id.unwrap();
        assert_eq!(file_id, first_file);
        om.irp_mut(irps[0]).unwrap().requestor_tid = 100;
        om.irp_mut(irps[1]).unwrap().requestor_tid = 100;
        om.irp_mut(irps[2]).unwrap().requestor_tid = 200;
        om.irp_mut(irps[3]).unwrap().requestor_tid = 100;
        assert_ne!(om.irp(irps[3]).unwrap().file_id, Some(file_id));

        let state = om.cancel_file_thread_io(client, file_id, 100).unwrap();
        assert_eq!(state.total, 2);
        assert_eq!(state.cancel_requested, 2);
        assert_eq!(state.terminal_unacknowledged, 0);
        assert_eq!(om.irp(irps[0]).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.irp(irps[1]).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.irp(irps[2]).unwrap().state, IrpState::Pending);
        assert_eq!(om.irp(irps[3]).unwrap().state, IrpState::Pending);

        assert_eq!(om.pump(), 2);
        let state = om.file_thread_io_drain_state(client, file_id, 100);
        assert_eq!(state.total, 2);
        assert_eq!(state.cancel_requested, 0);
        assert_eq!(state.terminal_unacknowledged, 2);
        assert!([irps[0], irps[1]].contains(&om.next_completed_irp().unwrap().id));
        om.acknowledge_completed_irp(irps[0]).unwrap();
        assert!(!om
            .file_thread_io_drain_state(client, file_id, 100)
            .is_drained());
        om.acknowledge_completed_irp(irps[1]).unwrap();
        assert!(om
            .file_thread_io_drain_state(client, file_id, 100)
            .is_drained());
        assert_eq!(om.irp(irps[2]).unwrap().state, IrpState::Pending);
        assert_eq!(om.irp(irps[3]).unwrap().state, IrpState::Pending);
    }

    #[test]
    fn cancel_file_thread_io_waits_for_normal_completion_ack() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        mock.set_pending_completion(NtStatus::SUCCESS, 1);
        let (mut om, client, irp) = pending_read(mock);
        let file_id = om.irp(irp).unwrap().file_id.unwrap();
        om.irp_mut(irp).unwrap().requestor_tid = 100;
        assert_eq!(om.pump(), 1);
        assert_eq!(om.irp(irp).unwrap().state, IrpState::Completed);

        let state = om.cancel_file_thread_io(client, file_id, 100).unwrap();
        assert_eq!(state.total, 1);
        assert_eq!(state.cancel_requested, 0);
        assert_eq!(state.terminal_unacknowledged, 1);
        assert!(!state.is_drained());
        assert_eq!(om.irp(irp).unwrap().status, NtStatus::SUCCESS);
        om.acknowledge_completed_irp(irp).unwrap();
        assert!(om
            .file_thread_io_drain_state(client, file_id, 100)
            .is_drained());
    }

    #[test]
    fn cancel_file_thread_io_validates_identity_before_side_effects() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let (mut om, client, irp) = pending_read(mock);
        let file_id = om.irp(irp).unwrap().file_id.unwrap();
        om.irp_mut(irp).unwrap().requestor_tid = 100;
        let other = om.register_client();

        assert_eq!(
            om.cancel_file_thread_io(client, file_id, 0),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            om.cancel_file_thread_io(other, file_id, 100),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(om.irp(irp).unwrap().state, IrpState::Pending);
        assert!(om
            .cancel_file_thread_io(client, file_id, 200)
            .unwrap()
            .is_drained());
        assert_eq!(om.irp(irp).unwrap().state, IrpState::Pending);
    }

    #[test]
    fn abandoned_pending_irp_is_cancelled_and_reclaimed_without_delivery() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let (mut om, client, irp) = pending_read(mock);
        om.abandon_irp_delivery(client, irp).unwrap();
        assert_eq!(om.irp(irp).unwrap().state, IrpState::CancelRequested);
        assert_eq!(om.pump(), 1);
        assert!(om.irp(irp).is_none());
        assert!(om.next_completed_irp().is_none());
    }

    #[test]
    fn cancel_other_client_denied() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let (mut om, _client, irp) = pending_read(mock);
        let other = om.register_client();
        assert_eq!(om.cancel(other, irp), Err(NtStatus::ACCESS_DENIED));
        assert_eq!(om.pending_irps().len(), 1); // still pending
    }

    #[test]
    fn cancel_racing_completion_is_exactly_once() {
        // Order A: no completion was ready, so the driver's cancellation result wins.
        {
            let mut mock = MockDriverBackend::new();
            mock.set_force_pending(true);
            let (mut om, client, irp) = pending_read(mock);
            om.cancel(client, irp).unwrap();
            assert_eq!(om.pump(), 1);
            assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::CANCELLED);
            om.acknowledge_completed_irp(irp).unwrap();
            assert!(om.irp(irp).is_none());
        }
        // Order B: a completion was already ready when cancel arrived, so it wins.
        {
            let mut mock = MockDriverBackend::new();
            mock.set_force_pending(true);
            mock.set_pending_completion(NtStatus::SUCCESS, 4);
            let (mut om, client, irp) = pending_read(mock);
            om.cancel(client, irp).unwrap();
            assert_eq!(om.pump(), 1);
            assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::SUCCESS);
            om.cancel(client, irp).unwrap();
            om.acknowledge_completed_irp(irp).unwrap();
            assert!(om.irp(irp).is_none());
        }
    }

    #[test]
    fn close_waits_for_completed_irp_acknowledgement() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        mock.set_pending_completion(NtStatus::SUCCESS, 4);
        let (mut om, client, handle) = open_device_with(mock, AccessMask::GENERIC_READ);
        let (file_id, _) = om
            .reference_open_file(client, handle, AccessMask::GENERIC_READ)
            .unwrap();
        let mut out = [0u8; 8];
        assert_eq!(om.read(client, handle, 0, &mut out), Err(NtStatus::PENDING));
        let irp = om.pending_irps()[0];
        let object = om.file(file_id).unwrap().object_id;
        assert_eq!(om.file(file_id).unwrap().outstanding_irp_refs, 1);
        assert!(om.port().is_object_retained(object));

        om.close(client, handle).unwrap();
        let file = om.file(file_id).unwrap();
        assert_eq!(file.state, FileState::ClosePending);
        assert!(file.close_deferred);
        assert!(!file.close_dispatched);
        assert_eq!(file.outstanding_irp_refs, 1);
        assert_eq!(
            om.read(client, handle, 0, &mut out),
            Err(NtStatus::INVALID_HANDLE)
        );

        assert_eq!(om.pump(), 1);
        assert!(om.file(file_id).is_some());
        assert!(om.port().is_object_retained(object));
        assert_eq!(om.file(file_id).unwrap().outstanding_irp_refs, 1);
        om.acknowledge_completed_irp(irp).unwrap();
        assert!(om.file(file_id).is_none());
        assert!(!om.port().is_object_retained(object));
    }

    #[test]
    fn completion_acknowledgement_can_release_independent_file_refs() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true);
        let (mut om, client, handle) = open_device_with(mock, AccessMask::GENERIC_READ);
        let (file_id, _) = om
            .reference_open_file(client, handle, AccessMask::GENERIC_READ)
            .unwrap();
        let mut out = [0u8; 1];
        assert_eq!(om.read(client, handle, 0, &mut out), Err(NtStatus::PENDING));
        assert_eq!(om.read(client, handle, 1, &mut out), Err(NtStatus::PENDING));
        let irps = om.pending_irps();
        assert_eq!(irps.len(), 2);
        assert_eq!(om.file(file_id).unwrap().outstanding_irp_refs, 2);
        om.close(client, handle).unwrap();

        om.cancel(client, irps[0]).unwrap();
        om.cancel(client, irps[1]).unwrap();
        assert_eq!(om.pump(), 2);
        let oldest = om.next_completed_irp().unwrap().id;
        let newer = if oldest == irps[0] { irps[1] } else { irps[0] };
        om.acknowledge_completed_irp(newer).unwrap();
        assert_eq!(om.file(file_id).unwrap().outstanding_irp_refs, 1);
        assert_eq!(om.next_completed_irp().unwrap().id, oldest);
        om.acknowledge_completed_irp(oldest).unwrap();
        assert!(om.file(file_id).is_none());
    }

    #[derive(Default)]
    struct RetainedOutputState {
        irp_id: Option<IrpId>,
        output: std::vec::Vec<u8>,
        completion_ready: bool,
        completion_status: NtStatus,
        fail_ack: bool,
        acknowledgements: usize,
        defer_completion_until_cancel: bool,
        cancel_failures_remaining: usize,
        cancel_attempts: usize,
    }

    struct RetainedOutputBackend {
        state: std::rc::Rc<std::cell::RefCell<RetainedOutputState>>,
    }

    impl DriverDispatchBackend for RetainedOutputBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            let mut state = self.state.borrow_mut();
            state.irp_id = Some(irp.irp_id);
            state.completion_ready = !state.defer_completion_until_cancel;
            Ok(DispatchOutcome::Pending)
        }

        fn cancel_irp(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
            let mut state = self.state.borrow_mut();
            if state.irp_id != Some(irp_id) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            state.cancel_attempts += 1;
            if state.cancel_failures_remaining != 0 {
                state.cancel_failures_remaining -= 1;
                return Err(NtStatus::DEVICE_NOT_READY);
            }
            state.completion_status = NtStatus::CANCELLED;
            state.completion_ready = true;
            Ok(())
        }

        fn poll_completion(&mut self) -> Option<DriverCompletion> {
            let mut state = self.state.borrow_mut();
            if !state.completion_ready {
                return None;
            }
            state.completion_ready = false;
            Some(DriverCompletion {
                irp_id: state.irp_id?,
                status: state.completion_status,
                information: state.output.len() as u64,
                file_context: None,
            })
        }

        fn copy_completion_output(
            &mut self,
            irp_id: IrpId,
            offset: u64,
            output: &mut [u8],
        ) -> Result<usize, NtStatus> {
            let state = self.state.borrow();
            let offset = usize::try_from(offset).map_err(|_| NtStatus::INVALID_PARAMETER)?;
            if state.irp_id != Some(irp_id) || offset > state.output.len() {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let copied = output.len().min(state.output.len() - offset);
            output[..copied].copy_from_slice(&state.output[offset..offset + copied]);
            Ok(copied)
        }

        fn acknowledge_completion(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
            let mut state = self.state.borrow_mut();
            if state.irp_id != Some(irp_id) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if state.fail_ack {
                return Err(NtStatus::DEVICE_NOT_READY);
            }
            state.irp_id = None;
            state.output.clear();
            state.acknowledgements += 1;
            Ok(())
        }
    }

    #[test]
    fn retained_output_is_exact_and_ack_failure_is_retryable() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(RetainedOutputState {
            output: b"done".to_vec(),
            completion_status: NtStatus::SUCCESS,
            ..RetainedOutputState::default()
        }));
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(
                &path("\\Driver\\RetainedOutput"),
                Box::new(RetainedOutputBackend {
                    state: state.clone(),
                }),
            )
            .unwrap();
        let mut dispatch_buffer = [0u8; 4];
        let result = om
            .build_and_dispatch_external_to_driver(
                client,
                driver,
                None,
                0,
                0,
                major::IRP_MJ_READ,
                IoParameters::Read(ReadWriteParameters {
                    length: 4,
                    key: 0,
                    offset: 0,
                }),
                0,
                4,
                &mut dispatch_buffer,
            )
            .unwrap();
        let irp_id = match result {
            ExternalDispatchResult::Pending { irp_id } => irp_id,
            other => panic!("expected retained pending output, got {other:?}"),
        };
        assert_eq!(om.pump(), 1);
        assert_eq!(om.completed_irp(irp_id).unwrap().information, 4);
        let mut output = [0u8; 4];
        assert_eq!(
            om.copy_completed_irp_output(irp_id, 0, &mut output[..2]),
            Ok(2)
        );
        assert_eq!(
            om.copy_completed_irp_output(irp_id, 2, &mut output[2..]),
            Ok(2)
        );
        assert_eq!(&output, b"done");
        let mut repeated = [0u8; 2];
        assert_eq!(
            om.copy_completed_irp_output(irp_id, 1, &mut repeated),
            Ok(2)
        );
        assert_eq!(&repeated, b"on");
        assert_eq!(
            om.copy_completed_irp_output(irp_id, 5, &mut output),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(om.copy_completed_irp_output(irp_id, 4, &mut output), Ok(0));

        state.borrow_mut().fail_ack = true;
        assert_eq!(
            om.acknowledge_completed_irp(irp_id),
            Err(NtStatus::DEVICE_NOT_READY)
        );
        assert_eq!(om.next_completed_irp().unwrap().id, irp_id);
        assert_eq!(om.copy_completed_irp_output(irp_id, 0, &mut output), Ok(4));

        state.borrow_mut().fail_ack = false;
        assert_eq!(om.acknowledge_completed_irp(irp_id).unwrap().id, irp_id);
        assert_eq!(state.borrow().acknowledgements, 1);
        assert!(om.completed_irp(irp_id).is_none());
        assert_eq!(
            om.copy_completed_irp_output(irp_id, 0, &mut output),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn rejected_backend_completion_ack_is_retried() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(RetainedOutputState {
            completion_status: NtStatus::PENDING,
            fail_ack: true,
            ..RetainedOutputState::default()
        }));
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(
                &path("\\Driver\\RejectedCompletion"),
                Box::new(RetainedOutputBackend {
                    state: state.clone(),
                }),
            )
            .unwrap();
        let mut buffer = [];
        let irp_id = match om
            .build_and_dispatch_external_to_driver(
                client,
                driver,
                None,
                0,
                0,
                major::IRP_MJ_READ,
                IoParameters::Read(ReadWriteParameters {
                    length: 0,
                    key: 0,
                    offset: 0,
                }),
                0,
                0,
                &mut buffer,
            )
            .unwrap()
        {
            ExternalDispatchResult::Pending { irp_id } => irp_id,
            other => panic!("expected pending request, got {other:?}"),
        };

        assert_eq!(om.pump(), 0);
        assert_eq!(state.borrow().irp_id, Some(irp_id));
        state.borrow_mut().fail_ack = false;
        assert_eq!(om.pump(), 1);
        assert_eq!(state.borrow().acknowledgements, 1);
        assert_eq!(state.borrow().irp_id, None);
    }

    #[test]
    fn failed_cancel_dispatch_is_retried_until_terminal_completion() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(RetainedOutputState {
            defer_completion_until_cancel: true,
            cancel_failures_remaining: 1,
            ..RetainedOutputState::default()
        }));
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(
                &path("\\Driver\\CancelRetry"),
                Box::new(RetainedOutputBackend {
                    state: state.clone(),
                }),
            )
            .unwrap();
        let mut buffer = [];
        let irp_id = match om
            .build_and_dispatch_external_to_driver(
                client,
                driver,
                None,
                0,
                0,
                major::IRP_MJ_READ,
                IoParameters::Read(ReadWriteParameters {
                    length: 0,
                    key: 0,
                    offset: 0,
                }),
                0,
                0,
                &mut buffer,
            )
            .unwrap()
        {
            ExternalDispatchResult::Pending { irp_id } => irp_id,
            other => panic!("expected pending request, got {other:?}"),
        };

        om.cancel(client, irp_id).unwrap();
        assert_eq!(state.borrow().cancel_attempts, 1);
        assert_eq!(om.pump(), 2, "retry dispatch plus terminal publication");
        assert_eq!(state.borrow().cancel_attempts, 2);
        assert_eq!(
            om.completed_irp(irp_id).unwrap().status,
            NtStatus::CANCELLED
        );
        om.acknowledge_completed_irp(irp_id).unwrap();
    }

    #[derive(Default)]
    struct LifecycleDispatchState {
        majors: std::vec::Vec<u8>,
        reject_first_close: bool,
        close_attempts: usize,
        accepted_closes: usize,
        pending_lifecycle: bool,
        completion_ready: bool,
        pending_irps: std::collections::VecDeque<IrpId>,
        published_irp: Option<IrpId>,
        fail_acknowledgements: usize,
        acknowledgements: usize,
        cancel_attempts: usize,
    }

    struct LifecycleDispatchBackend {
        state: std::rc::Rc<std::cell::RefCell<LifecycleDispatchState>>,
    }

    impl DriverDispatchBackend for LifecycleDispatchBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            let mut state = self.state.borrow_mut();
            state.majors.push(irp.major);
            if irp.major == major::IRP_MJ_CLOSE {
                state.close_attempts += 1;
                if state.reject_first_close && state.close_attempts == 1 {
                    return Err(NtStatus::DEVICE_NOT_READY);
                }
                state.accepted_closes += 1;
            }
            if state.pending_lifecycle
                && matches!(irp.major, major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE)
            {
                state.pending_irps.push_back(irp.irp_id);
                return Ok(DispatchOutcome::Pending);
            }
            Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            })
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            self.state.borrow_mut().cancel_attempts += 1;
            Err(NtStatus::NOT_SUPPORTED)
        }

        fn poll_completion(&mut self) -> Option<DriverCompletion> {
            let mut state = self.state.borrow_mut();
            if !state.completion_ready || state.published_irp.is_some() {
                return None;
            }
            let irp_id = state.pending_irps.pop_front()?;
            state.completion_ready = false;
            state.published_irp = Some(irp_id);
            Some(DriverCompletion {
                irp_id,
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            })
        }

        fn acknowledge_completion(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
            let mut state = self.state.borrow_mut();
            if state.published_irp != Some(irp_id) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            if state.fail_acknowledgements != 0 {
                state.fail_acknowledgements -= 1;
                return Err(NtStatus::DEVICE_NOT_READY);
            }
            state.published_irp = None;
            state.acknowledgements += 1;
            Ok(())
        }
    }

    fn lifecycle_device(
        state: std::rc::Rc<std::cell::RefCell<LifecycleDispatchState>>,
    ) -> (IoManager<MockObjectPort>, ClientId, HandleValue, FileId) {
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver(
                &path("\\Driver\\Lifecycle"),
                Box::new(LifecycleDispatchBackend { state }),
            )
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Lifecycle")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = om
            .open(
                client,
                &path("\\Device\\Lifecycle"),
                AccessMask::GENERIC_READ,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let file_id = om
            .reference_open_file(client, handle, AccessMask::GENERIC_READ)
            .unwrap()
            .0;
        (om, client, handle, file_id)
    }

    #[test]
    fn rejected_close_dispatch_retries_before_releasing_file() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(LifecycleDispatchState {
            reject_first_close: true,
            ..LifecycleDispatchState::default()
        }));
        let (mut om, client, handle, file_id) = lifecycle_device(state.clone());
        om.close(client, handle).unwrap();
        let file = om.file(file_id).expect("rejected close retains file");
        assert_eq!(file.state, FileState::ClosePending);
        assert!(!file.close_dispatched);
        assert_eq!(state.borrow().accepted_closes, 0);

        assert_eq!(om.pump(), 1);
        assert!(om.file(file_id).is_none());
        let state = state.borrow();
        assert_eq!(state.close_attempts, 2);
        assert_eq!(state.accepted_closes, 1);
    }

    #[test]
    fn pending_external_lifecycle_completes_without_cancellation() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(LifecycleDispatchState {
            pending_lifecycle: true,
            ..LifecycleDispatchState::default()
        }));
        let (mut om, client, _handle, file_id) = lifecycle_device(state.clone());

        om.release_external_file(client, file_id).unwrap();
        assert_eq!(om.file(file_id).unwrap().state, FileState::CleanupPending);
        assert_eq!(om.pending_irps().len(), 1);
        assert_eq!(state.borrow().cancel_attempts, 0);

        state.borrow_mut().completion_ready = true;
        assert_eq!(om.pump(), 1);
        assert_eq!(om.file(file_id).unwrap().state, FileState::ClosePending);
        assert_eq!(om.pending_irps().len(), 1);
        assert!(om.next_completed_irp().is_none());
        assert_eq!(state.borrow().acknowledgements, 1);
        assert_eq!(state.borrow().cancel_attempts, 0);

        state.borrow_mut().completion_ready = true;
        assert_eq!(om.pump(), 1);
        assert!(om.file(file_id).is_none());
        assert_eq!(om.irp_count(), 0);
        assert!(om.next_completed_irp().is_none());
        let state = state.borrow();
        assert_eq!(state.acknowledgements, 2);
        assert_eq!(state.cancel_attempts, 0);
        assert_eq!(
            state.majors,
            std::vec![
                major::IRP_MJ_CREATE,
                major::IRP_MJ_CLEANUP,
                major::IRP_MJ_CLOSE
            ]
        );
    }

    #[test]
    fn pending_lifecycle_ack_failure_preserves_exact_owner_for_retry() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(LifecycleDispatchState {
            pending_lifecycle: true,
            fail_acknowledgements: 1,
            ..LifecycleDispatchState::default()
        }));
        let (mut om, client, _handle, file_id) = lifecycle_device(state.clone());

        om.release_external_file(client, file_id).unwrap();
        let cleanup_irp = om.pending_irps()[0];
        state.borrow_mut().completion_ready = true;
        assert_eq!(om.pump(), 1);
        assert_eq!(
            om.completed_irp(cleanup_irp).unwrap().major,
            major::IRP_MJ_CLEANUP
        );
        assert_eq!(om.file(file_id).unwrap().state, FileState::CleanupPending);
        assert_eq!(state.borrow().acknowledgements, 0);
        assert_eq!(state.borrow().cancel_attempts, 0);

        assert_eq!(om.pump(), 0);
        assert!(om.irp(cleanup_irp).is_none());
        assert_eq!(om.file(file_id).unwrap().state, FileState::ClosePending);
        assert_eq!(state.borrow().acknowledgements, 1);
        assert_eq!(state.borrow().cancel_attempts, 0);

        state.borrow_mut().completion_ready = true;
        assert_eq!(om.pump(), 1);
        assert!(om.file(file_id).is_none());
        assert_eq!(state.borrow().acknowledgements, 2);
        assert_eq!(state.borrow().cancel_attempts, 0);
    }

    #[test]
    fn disconnect_dispatches_cleanup_then_close_before_retiring_client() {
        let state = std::rc::Rc::new(std::cell::RefCell::new(LifecycleDispatchState::default()));
        let (mut om, client, _handle, file_id) = lifecycle_device(state.clone());
        om.disconnect_client(client).unwrap();
        assert!(om.file(file_id).is_none());
        assert_eq!(
            state.borrow().majors,
            std::vec![
                major::IRP_MJ_CREATE,
                major::IRP_MJ_CLEANUP,
                major::IRP_MJ_CLOSE
            ]
        );
    }

    #[test]
    fn cleanup_close_lifecycle() {
        let (mut om, client, handle) = open_device_with(
            MockDriverBackend::new(),
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        );
        let mut out = [0u8; 8];
        assert!(om.read(client, handle, 0, &mut out).is_ok());

        // Cleanup: the file is no longer usable for reads.
        om.cleanup(client, handle).unwrap();
        assert_eq!(
            om.read(client, handle, 0, &mut out),
            Err(NtStatus::FILE_CLOSED)
        );

        // Close: the record is dropped + the handle is invalidated.
        assert_eq!(om.file_count(), 1);
        om.close(client, handle).unwrap();
        assert_eq!(om.file_count(), 0);
        assert_eq!(
            om.read(client, handle, 0, &mut out),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    // --- Driver-peer backend (Milestone 8) ---------------------------------

    fn peer_device(
        control: &MockPeerControl,
        access: AccessMask,
    ) -> (IoManager<MockObjectPort>, ClientId, HandleValue) {
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver_peer(
                &path("\\Driver\\Peer"),
                Box::new(DriverPeerBackend::new(control.transport())),
            )
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Peer0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = om
            .open(
                client,
                &path("\\Device\\Peer0"),
                access,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        (om, client, handle)
    }

    #[test]
    fn peer_sync_read_write_ioctl() {
        let ctrl = MockPeerControl::new();
        let (mut om, client, handle) =
            peer_device(&ctrl, AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE);

        // write -> read loopback through the peer protocol
        assert_eq!(om.write(client, handle, 0, b"peer!").unwrap(), 5);
        assert_eq!(ctrl.written(), b"peer!".to_vec());
        let mut out = [0u8; 8];
        let n = om.read(client, handle, 0, &mut out).unwrap();
        assert_eq!(&out[..n as usize], b"peer!");

        // echoing IOCTL (equal input/output lengths)
        let code = any_ioctl(0x800, ioctl::METHOD_BUFFERED);
        let mut io_out = [0u8; 4];
        let n = om
            .device_control(client, handle, code, b"ping", &mut io_out)
            .unwrap();
        assert_eq!(&io_out[..n as usize], b"ping");
        assert_eq!(om.irp_count(), 0);
    }

    #[test]
    fn peer_direct_and_neither_ioctls_round_trip_split_buffers() {
        let ctrl = MockPeerControl::new();
        let (mut om, client, handle) =
            peer_device(&ctrl, AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE);
        for method in [
            ioctl::METHOD_IN_DIRECT,
            ioctl::METHOD_OUT_DIRECT,
            ioctl::METHOD_NEITHER,
        ] {
            let code = any_ioctl(0x801 + method, method);
            let mut io_out = [0u8; 8];
            let n = om
                .device_control(client, handle, code, b"ping", &mut io_out)
                .unwrap();
            assert_eq!(n, 4);
            assert_eq!(&io_out[..n as usize], b"ping");
        }
    }

    #[test]
    fn peer_create_failure_cleans_up() {
        let ctrl = MockPeerControl::new();
        ctrl.set_create_status(NtStatus::ACCESS_DENIED);
        let mut om = io();
        let client = om.register_client();
        let driver = om
            .create_driver_peer(
                &path("\\Driver\\Peer"),
                Box::new(DriverPeerBackend::new(ctrl.transport())),
            )
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Peer0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        assert_eq!(
            open_read(&mut om, client, "\\Device\\Peer0"),
            Err(NtStatus::ACCESS_DENIED)
        );
        assert_eq!(om.file_count(), 0);
    }

    #[test]
    fn peer_pending_then_pump_and_cancel() {
        // Pending then pump completes.
        {
            let ctrl = MockPeerControl::new();
            ctrl.set_force_pending(true);
            ctrl.set_pending_completion(NtStatus::SUCCESS, 4);
            let (mut om, client, handle) = peer_device(&ctrl, AccessMask::GENERIC_READ);
            let mut out = [0u8; 8];
            assert_eq!(om.read(client, handle, 0, &mut out), Err(NtStatus::PENDING));
            let irp = om.pending_irps()[0];
            assert_eq!(om.pump(), 1);
            assert!(om.pending_irps().is_empty());
            assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::SUCCESS);
            om.acknowledge_completed_irp(irp).unwrap();
        }
        // Pending then cancel.
        {
            let ctrl = MockPeerControl::new();
            ctrl.set_force_pending(true);
            let (mut om, client, handle) = peer_device(&ctrl, AccessMask::GENERIC_READ);
            let mut out = [0u8; 8];
            let _ = om.read(client, handle, 0, &mut out);
            let irp = om.pending_irps()[0];
            om.cancel(client, irp).unwrap();
            assert_eq!(om.pump(), 1);
            assert_eq!(om.next_completed_irp().unwrap().status, NtStatus::CANCELLED);
            om.acknowledge_completed_irp(irp).unwrap();
            assert!(om.irp(irp).is_none());
        }
    }

    #[test]
    fn peer_fault_fails_its_irps_only() {
        let peer = MockPeerControl::new();
        peer.set_force_pending(true);
        let mut om = io();
        let client = om.register_client();

        // A peer driver + device.
        let pdrv = om
            .create_driver_peer(
                &path("\\Driver\\Peer"),
                Box::new(DriverPeerBackend::new(peer.transport())),
            )
            .unwrap();
        let pdev = om
            .create_device(
                pdrv,
                Some(&path("\\Device\\Peer0")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        // An unrelated in-process mock driver + device.
        let mdrv = om
            .create_driver(&path("\\Driver\\Mock"), Box::new(MockDriverBackend::new()))
            .unwrap();
        let mdev = om
            .create_device(
                mdrv,
                Some(&path("\\Device\\Mock0")),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();

        let ph = om
            .open(
                client,
                &path("\\Device\\Peer0"),
                AccessMask::GENERIC_READ,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let mh = om
            .open(
                client,
                &path("\\Device\\Mock0"),
                AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();

        // A pending read on the peer device.
        let mut out = [0u8; 8];
        let _ = om.read(client, ph, 0, &mut out);
        let irp = om.pending_irps()[0];

        // The peer faults; pump detects it + fails the peer's in-flight IRPs.
        peer.set_faulted(true);
        assert_eq!(om.pump(), 1);
        assert_eq!(
            om.next_completed_irp().unwrap().status,
            NtStatus::DEVICE_NOT_CONNECTED
        );
        assert!(om.pending_irps().is_empty());
        assert!(om.device(pdev).unwrap().delete_pending);
        assert!(om
            .driver(pdrv)
            .unwrap()
            .flags
            .contains(DriverFlags::FAULTED));
        om.acknowledge_completed_irp(irp).unwrap();
        assert!(om.irp(irp).is_none());

        // The unrelated mock device is untouched + still usable.
        assert!(!om.device(mdev).unwrap().delete_pending);
        assert!(om.write(client, mh, 0, b"ok").is_ok());
    }

    // --- Driver Host readiness (Milestone 9) -------------------------------

    #[test]
    fn projections_reflect_the_records() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);

        let dp = om.project_driver(drv).unwrap();
        assert_eq!(dp.driver_id, drv.0);
        assert_eq!(dp.device_count, 1);

        let dvp = om.project_device(dev).unwrap();
        assert_eq!(dvp.device_id, dev.0);
        assert_eq!(dvp.driver_id, drv.0);
        assert_eq!(dvp.device_type, DeviceType::UNKNOWN.0);
        assert_eq!(dvp.flags, DeviceFlags::BUFFERED_IO.bits());
        assert_eq!(dvp.stack_size, 1);

        // Unknown ids project to None.
        assert!(om.project_device(DeviceId::NULL).is_none());
    }

    #[test]
    fn file_projection_targets_device() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);
        let fid = om.add_file(FileRecord::new(
            ObjectId::NULL,
            ClientId(1),
            dev,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            None,
        ));
        let fp = om.project_file(fid).unwrap();
        assert_eq!(fp.file_id, fid.0);
        assert_eq!(fp.device_id, dev.0);
    }

    fn le_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn le_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn le_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ])
    }

    #[test]
    fn wdm_x64_device_and_file_layouts_are_stable() {
        let mut driver = [0xCC; WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE];
        write_wdm_driver_object(
            &mut driver,
            WdmDriverObjectInit {
                size_field: WDM_X64_DRIVER_OBJECT_SIZE as u16,
                device_object: 0x6666,
                driver_extension: 0x7777,
                driver_unload: 0x8888,
            },
        )
        .unwrap();
        assert_eq!(le_u16(&driver, 0x00), WDM_X64_IO_TYPE_DRIVER as u16);
        assert_eq!(le_u16(&driver, 0x02), WDM_X64_DRIVER_OBJECT_SIZE as u16);
        assert_eq!(le_u64(&driver, 0x08), 0x6666);
        assert_eq!(le_u64(&driver, WDM_X64_DRIVER_EXTENSION_OFFSET), 0x7777);
        assert_eq!(le_u64(&driver, WDM_X64_DRIVER_UNLOAD_OFFSET), 0x8888);

        let mut dev = [0xCC; WDM_X64_DEVICE_OBJECT_SIZE + 16];
        write_wdm_device_object(
            &mut dev,
            WdmDeviceObjectInit {
                driver_object: 0x1111,
                next_device: 0x2222,
                device_extension: 0x3333,
                device_type: 0x44,
                stack_size: 3,
            },
        )
        .unwrap();
        assert_eq!(le_u16(&dev, 0x00), WDM_X64_IO_TYPE_DEVICE as u16);
        assert_eq!(le_u16(&dev, 0x02), WDM_X64_DEVICE_OBJECT_SIZE as u16);
        assert_eq!(le_u64(&dev, 0x08), 0x1111);
        assert_eq!(le_u64(&dev, 0x10), 0x2222);
        assert_eq!(le_u64(&dev, 0x40), 0x3333);
        assert_eq!(le_u32(&dev, 0x48), 0x44);
        assert_eq!(dev[0x4c], 3);
        assert!(dev.iter().skip(WDM_X64_DEVICE_OBJECT_SIZE).all(|b| *b == 0));

        let mut file = [0xCC; WDM_X64_FILE_OBJECT_SIZE];
        write_wdm_file_object(
            &mut file,
            WdmFileObjectInit {
                device_object: 0x4444,
                fs_context: 0x5555,
                file_name_len: 12,
                file_name_max_len: 14,
                file_name_buffer: 0x6666,
            },
        )
        .unwrap();
        assert_eq!(le_u16(&file, 0x00), WDM_X64_IO_TYPE_FILE as u16);
        assert_eq!(le_u16(&file, 0x02), WDM_X64_FILE_OBJECT_SIZE as u16);
        assert_eq!(le_u64(&file, 0x08), 0x4444);
        assert_eq!(le_u64(&file, 0x18), 0x5555);
        assert_eq!(le_u16(&file, 0x58), 12);
        assert_eq!(le_u16(&file, 0x5a), 14);
        assert_eq!(le_u64(&file, 0x60), 0x6666);
    }

    #[test]
    fn wdm_x64_open_device_projection_wires_backlinks() {
        let mut driver = [0xCC; WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE];
        let mut device = [0xCC; WDM_X64_DEVICE_OBJECT_SIZE];
        let mut file = [0xCC; WDM_X64_FILE_OBJECT_SIZE];

        write_wdm_open_device_projection(
            &mut driver,
            &mut device,
            &mut file,
            WdmOpenDeviceProjectionInit {
                driver_object: 0x1000,
                driver_extension: 0x1150,
                device_object: 0x2000,
                file_object_context: 0x77,
                device_type: 0x23,
            },
        )
        .unwrap();

        assert_eq!(le_u16(&driver, 0x00), WDM_X64_IO_TYPE_DRIVER as u16);
        assert_eq!(le_u16(&driver, 0x02), WDM_X64_DRIVER_OBJECT_SIZE as u16);
        assert_eq!(le_u64(&driver, 0x08), 0x2000);
        assert_eq!(le_u64(&driver, WDM_X64_DRIVER_EXTENSION_OFFSET), 0x1150);
        assert_eq!(le_u64(&driver, WDM_X64_DRIVER_UNLOAD_OFFSET), 0);

        assert_eq!(le_u16(&device, 0x00), WDM_X64_IO_TYPE_DEVICE as u16);
        assert_eq!(le_u64(&device, 0x08), 0x1000);
        assert_eq!(le_u64(&device, 0x10), 0);
        assert_eq!(le_u32(&device, 0x48), 0x23);
        assert_eq!(device[0x4c], 1);

        assert_eq!(le_u16(&file, 0x00), WDM_X64_IO_TYPE_FILE as u16);
        assert_eq!(le_u64(&file, 0x08), 0x2000);
        assert_eq!(le_u64(&file, 0x18), 0x77);
        assert_eq!(le_u16(&file, 0x58), 0);
        assert_eq!(le_u16(&file, 0x5a), 0);
    }

    #[test]
    fn wdm_x64_irp_and_stack_layouts_are_stable() {
        let mut irp = [0xCC; WDM_X64_IRP_SIZE];
        write_wdm_irp(
            &mut irp,
            WdmIrpInit {
                mdl_address: 0xAAAA,
                flags: 0x55AA,
                system_buffer: 0x1111,
                user_buffer: 0x2222,
                thread: 0x4444,
                stack_count: 1,
                current_location: 1,
                current_stack_location: 0x3333,
            },
        )
        .unwrap();
        assert_eq!(le_u64(&irp, 0x08), 0xAAAA);
        assert_eq!(le_u32(&irp, 0x10), 0x55AA);
        assert_eq!(le_u64(&irp, 0x18), 0x1111);
        assert_eq!(irp[0x42], 1);
        assert_eq!(irp[0x43], 1);
        assert_eq!(le_u64(&irp, 0x70), 0x2222);
        assert_eq!(le_u64(&irp, 0xa8), 0x4444);
        assert_eq!(le_u64(&irp, 0xb8), 0x3333);

        let mut stack = [0xCC; WDM_X64_IO_STACK_LOCATION_SIZE];
        write_wdm_io_stack_location(
            &mut stack,
            WdmIoStackLocationInit {
                major: major::IRP_MJ_DEVICE_CONTROL,
                minor: 2,
                device_object: 0x4444,
                file_object: 0x5555,
                parameters: WdmIoStackParameters::DeviceControl {
                    output_buffer_length: 0x10,
                    input_buffer_length: 0x20,
                    io_control_code: 0x333000,
                    type3_input_buffer: 0x6666,
                },
            },
        )
        .unwrap();
        assert_eq!(stack[0x00], major::IRP_MJ_DEVICE_CONTROL);
        assert_eq!(stack[0x01], 2);
        assert_eq!(le_u32(&stack, 0x08), 0x10);
        assert_eq!(le_u32(&stack, 0x10), 0x20);
        assert_eq!(le_u32(&stack, 0x18), 0x333000);
        assert_eq!(le_u64(&stack, 0x20), 0x6666);
        assert_eq!(le_u64(&stack, 0x28), 0x4444);
        assert_eq!(le_u64(&stack, 0x30), 0x5555);

        write_wdm_io_stack_location(
            &mut stack,
            WdmIoStackLocationInit {
                major: major::IRP_MJ_QUERY_INFORMATION,
                minor: 0,
                device_object: 0x4444,
                file_object: 0x5555,
                parameters: WdmIoStackParameters::QueryInformation {
                    length: 0x28,
                    information_class: 24,
                },
            },
        )
        .unwrap();
        assert_eq!(stack[0x00], major::IRP_MJ_QUERY_INFORMATION);
        assert_eq!(le_u32(&stack, 0x08), 0x28);
        assert_eq!(le_u32(&stack, 0x10), 24);
        assert_eq!(le_u64(&stack, 0x28), 0x4444);
        assert_eq!(le_u64(&stack, 0x30), 0x5555);

        write_wdm_io_stack_location(
            &mut stack,
            WdmIoStackLocationInit {
                major: major::IRP_MJ_CREATE_NAMED_PIPE,
                minor: 0,
                device_object: 0x4444,
                file_object: 0x5555,
                parameters: WdmIoStackParameters::Create {
                    security_context: 0x7777,
                    options: 3 << 24,
                    share_access: 3,
                    named_pipe_parameters: Some(0x8888),
                },
            },
        )
        .unwrap();
        assert_eq!(le_u64(&stack, 0x08), 0x7777);
        assert_eq!(le_u32(&stack, 0x10), 3 << 24);
        assert_eq!(le_u16(&stack, 0x1a), 3);
        assert_eq!(le_u64(&stack, 0x20), 0x8888);
        assert_eq!(le_u64(&stack, 0x28), 0x4444);
        assert_eq!(le_u64(&stack, 0x30), 0x5555);

        write_wdm_io_stack_location(
            &mut stack,
            WdmIoStackLocationInit {
                major: major::IRP_MJ_PNP,
                minor: 0,
                device_object: 0x4444,
                file_object: 0,
                parameters: WdmIoStackParameters::PnpStartDevice {
                    allocated_resources: 0xAAAA,
                    allocated_resources_translated: 0xBBBB,
                },
            },
        )
        .unwrap();
        assert_eq!(stack[0x00], major::IRP_MJ_PNP);
        assert_eq!(stack[0x01], 0);
        assert_eq!(le_u64(&stack, 0x08), 0xAAAA);
        assert_eq!(le_u64(&stack, 0x10), 0xBBBB);
        assert_eq!(le_u64(&stack, 0x28), 0x4444);
    }

    #[test]
    fn support_routine_plan_is_complete() {
        use nt_io_abi::projection::cqe_flags;

        // Every routine has an export name matching its identifier.
        for r in DriverHostRoutine::ALL {
            assert!(!r.export_name().is_empty());
        }
        assert_eq!(
            DriverHostRoutine::IoCreateDevice.export_name(),
            "IoCreateDevice"
        );
        // The §20 status table.
        assert_eq!(
            DriverHostRoutine::IoCreateDevice.mvp_status(),
            MvpStatus::RequiredInternal
        );
        assert_eq!(
            DriverHostRoutine::IoCompleteRequest.mvp_status(),
            MvpStatus::ThroughPeerProtocol
        );
        assert_eq!(
            DriverHostRoutine::IoCallDriver.mvp_status(),
            MvpStatus::SingleStackStub
        );
        assert_eq!(
            DriverHostRoutine::IoCancelIrp.mvp_status(),
            MvpStatus::Partial
        );

        // The completion flags are distinct bits.
        assert_ne!(
            cqe_flags::IODRV_CQE_FINAL,
            cqe_flags::IODRV_CQE_PENDING_ACCEPTED
        );
    }

    #[cfg(feature = "object-manager")]
    #[test]
    fn library_port_against_real_object_manager() {
        use nt_object_manager::ComponentId;

        let mut port = ObjectManagerLibraryPort::new(ComponentId(0x10)).unwrap();
        let client = port.register_client();

        // IoCreateDevice-style: \Driver\Test + \Device\Test0, then \??\Test0 link.
        port.create_driver_object(&path("\\Driver\\Test"), 1)
            .unwrap();
        let dev = port
            .create_device_object(Some(&path("\\Device\\Test0")), 100)
            .unwrap();
        port.create_symbolic_link(&path("\\??\\Test0"), &path("\\Device\\Test0"))
            .unwrap();

        // Open by direct path + via the symlink both resolve to the device.
        assert_eq!(port.open_device_object(&path("\\Device\\Test0")), Ok(dev));
        assert_eq!(port.open_device_object(&path("\\??\\Test0")), Ok(dev));

        // Brokered file+handle, then reference it back for the client.
        let (file, handle) = port
            .create_file_object_and_handle(client, dev, 7, AccessMask::GENERIC_READ)
            .unwrap();
        assert_eq!(
            port.reference_file_by_handle(client, handle, AccessMask::GENERIC_READ),
            Ok(file)
        );
        assert!(port.reference_device(dev).is_ok());
        assert!(port.close_handle(client, handle).is_ok());
    }

    #[cfg(feature = "object-manager")]
    #[test]
    fn open_against_real_object_manager() {
        use nt_object_manager::ComponentId;

        let mut om = IoManager::new(ObjectManagerLibraryPort::new(ComponentId(0x10)).unwrap());
        let client = om.register_client();
        let good = om
            .create_driver(&path("\\Driver\\Good"), Box::new(MockDriverBackend::new()))
            .unwrap();
        om.create_device(
            good,
            Some(&path("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        om.create_symbolic_link(&path("\\??\\Test0"), &path("\\Device\\Test0"))
            .unwrap();

        // Success: open by direct path + via the symlink through the real OM.
        let open = |om: &mut IoManager<ObjectManagerLibraryPort>, p: &str| {
            om.open(
                client,
                &path(p),
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
        };
        assert!(open(&mut om, "\\Device\\Test0").is_ok());
        assert!(open(&mut om, "\\??\\Test0").is_ok());

        // Failure cleanup leaks no Object Manager object.
        let mut bad = MockDriverBackend::new();
        bad.set_create_status(NtStatus::ACCESS_DENIED);
        let bd = om
            .create_driver(&path("\\Driver\\Bad"), Box::new(bad))
            .unwrap();
        om.create_device(
            bd,
            Some(&path("\\Device\\Bad0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let before = om.port_mut().object_manager().live_object_count();
        assert_eq!(
            open(&mut om, "\\Device\\Bad0"),
            Err(NtStatus::ACCESS_DENIED)
        );
        let after = om.port_mut().object_manager().live_object_count();
        assert_eq!(before, after);
    }

    #[cfg(feature = "object-manager")]
    #[test]
    fn read_write_ioctl_against_real_object_manager() {
        use nt_object_manager::ComponentId;

        let mut om = IoManager::new(ObjectManagerLibraryPort::new(ComponentId(0x10)).unwrap());
        let client = om.register_client();
        let driver = om
            .create_driver(&path("\\Driver\\Test"), Box::new(MockDriverBackend::new()))
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = om
            .open(
                client,
                &path("\\Device\\Test0"),
                AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();

        // Write then read loopback + an echoing IOCTL, all through the real OM
        // handle validation.
        assert_eq!(om.write(client, handle, 0, b"echo").unwrap(), 4);
        let mut out = [0u8; 8];
        let n = om.read(client, handle, 0, &mut out).unwrap();
        assert_eq!(&out[..n as usize], b"echo");

        let code = ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS);
        let mut io_out = [0u8; 8];
        let n = om
            .device_control(client, handle, code, b"ping", &mut io_out)
            .unwrap();
        assert_eq!(&io_out[..n as usize], b"ping");
    }

    #[cfg(feature = "object-manager")]
    #[test]
    fn close_balances_object_manager_refs() {
        use nt_object_manager::ComponentId;

        let mut om = IoManager::new(ObjectManagerLibraryPort::new(ComponentId(0x10)).unwrap());
        let client = om.register_client();
        let driver = om
            .create_driver(&path("\\Driver\\Test"), Box::new(MockDriverBackend::new()))
            .unwrap();
        om.create_device(
            driver,
            Some(&path("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();

        let before = om.port_mut().object_manager().live_object_count();
        let handle = om
            .open(
                client,
                &path("\\Device\\Test0"),
                AccessMask::GENERIC_READ,
                ShareAccess::empty(),
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        // The File object is alive while the handle is open.
        assert!(om.port_mut().object_manager().live_object_count() > before);
        // Close reaps it: the reference count returns to baseline.
        om.close(client, handle).unwrap();
        assert_eq!(om.port_mut().object_manager().live_object_count(), before);
    }
}
