//! The create/open path + driver/device creation (spec §10.3, §11.3, §12.3).
//!
//! `open` resolves a Device object through the Object Manager, brokers a File
//! object + handle for the client, allocates and dispatches an `IRP_MJ_CREATE` to
//! the device's driver backend, and returns the handle on success — cleaning up
//! the File object + IRP on failure so no reference or record leaks.

use alloc::boxed::Box;

use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath, ObjectId};

use crate::device::{DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType};
use crate::dispatch::{DispatchOutcome, DriverDispatchBackend};
use crate::driver::{
    DispatchTarget, DriverBackendId, DriverPeerId, DriverRecord, DriverUnloadState,
    MajorFunctionTable, MockDispatchId,
};
use crate::file::{CreateOptions, FileRecord, FileState, ShareAccess};
use crate::irp::{CreateParameters, IoParameters, IoStackLocation, IrpRecord, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, DriverId, FileId, IoManager, IrpId};

/// The major functions a driver dispatches in v0.1 (spec §13.3).
const SUPPORTED_MAJORS: [u8; 8] = [
    major::IRP_MJ_CREATE,
    major::IRP_MJ_CLEANUP,
    major::IRP_MJ_CLOSE,
    major::IRP_MJ_READ,
    major::IRP_MJ_WRITE,
    major::IRP_MJ_DEVICE_CONTROL,
    major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
    major::IRP_MJ_FLUSH_BUFFERS,
];

#[derive(Clone, Copy)]
enum DriverInstallKind {
    Mock,
    Kernel,
    Peer,
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Register an I/O client with the Object Manager (its handles live there).
    pub fn register_client(&mut self) -> ClientId {
        self.port.register_client()
    }

    /// Create a driver (spec §10.3): register its dispatch `backend` + a
    /// `\Driver\Name` object, with the v0.1 majors routed to that backend.
    pub fn create_driver(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
    ) -> Result<DriverId, NtStatus> {
        self.install_driver(name, backend, false)
    }

    /// Create a driver whose backend is an isolated driver **peer** (spec §15.3).
    /// Functionally identical to [`create_driver`] but the dispatch table marks
    /// the target as a `DriverPeer` (informational; both route to the backend).
    pub fn create_driver_peer(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
    ) -> Result<DriverId, NtStatus> {
        self.install_driver(name, backend, true)
    }

    fn install_driver(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        peer: bool,
    ) -> Result<DriverId, NtStatus> {
        let kind = if peer {
            DriverInstallKind::Peer
        } else {
            DriverInstallKind::Mock
        };
        self.install_driver_with_majors_kind(name, backend, kind, &SUPPORTED_MAJORS)
    }

    /// Create a kernel-owned in-process driver using an explicit major-function table.
    pub fn create_kernel_driver_with_major_table(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        table: MajorFunctionTable,
    ) -> Result<DriverId, NtStatus> {
        self.install_driver_with_table_kind(name, backend, DriverInstallKind::Kernel, table)
    }

    /// Create a kernel-owned in-process driver with only the listed major functions supported.
    pub fn create_kernel_driver_with_majors(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        majors: &[u8],
    ) -> Result<DriverId, NtStatus> {
        self.install_driver_with_majors_kind(name, backend, DriverInstallKind::Kernel, majors)
    }

    /// Create an isolated driver peer using an explicit major-function table.
    ///
    /// Hosted WDM components populate their own `MajorFunction[]` table at runtime, so their
    /// canonical I/O Manager record needs the same broad dispatch surface instead of the small
    /// built-in synchronous-driver default.
    pub fn create_driver_peer_with_major_table(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        table: MajorFunctionTable,
    ) -> Result<DriverId, NtStatus> {
        self.install_driver_with_table(name, backend, true, table)
    }

    fn install_driver_with_table(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        peer: bool,
        table: MajorFunctionTable,
    ) -> Result<DriverId, NtStatus> {
        let kind = if peer {
            DriverInstallKind::Peer
        } else {
            DriverInstallKind::Mock
        };
        self.install_driver_with_table_kind(name, backend, kind, table)
    }

    fn install_driver_with_table_kind(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        kind: DriverInstallKind,
        mut table: MajorFunctionTable,
    ) -> Result<DriverId, NtStatus> {
        let idx = self.register_backend(backend);
        let target = match kind {
            DriverInstallKind::Mock => DispatchTarget::Mock(MockDispatchId(idx as u64)),
            DriverInstallKind::Kernel => DispatchTarget::Kernel(DriverBackendId(idx as u64)),
            DriverInstallKind::Peer => DispatchTarget::DriverPeer(DriverPeerId(idx as u64)),
        };
        table.retarget(target);
        self.install_driver_record_with_dispatch(
            name,
            DriverBackendId(idx as u64),
            MajorFunctionTable::boxed_from(table),
        )
    }

    fn install_driver_with_majors_kind(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        kind: DriverInstallKind,
        majors: &[u8],
    ) -> Result<DriverId, NtStatus> {
        let idx = self.register_backend(backend);
        let target = match kind {
            DriverInstallKind::Mock => DispatchTarget::Mock(MockDispatchId(idx as u64)),
            DriverInstallKind::Kernel => DispatchTarget::Kernel(DriverBackendId(idx as u64)),
            DriverInstallKind::Peer => DispatchTarget::DriverPeer(DriverPeerId(idx as u64)),
        };
        let table = MajorFunctionTable::boxed_with_majors(majors, target);
        self.install_driver_record_with_dispatch(name, DriverBackendId(idx as u64), table)
    }

    fn install_driver_record_with_dispatch(
        &mut self,
        name: &NtPath,
        backend: DriverBackendId,
        dispatch: Box<MajorFunctionTable>,
    ) -> Result<DriverId, NtStatus> {
        let driver_id = self.register_driver(DriverRecord::new_boxed(
            ObjectId::NULL,
            name.clone(),
            backend,
            dispatch,
        ));
        match self.port.create_driver_object(name, driver_id.raw()) {
            Ok(obj) => {
                self.driver_mut(driver_id)
                    .expect("just registered")
                    .object_id = obj;
                Ok(driver_id)
            }
            Err(e) => {
                self.remove_driver(driver_id);
                Err(e)
            }
        }
    }

    /// Create a device (spec §11.3, `IoCreateDevice`): a `Device` object (named
    /// under `\Device`, or unnamed for tests) owned by `driver`.
    pub fn create_device(
        &mut self,
        driver: DriverId,
        name: Option<&NtPath>,
        device_type: DeviceType,
        characteristics: DeviceCharacteristics,
        flags: DeviceFlags,
        extension_size: u32,
    ) -> Result<DeviceId, NtStatus> {
        if self.driver(driver).is_none() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let device_id = self.add_device(DeviceRecord::new(
            ObjectId::NULL,
            driver,
            name.cloned(),
            device_type,
            characteristics,
            flags,
            extension_size,
        ));
        match self.port.create_device_object(name, device_id.raw()) {
            Ok(obj) => {
                self.device_mut(device_id).expect("just added").object_id = obj;
                Ok(device_id)
            }
            Err(e) => {
                self.remove_device(device_id);
                Err(e)
            }
        }
    }

    /// Destroy a device through the I/O Manager and Object Manager. If open files or upper
    /// attachments still reference it, the record is left live and marked delete-pending.
    pub fn destroy_device(&mut self, device: DeviceId) -> Result<DeviceRecord, NtStatus> {
        let record = self.delete_device(device)?;
        if record.object_id != ObjectId::NULL {
            self.port
                .delete_device_object(record.object_id, record.name.as_ref())?;
        }
        Ok(record)
    }

    /// Mark a driver unload requested and mark its devices delete-pending.
    pub fn request_driver_unload(&mut self, driver: DriverId) -> Result<(), NtStatus> {
        self.request_driver_unload_records(driver)
    }

    /// Complete a driver unload when all owned devices are free of open files and upper attachments.
    /// This tears down Object Manager device/driver objects as well as I/O Manager records.
    pub fn destroy_driver(&mut self, driver: DriverId) -> Result<DriverRecord, NtStatus> {
        self.request_driver_unload(driver)?;
        self.can_destroy_driver(driver)?;

        let devices = self.devices_of(driver).to_vec();
        for device in devices {
            self.destroy_device(device)?;
        }
        let mut record = self
            .remove_driver(driver)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        record.unload_state = DriverUnloadState::Unloaded;
        if record.object_id != ObjectId::NULL {
            self.port
                .delete_driver_object(record.object_id, &record.name)?;
        }
        Ok(record)
    }

    /// Create a symbolic link through the Object Manager (spec §11.4).
    pub fn create_symbolic_link(&mut self, link: &NtPath, target: &NtPath) -> Result<(), NtStatus> {
        self.port.create_symbolic_link(link, target)
    }

    /// Delete a symbolic link through the Object Manager (spec §11.4).
    pub fn delete_symbolic_link(&mut self, link: &NtPath) -> Result<(), NtStatus> {
        self.port.delete_symbolic_link(link)
    }

    /// Open (create) a file on a device `path` (spec §12.3). Returns the Object
    /// Manager file handle on success; on any failure the File object + IRP are
    /// cleaned up. v0.1 completes creates synchronously.
    pub fn open(
        &mut self,
        client: ClientId,
        path: &NtPath,
        desired_access: AccessMask,
        share_access: ShareAccess,
        create_options: CreateOptions,
        create_disposition: u32,
    ) -> Result<HandleValue, NtStatus> {
        // 1. Resolve the Device object (the OM follows symbolic links).
        let device_object = self.port.open_device_object(path)?;
        let device_id = self
            .find_device_by_object(device_object)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;

        // 2. Allocate the FileRecord.
        let file_id = self.add_file(FileRecord::new(
            ObjectId::NULL,
            client,
            device_id,
            desired_access,
            share_access,
            create_options,
            Some(path.clone()),
        ));

        // 3. Broker the OM File object + a handle for the client (spec §8.4).
        let (file_object, handle) = match self.port.create_file_object_and_handle(
            client,
            device_object,
            file_id.raw(),
            desired_access,
        ) {
            Ok(x) => x,
            Err(e) => {
                self.remove_file(file_id);
                return Err(e);
            }
        };
        self.file_mut(file_id).expect("just added").object_id = file_object;

        // 4. Build + dispatch IRP_MJ_CREATE.
        let mut irp = IrpRecord::new(client, device_id, Some(file_id), major::IRP_MJ_CREATE);
        let mut sl = IoStackLocation::new(major::IRP_MJ_CREATE, device_id, Some(file_id));
        sl.parameters = IoParameters::Create(CreateParameters {
            desired_access,
            share_access,
            create_options,
            create_disposition,
        });
        irp.stack.push(sl);
        let irp_id = self.allocate_irp(irp);
        self.irp_mut(irp_id)
            .unwrap()
            .transition(IrpState::Initialized);
        self.file_mut(file_id)
            .unwrap()
            .transition(FileState::CreateIrpDispatched);
        self.irp_mut(irp_id)
            .unwrap()
            .transition(IrpState::Dispatched);

        let mut empty: [u8; 0] = [];
        let outcome = self.dispatch(irp_id, &mut empty);

        // 5. Apply the outcome.
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
                self.file_mut(file_id).unwrap().transition(FileState::Open);
                self.free_irp(irp_id);
                Ok(handle)
            }
            Ok(DispatchOutcome::Completed { status, .. }) => {
                self.cleanup_failed_open(client, file_id, handle, irp_id);
                Err(status)
            }
            Ok(DispatchOutcome::Failed { status }) => {
                self.cleanup_failed_open(client, file_id, handle, irp_id);
                Err(status)
            }
            Ok(DispatchOutcome::Pending) => {
                // v0.1 open is synchronous; async create arrives with the
                // completion engine (later milestone).
                self.cleanup_failed_open(client, file_id, handle, irp_id);
                Err(NtStatus::NOT_SUPPORTED)
            }
            Err(status) => {
                self.cleanup_failed_open(client, file_id, handle, irp_id);
                Err(status)
            }
        }
    }

    // --- internals ---------------------------------------------------------

    fn find_device_by_object(&self, obj: ObjectId) -> Option<DeviceId> {
        self.devices
            .iter()
            .find(|(_, d)| d.object_id == obj)
            .map(|(id, _)| id)
    }

    /// Route an IRP to its device's driver backend + dispatch it.
    pub(crate) fn dispatch(
        &mut self,
        irp_id: IrpId,
        system_buffer: &mut [u8],
    ) -> Result<DispatchOutcome, NtStatus> {
        let device_id = {
            let irp = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            irp.device_id
        };
        let driver_id = self
            .device(device_id)
            .ok_or(NtStatus::INVALID_PARAMETER)?
            .driver_id;
        self.dispatch_to_driver(driver_id, irp_id, system_buffer)
    }

    fn cleanup_failed_open(
        &mut self,
        client: ClientId,
        file_id: FileId,
        handle: HandleValue,
        irp_id: IrpId,
    ) {
        // Closing the handle drops the last reference, reaping the OM File object.
        let _ = self.port.close_handle(client, handle);
        self.remove_file(file_id);
        self.free_irp(irp_id);
    }
}
