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
use alloc::vec::Vec;

mod cancel;
mod close;
mod complete;
mod device;
mod device_control;
mod dispatch;
mod driver;
mod driver_host;
mod driver_peer;
mod fault;
mod file;
mod irp;
mod mock_driver;
mod object_port;
mod open;
mod pipe;
mod projection;
mod read_write;
mod store;

pub use device::{DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType};
pub use dispatch::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IrpProjection,
};
pub use driver::{
    DeviceList, DispatchTarget, DriverBackendId, DriverFlags, DriverPeerId, DriverRecord,
    DriverUnloadState, MajorFunctionTable, MockDispatchId,
};
pub use driver_host::{DriverHostRoutine, MvpStatus};
pub use driver_peer::{DriverPeerBackend, DriverPeerTransport, MockDriverPeer, MockPeerControl};
pub use file::{CreateOptions, FileFlags, FileRecord, FileState, ShareAccess};
pub use irp::{
    BufferAccess, CancelState, CreateParameters, DeviceControlParameters, InformationParameters,
    IoBufferRef, IoParameters, IoStackLocation, IrpRecord, IrpState, ReadWriteParameters,
    StackControl, StackFlags,
};
pub use mock_driver::{IoctlBehavior, MockDriverBackend};
pub use object_port::{MockObjectPort, ObjectManagerPort};
pub use pipe::{
    pipe_name_hash, AsyncListen, AsyncListenTable,
    PipeConnection, PipeEnd, PipeFcb, PipeHandle, PipeParams, PipeRegistry, PipeState, PipeWaiter,
    PipeWaiterTable,
    FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_BYTE_STREAM_TYPE, FILE_PIPE_CLIENT_END,
    FILE_PIPE_FULL_DUPLEX, FILE_PIPE_INBOUND, FILE_PIPE_MESSAGE_MODE, FILE_PIPE_MESSAGE_TYPE,
    FILE_PIPE_OUTBOUND, FILE_PIPE_SERVER_END, STATUS_INSTANCE_NOT_AVAILABLE, STATUS_PIPE_BUSY,
    STATUS_PIPE_CONNECTED, STATUS_PIPE_DISCONNECTED, STATUS_PIPE_LISTENING,
    STATUS_PIPE_NOT_AVAILABLE,
};
pub use store::{GenStore, IoId};

#[cfg(feature = "object-manager")]
pub use object_port::ObjectManagerLibraryPort;

// Re-export the canonical id types + Driver Host projections from one place.
pub use nt_io_abi::{
    DeviceId, DeviceObjectProjection, DriverId, DriverObjectProjection, FileId,
    FileObjectProjection, IoRequestId, IrpId,
};

/// The canonical I/O Manager (spec §6): owns the driver / device / file / IRP
/// stores, the registered dispatch backends, and the port to the Object Manager
/// (`P`). Single-threaded (`&mut self`).
#[derive(Default)]
pub struct IoManager<P> {
    drivers: GenStore<DriverId, DriverRecord>,
    devices: GenStore<DeviceId, DeviceRecord>,
    files: GenStore<FileId, FileRecord>,
    irps: GenStore<IrpId, IrpRecord>,
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
        self.devices.remove(id)
    }
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// The devices owned by a driver (empty for an unknown driver).
    pub fn devices_of(&self, driver: DriverId) -> &[DeviceId] {
        self.drivers
            .get(driver)
            .map(|d| d.devices.as_slice())
            .unwrap_or(&[])
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
    pub fn remove_file(&mut self, id: FileId) -> Option<FileRecord> {
        self.files.remove(id)
    }
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    // --- IRPs --------------------------------------------------------------

    /// Allocate an IRP record, assigning + returning its id.
    pub fn allocate_irp(&mut self, record: IrpRecord) -> IrpId {
        let id = self.irps.insert(record);
        self.irps.get_mut(id).expect("just inserted").id = id;
        id
    }

    pub fn irp(&self, id: IrpId) -> Option<&IrpRecord> {
        self.irps.get(id)
    }
    pub fn irp_mut(&mut self, id: IrpId) -> Option<&mut IrpRecord> {
        self.irps.get_mut(id)
    }
    pub fn free_irp(&mut self, id: IrpId) -> Option<IrpRecord> {
        self.irps.remove(id)
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
        assert_eq!(d.top_of_stack, dev); // single-device stack (v0.1)
        assert_eq!(om.devices_of(drv), &[dev]);
        assert!(d.is_buffered_io());
    }

    #[test]
    fn stale_ids_are_rejected() {
        let mut om = io();
        let drv = a_driver(&mut om);
        let dev = a_device(&mut om, drv);

        assert!(om.remove_device(dev).is_some());
        assert!(om.device(dev).is_none()); // stale id no longer resolves
        assert!(om.remove_device(dev).is_none()); // double remove is a no-op

        // Reusing the slot yields a fresh id; the old id stays stale.
        let dev2 = a_device(&mut om, drv);
        assert_ne!(dev2, dev);
        assert!(om.device(dev).is_none());
        assert!(om.device(dev2).is_some());
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
        let iid = om.allocate_irp(IrpRecord::new(ClientId(1), dev, None, major::IRP_MJ_CREATE));

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
        let iid = om.allocate_irp(IrpRecord::new(ClientId(1), dev, None, major::IRP_MJ_READ));
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
                information: 0
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
                information: 5
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
                information: 8
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
                information: 8
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
                information: 42
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
    fn ioctl_unsupported_method_rejected() {
        let (mut om, client, handle) =
            open_device_with(MockDriverBackend::new(), AccessMask::GENERIC_READ);
        let code = any_ioctl(0x801, ioctl::METHOD_IN_DIRECT);
        let mut out = [0u8; 8];
        assert_eq!(
            om.device_control(client, handle, code, b"x", &mut out),
            Err(NtStatus::NOT_SUPPORTED)
        );
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
        assert!(om.irp(irp).is_none()); // finalized + freed
    }

    #[test]
    fn cancel_pending_irp() {
        let mut mock = MockDriverBackend::new();
        mock.set_force_pending(true); // no completion queued
        let (mut om, client, irp) = pending_read(mock);
        om.cancel(client, irp).unwrap();
        assert!(om.irp(irp).is_none()); // finalized as cancelled + freed
        assert!(om.pending_irps().is_empty());
        assert_eq!(om.pump(), 0);
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
        // Order A: cancel before pump — cancellation wins, completion dropped.
        {
            let mut mock = MockDriverBackend::new();
            mock.set_force_pending(true);
            mock.set_pending_completion(NtStatus::SUCCESS, 4);
            let (mut om, client, irp) = pending_read(mock);
            om.cancel(client, irp).unwrap();
            assert_eq!(om.pump(), 0); // no double finalize
            assert!(om.irp(irp).is_none());
        }
        // Order B: pump before cancel — completion wins, cancel is a no-op.
        {
            let mut mock = MockDriverBackend::new();
            mock.set_force_pending(true);
            mock.set_pending_completion(NtStatus::SUCCESS, 4);
            let (mut om, client, irp) = pending_read(mock);
            assert_eq!(om.pump(), 1);
            om.cancel(client, irp).unwrap(); // already final: no-op
            assert!(om.irp(irp).is_none());
        }
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
            assert_eq!(om.pump(), 1);
            assert!(om.pending_irps().is_empty());
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
        om.pump();
        assert!(om.irp(irp).is_none());
        assert!(om.pending_irps().is_empty());
        assert!(om.device(pdev).unwrap().delete_pending);
        assert!(om
            .driver(pdrv)
            .unwrap()
            .flags
            .contains(DriverFlags::FAULTED));

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
