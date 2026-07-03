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

mod device;
mod dispatch;
mod driver;
mod file;
mod irp;
mod mock_driver;
mod object_port;
mod store;

pub use device::{DeviceCharacteristics, DeviceFlags, DeviceRecord, DeviceType};
pub use dispatch::{DispatchContext, DispatchOutcome, DriverDispatchBackend, IrpProjection};
pub use driver::{
    DeviceList, DispatchTarget, DriverBackendId, DriverFlags, DriverPeerId, DriverRecord,
    DriverUnloadState, MajorFunctionTable, MockDispatchId,
};
pub use file::{CreateOptions, FileFlags, FileRecord, FileState, ShareAccess};
pub use irp::{
    BufferAccess, CancelState, CreateParameters, DeviceControlParameters, InformationParameters,
    IoBufferRef, IoParameters, IoStackLocation, IrpRecord, IrpState, ReadWriteParameters,
    StackControl, StackFlags,
};
pub use mock_driver::{IoctlBehavior, MockDriverBackend};
pub use object_port::{MockObjectPort, ObjectManagerPort};
pub use store::{GenStore, IoId};

#[cfg(feature = "object-manager")]
pub use object_port::ObjectManagerLibraryPort;

// Re-export the canonical id types so downstream crates get them from one place.
pub use nt_io_abi::{DeviceId, DriverId, FileId, IoRequestId, IrpId};

/// The canonical I/O Manager: owns the driver / device / file / IRP stores.
#[derive(Default)]
pub struct IoManager {
    drivers: GenStore<DriverId, DriverRecord>,
    devices: GenStore<DeviceId, DeviceRecord>,
    files: GenStore<FileId, FileRecord>,
    irps: GenStore<IrpId, IrpRecord>,
}

impl IoManager {
    /// A fresh I/O Manager with empty stores.
    pub fn new() -> Self {
        Self::default()
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
    use nt_io_abi::major;
    use nt_status::NtStatus;
    use nt_types::{AccessMask, ClientId, NtPath, ObjectId};
    use proptest::prelude::*;

    fn path(s: &str) -> NtPath {
        NtPath::parse_str(s).unwrap()
    }

    fn a_driver(om: &mut IoManager) -> DriverId {
        om.register_driver(DriverRecord::new(
            ObjectId::NULL,
            path("\\Driver\\Test"),
            DriverBackendId(1),
            MajorFunctionTable::new(),
        ))
    }

    fn a_device(om: &mut IoManager, driver: DriverId) -> DeviceId {
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
        let mut om = IoManager::new();
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
        let mut om = IoManager::new();
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
        let mut om = IoManager::new();
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
        let mut om = IoManager::new();
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
        let mut om = IoManager::new();
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
        let mut om = IoManager::new();
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
}
