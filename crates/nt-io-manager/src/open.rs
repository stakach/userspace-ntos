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
    DispatchTarget, DriverBackendId, DriverPeerId, DriverRecord, MajorFunctionTable, MockDispatchId,
};
use crate::file::{CreateOptions, FileRecord, FileState, ShareAccess};
use crate::irp::{CreateParameters, IoParameters, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DeviceId, DriverId, FileId, IoManager, IrpId};

/// The major functions a driver dispatches in v0.1 (spec §13.3).
const SUPPORTED_MAJORS: [u8; 12] = [
    major::IRP_MJ_CREATE,
    major::IRP_MJ_CREATE_NAMED_PIPE,
    major::IRP_MJ_CREATE_MAILSLOT,
    major::IRP_MJ_CLEANUP,
    major::IRP_MJ_CLOSE,
    major::IRP_MJ_READ,
    major::IRP_MJ_WRITE,
    major::IRP_MJ_DEVICE_CONTROL,
    major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
    major::IRP_MJ_FLUSH_BUFFERS,
    major::IRP_MJ_QUERY_INFORMATION,
    major::IRP_MJ_SET_INFORMATION,
];

#[derive(Clone, Copy)]
enum DriverInstallKind {
    Mock,
    Kernel,
    Peer,
}

#[cfg(test)]
mod open_with_details_tests {
    extern crate std;

    use super::*;
    use crate::dispatch::{DispatchContext, DriverCompletion, IrpProjection};
    use crate::{MockDriverBackend, MockObjectPort};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::vec::Vec;

    struct QueuedCreateBackend {
        first: Option<IrpId>,
        ready: VecDeque<DriverCompletion>,
        acks: Rc<RefCell<Vec<IrpId>>>,
    }

    impl DriverDispatchBackend for QueuedCreateBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            if irp.major == major::IRP_MJ_CREATE {
                if let Some(first) = self.first {
                    for id in [first, irp.irp_id] {
                        self.ready.push_back(DriverCompletion {
                            irp_id: id,
                            status: NtStatus::SUCCESS,
                            information: 0,
                            file_context: Some(id.raw()),
                        });
                    }
                } else {
                    self.first = Some(irp.irp_id);
                }
                Ok(DispatchOutcome::Pending)
            } else {
                Ok(DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                })
            }
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> { Ok(()) }

        fn poll_completion(&mut self) -> Option<DriverCompletion> { self.ready.pop_front() }

        fn acknowledge_completion(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
            self.acks.borrow_mut().push(irp_id);
            Ok(())
        }
    }

    struct EndlessUnrelatedBackend {
        target: Rc<RefCell<Option<IrpId>>>,
        polls: Rc<Cell<usize>>,
        acks: Rc<RefCell<Vec<IrpId>>>,
    }

    impl DriverDispatchBackend for EndlessUnrelatedBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            if irp.major == major::IRP_MJ_CREATE {
                *self.target.borrow_mut() = Some(irp.irp_id);
                Ok(DispatchOutcome::Pending)
            } else {
                Ok(DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                })
            }
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> { Ok(()) }

        fn poll_completion(&mut self) -> Option<DriverCompletion> {
            let count = self.polls.get() + 1;
            assert!(count <= 64, "synchronous open must not poll an unbounded backend");
            self.polls.set(count);
            Some(DriverCompletion {
                irp_id: IrpId::new(999_999, 1),
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            })
        }

        fn acknowledge_completion(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
            self.acks.borrow_mut().push(irp_id);
            Ok(())
        }
    }

    #[test]
    fn ready_create_drain_preserves_unrelated_completion_owner() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let acks = Rc::new(RefCell::new(Vec::new()));
        let driver = io.create_driver(
            &path(r"\Driver\QueuedCreate"),
            Box::new(QueuedCreateBackend { first: None, ready: VecDeque::new(), acks: acks.clone() }),
        ).unwrap();
        let device_path = path(r"\Device\QueuedCreate");
        io.create_device(driver, Some(&device_path), DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0).unwrap();
        assert_eq!(io.open(client, &device_path, AccessMask::GENERIC_READ,
            ShareAccess::READ, CreateOptions::NON_DIRECTORY_FILE, 1), Err(NtStatus::PENDING));
        let first = io.irps.iter().next().unwrap().0;
        let (handle, _file, _device, _object) = io.open_with_details(client, &device_path,
            AccessMask::GENERIC_READ, ShareAccess::READ, CreateOptions::NON_DIRECTORY_FILE, 1)
            .expect("target CREATE behind unrelated completion must become visible");
        assert!(io.completed_irp(first).is_some(), "unrelated completion remains published");
        assert_eq!(acks.borrow().len(), 1, "only target CREATE is acknowledged");
        assert_ne!(acks.borrow()[0], first);
        io.close(client, handle).unwrap();
    }

    #[test]
    fn endless_unrelated_ready_queue_returns_pending_without_target_ack() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let target = Rc::new(RefCell::new(None));
        let polls = Rc::new(Cell::new(0));
        let acks = Rc::new(RefCell::new(Vec::new()));
        let driver = io.create_driver(
            &path(r"\Driver\EndlessCreate"),
            Box::new(EndlessUnrelatedBackend {
                target: target.clone(), polls: polls.clone(), acks: acks.clone(),
            }),
        ).unwrap();
        let device_path = path(r"\Device\EndlessCreate");
        io.create_device(driver, Some(&device_path), DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 0).unwrap();
        assert_eq!(io.open(client, &device_path, AccessMask::GENERIC_READ,
            ShareAccess::READ, CreateOptions::NON_DIRECTORY_FILE, 1), Err(NtStatus::PENDING));
        let target = target.borrow().expect("CREATE was dispatched");
        assert!(polls.get() > 0 && polls.get() <= 64);
        assert!(io.irp(target).is_some(), "pending CREATE keeps canonical IRP");
        assert!(!acks.borrow().contains(&target), "target completion was never polled or ACKed");
    }

    struct ReentrantCreateBackend {
        create_irp: Rc<RefCell<Option<IrpId>>>,
        acks: Rc<Cell<usize>>,
        reject_ack: bool,
        lifecycle_dispatches: Rc<Cell<usize>>,
    }

    impl DriverDispatchBackend for ReentrantCreateBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            if irp.major == major::IRP_MJ_CREATE {
                *self.create_irp.borrow_mut() = Some(irp.irp_id);
                Ok(DispatchOutcome::Pending)
            } else {
                if matches!(irp.major, major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE) {
                    self.lifecycle_dispatches
                        .set(self.lifecycle_dispatches.get() + 1);
                }
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

        fn acknowledge_completion(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            self.acks.set(self.acks.get() + 1);
            if self.reject_ack {
                Err(NtStatus::UNSUCCESSFUL)
            } else {
                Ok(())
            }
        }
    }

    struct ReadyAfterPendingCreateBackend {
        create_irp: Rc<RefCell<Option<IrpId>>>,
        acks: Rc<Cell<usize>>,
        ready: Option<DriverCompletion>,
    }

    impl DriverDispatchBackend for ReadyAfterPendingCreateBackend {
        fn dispatch_irp(
            &mut self,
            _ctx: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            if irp.major == major::IRP_MJ_CREATE {
                *self.create_irp.borrow_mut() = Some(irp.irp_id);
                self.ready = Some(DriverCompletion {
                    irp_id: irp.irp_id,
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: Some(0x5669_6465_6f),
                });
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

        fn poll_completion(&mut self) -> Option<DriverCompletion> {
            self.ready.take()
        }

        fn acknowledge_completion(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            self.acks.set(self.acks.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn pending_return_with_ready_create_completion_opens_exact_file() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let create_irp = Rc::new(RefCell::new(None));
        let acks = Rc::new(Cell::new(0));
        let driver = io
            .create_driver(
                &path(r"\Driver\ReadyPendingOpen"),
                Box::new(ReadyAfterPendingCreateBackend {
                    create_irp: create_irp.clone(),
                    acks: acks.clone(),
                    ready: None,
                }),
            )
            .unwrap();
        let device_path = path(r"\Device\ReadyPendingOpen");
        let device = io
            .create_device(
                driver,
                Some(&device_path),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let (handle, file, resolved_device, object) = io
            .open_with_details(
                client,
                &device_path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            )
            .expect("ready terminal CREATE must open the exact File");
        let irp = create_irp.borrow().expect("CREATE must reach the backend");
        assert_eq!(resolved_device, device);
        assert_eq!(io.file(file).unwrap().object_id, object);
        assert_eq!(io.file(file).unwrap().state, FileState::Open);
        assert_eq!(io.file(file).unwrap().driver_context, Some(0x5669_6465_6f));
        assert!(io.irp(irp).is_none());
        assert_eq!(acks.get(), 1);
        assert_eq!(io.port().live_handle_count(), 1);
        io.close(client, handle).unwrap();
    }

    #[test]
    fn reentrant_create_completion_returns_exact_open_file_and_acknowledges_irp() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let create_irp = Rc::new(RefCell::new(None));
        let acks = Rc::new(Cell::new(0));
        let driver = io
            .create_driver(
                &path(r"\Driver\ReentrantOpen"),
                Box::new(ReentrantCreateBackend {
                    create_irp: create_irp.clone(),
                    acks: acks.clone(),
                    reject_ack: false,
                    lifecycle_dispatches: Rc::new(Cell::new(0)),
                }),
            )
            .unwrap();
        let device_path = path(r"\Device\ReentrantOpen");
        let device = io
            .create_device(
                driver,
                Some(&device_path),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        io.test_reentrant_create_status = Some(NtStatus::SUCCESS);
        let (handle, file, resolved_device, object) = io
            .open_with_details(
                client,
                &device_path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            )
            .unwrap();
        let irp = create_irp.borrow().expect("CREATE must reach the backend");
        assert_eq!(resolved_device, device);
        assert_eq!(io.file(file).unwrap().object_id, object);
        assert_eq!(io.file(file).unwrap().state, FileState::Open);
        assert!(io.irp(irp).is_none(), "ACK must retire the exact CREATE IRP");
        assert_eq!(acks.get(), 1);
        assert_eq!(io.port().live_handle_count(), 1);
        io.close(client, handle).unwrap();
        assert_eq!(io.port().live_handle_count(), 0);
    }

    #[test]
    fn genuinely_pending_create_does_not_publish_a_file_handle() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let create_irp = Rc::new(RefCell::new(None));
        let acks = Rc::new(Cell::new(0));
        let driver = io
            .create_driver(
                &path(r"\Driver\PendingOpenDetails"),
                Box::new(ReentrantCreateBackend {
                    create_irp: create_irp.clone(),
                    acks: acks.clone(),
                    reject_ack: false,
                    lifecycle_dispatches: Rc::new(Cell::new(0)),
                }),
            )
            .unwrap();
        let device_path = path(r"\Device\PendingOpenDetails");
        io.create_device(
            driver,
            Some(&device_path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        assert_eq!(
            io.open_with_details(
                client,
                &device_path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            ),
            Err(NtStatus::PENDING)
        );
        let irp = create_irp.borrow().expect("CREATE must reach the backend");
        assert!(io.irp(irp).is_some(), "pending CREATE retains its canonical IRP");
        assert_eq!(acks.get(), 0);
        assert_eq!(io.port().live_handle_count(), 0);
    }

    #[test]
    fn rejected_reentrant_create_ack_retains_irp_without_reentering_driver() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let create_irp = Rc::new(RefCell::new(None));
        let acks = Rc::new(Cell::new(0));
        let lifecycle_dispatches = Rc::new(Cell::new(0));
        let driver = io
            .create_driver(
                &path(r"\Driver\RejectedCreateAck"),
                Box::new(ReentrantCreateBackend {
                    create_irp: create_irp.clone(),
                    acks: acks.clone(),
                    reject_ack: true,
                    lifecycle_dispatches: lifecycle_dispatches.clone(),
                }),
            )
            .unwrap();
        let device_path = path(r"\Device\RejectedCreateAck");
        io.create_device(
            driver,
            Some(&device_path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        io.test_reentrant_create_status = Some(NtStatus::SUCCESS);
        assert_eq!(
            io.open_with_details(
                client,
                &device_path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            ),
            Err(NtStatus::UNSUCCESSFUL)
        );
        let irp = create_irp.borrow().expect("CREATE must reach the backend");
        let file = io.irp(irp).unwrap().file_id.unwrap();
        assert_eq!(io.irp(irp).unwrap().state, IrpState::Completed);
        assert!(io.completed_irp(irp).is_some());
        assert!(io.manager_owned_irps.contains(&irp));
        assert_eq!(io.file(file).unwrap().state, FileState::CleanupPending);
        assert_eq!(acks.get(), 1);
        assert_eq!(io.port().live_handle_count(), 0);
        assert_eq!(lifecycle_dispatches.get(), 0);
    }

    fn path(name: &str) -> NtPath {
        NtPath::parse_str(name).unwrap()
    }

    #[test]
    fn resolves_two_registered_devices_and_a_symbolic_link() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &path(r"\Driver\OpenDetails"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let first_path = path(r"\Device\OpenDetailsA");
        let second_path = path(r"\Device\OpenDetailsB");
        let first = io
            .create_device(
                driver,
                Some(&first_path),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let second = io
            .create_device(
                driver,
                Some(&second_path),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let link = path(r"\DosDevices\OpenDetailsB");
        io.create_symbolic_link(&link, &second_path).unwrap();

        let (first_handle, first_file, first_device, first_object) = io
            .open_with_details(
                client,
                &first_path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            )
            .unwrap();
        let (second_handle, second_file, second_device, second_object) = io
            .open_with_details(
                client,
                &link,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            )
            .unwrap();
        assert_eq!((first_device, second_device), (first, second));
        assert_ne!(first_file, second_file);
        assert_ne!(first_object, second_object);
        io.close(client, first_handle).unwrap();
        io.close(client, second_handle).unwrap();
        assert_eq!(io.port().live_handle_count(), 0);
    }

    #[test]
    fn failed_identity_lookup_closes_the_transient_handle() {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &path(r"\Driver\OpenRollback"),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device_path = path(r"\Device\OpenRollback");
        io.create_device(
            driver,
            Some(&device_path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        io.port_mut().fail_next_file_reference();
        assert!(matches!(
            io.open_with_details(
                client,
                &device_path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::NON_DIRECTORY_FILE,
                1,
            ),
            Err(NtStatus::INVALID_HANDLE)
        ));
        assert_eq!(io.port().live_handle_count(), 0);
        assert_eq!(io.port().retained_reference_count(), 0);
        io.pump();
        assert_eq!(io.file_count(), 0);
    }
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
        let idx = self.backends.len();
        let target = match kind {
            DriverInstallKind::Mock => DispatchTarget::Mock(MockDispatchId(idx as u64)),
            DriverInstallKind::Kernel => DispatchTarget::Kernel(DriverBackendId(idx as u64)),
            DriverInstallKind::Peer => DispatchTarget::DriverPeer(DriverPeerId(idx as u64)),
        };
        table.retarget(target);
        let result = self.install_driver_record_with_dispatch(
            name,
            DriverBackendId(idx as u64),
            MajorFunctionTable::boxed_from(table),
        );
        if result.is_ok() {
            let registered = self.register_backend(backend);
            assert_eq!(
                registered, idx,
                "backend registry changed during publication"
            );
        }
        result
    }

    fn install_driver_with_majors_kind(
        &mut self,
        name: &NtPath,
        backend: Box<dyn DriverDispatchBackend>,
        kind: DriverInstallKind,
        majors: &[u8],
    ) -> Result<DriverId, NtStatus> {
        let idx = self.backends.len();
        let target = match kind {
            DriverInstallKind::Mock => DispatchTarget::Mock(MockDispatchId(idx as u64)),
            DriverInstallKind::Kernel => DispatchTarget::Kernel(DriverBackendId(idx as u64)),
            DriverInstallKind::Peer => DispatchTarget::DriverPeer(DriverPeerId(idx as u64)),
        };
        let table = MajorFunctionTable::boxed_with_majors(majors, target);
        let result =
            self.install_driver_record_with_dispatch(name, DriverBackendId(idx as u64), table);
        if result.is_ok() {
            let registered = self.register_backend(backend);
            assert_eq!(
                registered, idx,
                "backend registry changed during publication"
            );
        }
        result
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
        self.complete_driver_unload_callback(driver)?;
        let record = self.remove_driver_records_after_unload(driver)?;
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

    /// Open a device File and resolve the exact File, Device and Object Manager identities.
    /// A failed post-open lookup closes the transient handle before reporting the failure.
    pub fn open_with_details(
        &mut self,
        client: ClientId,
        path: &NtPath,
        desired_access: AccessMask,
        share_access: ShareAccess,
        create_options: CreateOptions,
        create_disposition: u32,
    ) -> Result<(HandleValue, FileId, DeviceId, ObjectId), NtStatus> {
        let handle = self.open(
            client,
            path,
            desired_access,
            share_access,
            create_options,
            create_disposition,
        )?;
        match self.reference_open_file_details(client, handle, AccessMask::empty()) {
            Ok((file, device, object)) => Ok((handle, file, device, object)),
            Err(status) => {
                self.close(client, handle)
                    .expect("opened device File must remain closable after identity lookup failure");
                Err(status)
            }
        }
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
        let origin_driver_id = self
            .device(device_id)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?
            .driver_id;

        // 2. Allocate the FileRecord.
        let file_id = self.add_file(FileRecord::new(
            ObjectId::NULL,
            client,
            device_id,
            desired_access,
            share_access,
            create_options,
            path.to_unicode_string(),
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
                self.release_file_record(file_id)?;
                return Err(e);
            }
        };
        let object_reference = match self.port.retain_file_object(client, handle) {
            Ok(reference) => reference,
            Err(status) => {
                let _ = self.port.close_handle(client, handle);
                self.release_file_record(file_id)?;
                return Err(status);
            }
        };
        {
            let file = self.file_mut(file_id).expect("just added");
            file.object_id = file_object;
            file.object_reference = object_reference;
        }

        // 4. Build + dispatch IRP_MJ_CREATE.
        let irp = match self.build_irp_record(
            client,
            origin_driver_id,
            device_id,
            Some(file_id),
            major::IRP_MJ_CREATE,
            IoParameters::Create(CreateParameters {
                opened_case_sensitive: false,
                desired_access,
                share_access,
                create_options,
                create_disposition,
                file_attributes: 0,
                ea_length: 0,
                related_file: None,
            }),
        ) {
            Ok(irp) => irp,
            Err(status) => {
                let _ = self.port.close_handle(client, handle);
                self.release_file_record(file_id)?;
                return Err(status);
            }
        };
        let irp_id = match self.allocate_irp(irp) {
            Ok(id) => id,
            Err(status) => {
                let _ = self.port.close_handle(client, handle);
                self.release_file_record(file_id)?;
                return Err(status);
            }
        };
        // Reentrant IoCompleteRequest may finish CREATE inside dispatch. Reserve the fallback
        // retirement slot before that native effect so an ACK failure can never orphan its IRP.
        if let Err(status) = self.reserve_manager_owned_irp_slot() {
            self.cleanup_failed_open(client, file_id, handle, irp_id)?;
            return Err(status);
        }
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
        if matches!(outcome, Ok(DispatchOutcome::Pending))
            && self.irp(irp_id).is_some_and(|irp| irp.state == IrpState::Dispatched)
        {
            self.publish_ready_create_completion(irp_id);
        }

        // A reentrant IoCompleteRequest can publish terminal CREATE before dispatch returns.
        // Its canonical completion has already moved the File to Open or Closed. The original
        // handle is valid only after the exact backend acknowledges that completion.
        if self
            .irp(irp_id)
            .map(|irp| irp.state != IrpState::Dispatched)
            .unwrap_or(true)
        {
            if let Some(completed) = self.completed_irp(irp_id) {
                assert_eq!(completed.file_id, Some(file_id));
                assert_eq!(completed.client_id, client);
                assert_eq!(completed.major, major::IRP_MJ_CREATE);
                let status = completed.status;
                if let Err(ack_status) = self.acknowledge_completed_irp_strict(irp_id) {
                    self.claim_manager_owned_irp(client, irp_id)
                        .expect("pre-reserved CREATE retirement owner disappeared");
                    if self.file(file_id).is_some_and(|file| file.state == FileState::Open) {
                        self.port.close_handle(client, handle)
                            .expect("unpublished CREATE handle could not close after ACK failure");
                        self.queue_external_file_release(client, file_id)
                            .expect("completed CREATE File could not queue release after ACK failure");
                    } else {
                        self.port.close_handle(client, handle)
                            .expect("unpublished CREATE handle could not close after ACK failure");
                        if let Some(file) = self.file_mut(file_id) {
                            file.close_deferred = true;
                        }
                        self.queue_deferred_file_close(file_id);
                    }
                    return Err(ack_status);
                }
                if crate::file::create_terminal_opens_file(status)
                    && self.file(file_id).is_some_and(|file| file.state == FileState::Open)
                {
                    return Ok(handle);
                }
                self.port.close_handle(client, handle)
                    .expect("failed CREATE handle could not close after ACK");
                self.release_external_file(client, file_id)?;
                return Err(status);
            }
            if let Some(file) = self.file_mut(file_id) {
                file.transition(FileState::ClosePending);
                file.close_deferred = true;
            }
            let _ = self.port.close_handle(client, handle);
            return Err(NtStatus::PENDING);
        }

        // 5. Apply the outcome.
        match outcome {
            Ok(DispatchOutcome::Completed {
                status,
                information,
                file_context,
            }) if status.is_success() => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.transition(IrpState::Completing);
                    irp.transition(IrpState::Completed);
                    irp.status = status;
                    irp.information = information;
                }
                let file = self.file_mut(file_id).unwrap();
                file.driver_context = file_context;
                file.transition(FileState::Open);
                self.free_irp(irp_id);
                Ok(handle)
            }
            Ok(DispatchOutcome::Completed { status, .. }) => {
                self.cleanup_failed_open(client, file_id, handle, irp_id)?;
                Err(status)
            }
            Ok(DispatchOutcome::Failed { status }) => {
                self.cleanup_failed_open(client, file_id, handle, irp_id)?;
                Err(status)
            }
            Ok(DispatchOutcome::Pending) => {
                if let Some(irp) = self.irp_mut(irp_id) {
                    irp.transition(IrpState::Pending);
                }
                if let Some(file) = self.file_mut(file_id) {
                    file.transition(FileState::ClosePending);
                    file.close_deferred = true;
                }
                let _ = self.port.close_handle(client, handle);
                let _ = self.cancel(client, irp_id);
                Err(NtStatus::PENDING)
            }
            Err(status) => {
                self.cleanup_failed_open(client, file_id, handle, irp_id)?;
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
        let driver_id = {
            let irp = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            irp.current_stack()
                .ok_or(NtStatus::INVALID_PARAMETER)?
                .driver_id
        };
        let outcome = self.dispatch_to_driver(driver_id, irp_id, system_buffer);
        #[cfg(test)]
        if let Some(status) = self.test_reentrant_create_status.take() {
            assert!(self.publish_driver_completion(
                driver_id,
                crate::dispatch::DriverCompletion {
                    irp_id,
                    status,
                    information: 0,
                    file_context: Some(0x1234),
                }
            ));
        }
        outcome
    }

    fn cleanup_failed_open(
        &mut self,
        client: ClientId,
        file_id: FileId,
        handle: HandleValue,
        irp_id: IrpId,
    ) -> Result<(), NtStatus> {
        // The I/O Manager's retained ObjectRef keeps the File alive until the
        // IRP reference is gone and this teardown releases the record.
        let _ = self.port.close_handle(client, handle);
        let file = self.file_mut(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
        file.transition(FileState::Closed);
        file.close_deferred = true;
        self.free_irp(irp_id);
        self.release_external_file(client, file_id)
    }
}
