//! Compose projection ownership with real canonical CLEANUP/CLOSE and backend completion.
//! These are host-model lifecycle tests, not native registration or IPC evidence.

use crate::{
    CreateOptions, CreateParameters, DeviceCharacteristics, DeviceFlags, DeviceType,
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend,
    ExternalDispatchResult, FileId, FileState, HostedFileUnbindOutcome, IoManager, IoParameters,
    IrpId, IrpProjection, MockDriverBackend, MockObjectPort, ShareAccess,
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath, UnicodeString};

struct Recording {
    backend: MockDriverBackend,
    calls: Rc<RefCell<Vec<u8>>>,
    pending_close: bool,
    deny_create: Rc<Cell<bool>>,
}

impl DriverDispatchBackend for Recording {
    fn dispatch_irp(
        &mut self,
        context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push(irp.major);
        if irp.major == major::IRP_MJ_CREATE && self.deny_create.get() {
            return Ok(DispatchOutcome::Completed {
                status: NtStatus::ACCESS_DENIED,
                information: 0,
                file_context: None,
            });
        }
        if irp.major == major::IRP_MJ_CLOSE && self.pending_close {
            self.backend.set_force_pending(true);
            self.backend.set_pending_completion(NtStatus::SUCCESS, 0);
        }
        self.backend.dispatch_irp(context, irp)
    }

    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.backend.cancel_irp(irp)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.backend.poll_completion()
    }

    fn acknowledge_completion(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.backend.acknowledge_completion(irp)
    }
}

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    handle: HandleValue,
    file: FileId,
    calls: Rc<RefCell<Vec<u8>>>,
    deny_create: Rc<Cell<bool>>,
}

impl Fixture {
    fn new(pending_close: bool) -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let deny_create = Rc::new(Cell::new(false));
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ProjectionLifetime").unwrap(),
                Box::new(Recording {
                    backend: MockDriverBackend::new(),
                    calls: calls.clone(),
                    pending_close,
                    deny_create: deny_create.clone(),
                }),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\ProjectionLifetime").unwrap();
        io.create_device(
            driver,
            Some(&path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = io
            .open(
                client,
                &path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let file = io
            .reference_open_file_details(client, handle, AccessMask::empty())
            .unwrap()
            .0;
        Self {
            io,
            client,
            handle,
            file,
            calls,
            deny_create,
        }
    }

    fn count(&self, major: u8) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|&&call| call == major)
            .count()
    }
}

#[test]
fn projections_allow_inline_and_pending_close_but_pin_final_body_retirement() {
    for pending in [false, true] {
        let mut f = Fixture::new(pending);
        let first_domain = f.io.register_hosted_domain();
        let second_domain = f.io.register_hosted_domain();
        let first =
            f.io.bind_hosted_file_identity(first_domain, 0x4000, f.file)
                .unwrap();
        let second =
            f.io.bind_hosted_file_identity(second_domain, 0x4000, f.file)
                .unwrap();
        let mut publication = f.io.lease_hosted_file_identity(first).unwrap();
        let object_reference = f.io.file(f.file).unwrap().object_reference;
        assert_ne!(object_reference, 0);
        assert_eq!(f.io.file_reference_count(f.file), 0);
        assert!(f.io.remove_file(f.file).is_none());
        assert_eq!(
            f.io.release_file_record(f.file),
            Err(NtStatus::DELETE_PENDING)
        );
        assert_eq!(
            f.io.file(f.file).unwrap().object_reference,
            object_reference
        );

        f.io.close(f.client, f.handle).unwrap();
        for _ in 0..3 {
            f.io.pump();
        }
        assert_eq!(f.count(major::IRP_MJ_CLEANUP), 1);
        assert_eq!(f.count(major::IRP_MJ_CLOSE), 1);
        let record = f.io.file(f.file).unwrap();
        assert!(record.close_dispatched);
        assert_eq!(record.outstanding_irp_refs, 0);
        assert_eq!(record.object_reference, object_reference);
        assert_eq!(f.io.hosted_file_identities(f.file).unwrap().len(), 2);
        assert_eq!(
            f.io.unbind_hosted_file_identity(first),
            Err(NtStatus::DELETE_PENDING)
        );
        assert_eq!(
            f.io.unbind_hosted_file_identity(second),
            Ok(HostedFileUnbindOutcome::Removed)
        );
        f.io.pump();
        assert!(f.io.file(f.file).is_some());
        assert_eq!(f.io.hosted_file_identities(f.file).unwrap(), [first]);

        f.io.release_hosted_file_publication(&mut publication)
            .unwrap();
        assert_eq!(
            f.io.unbind_hosted_file_identity(first),
            Ok(HostedFileUnbindOutcome::Removed)
        );
        assert!(!f.io.has_hosted_file_bindings(f.file));
        // Unbind is memory-only; the existing close pump performs canonical object retirement.
        assert!(f.io.file(f.file).is_some());
        assert_eq!(f.count(major::IRP_MJ_CLOSE), 1);
        f.io.pump();
        assert!(f.io.file(f.file).is_none());
        assert_eq!(f.io.irp_count(), 0);
        assert_eq!(f.count(major::IRP_MJ_CLOSE), 1);
        assert_eq!(
            f.io.unbind_hosted_file_identity(first),
            Ok(HostedFileUnbindOutcome::AlreadyAbsent)
        );
        f.io.unregister_hosted_domain(first_domain).unwrap();
        f.io.unregister_hosted_domain(second_domain).unwrap();
    }
}

#[test]
fn canonical_references_block_close_but_publication_leases_only_block_unbind() {
    let mut f = Fixture::new(false);
    let domain = f.io.register_hosted_domain();
    let identity =
        f.io.bind_hosted_file_identity(domain, 0x8000, f.file)
            .unwrap();
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    let mut publication = f.io.lease_hosted_file_identity(identity).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert_eq!(f.count(major::IRP_MJ_CLEANUP), 1);
    assert_eq!(f.count(major::IRP_MJ_CLOSE), 0);
    assert_eq!(f.io.file_reference_count(f.file), 1);
    f.io.release_file_reference(&mut owner).unwrap();
    f.io.pump();
    assert_eq!(f.count(major::IRP_MJ_CLOSE), 1);
    assert!(publication.is_held());
    assert_eq!(
        f.io.unbind_hosted_file_identity(identity),
        Err(NtStatus::DELETE_PENDING)
    );
    f.io.release_hosted_file_publication(&mut publication)
        .unwrap();
    f.io.unbind_hosted_file_identity(identity).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
    f.io.unregister_hosted_domain(domain).unwrap();
}

#[test]
fn unpublished_file_release_refusal_keeps_retry_ownership_with_the_caller() {
    let mut f = Fixture::new(false);
    let device = f.io.file(f.file).unwrap().device_id;
    let file =
        f.io.allocate_external_file(
            f.client,
            device,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            UnicodeString::from_str("Unpublished"),
        )
        .unwrap();
    let domain = f.io.register_hosted_domain();
    let identity =
        f.io.bind_hosted_file_identity(domain, 0x9000, file)
            .unwrap();
    assert_eq!(
        f.io.release_external_file(f.client, file),
        Err(NtStatus::DELETE_PENDING)
    );
    assert!(!f.io.file(file).unwrap().close_deferred);
    assert!(!f.io.file(file).unwrap().close_retry_queued);
    f.io.unbind_hosted_file_identity(identity).unwrap();
    f.io.pump();
    // Refusal did not consume the caller's ownership or promise automatic retirement.
    assert!(f.io.file(file).is_some());
    assert_eq!(f.count(major::IRP_MJ_CLOSE), 0);
    f.io.release_external_file(f.client, file).unwrap();
    assert!(f.io.file(file).is_none());
    f.io.unregister_hosted_domain(domain).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert_eq!(f.io.file_count(), 0);
}

#[test]
fn explicit_unopened_handoff_retires_allocated_and_failed_create_after_binding_drain() {
    for fail_create in [false, true] {
        let mut f = Fixture::new(false);
        let device = f.io.file(f.file).unwrap().device_id;
        let file =
            f.io.allocate_external_file(
                f.client,
                device,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                UnicodeString::from_str("Unpublished"),
            )
            .unwrap();
        let domain = f.io.register_hosted_domain();
        let binding =
            f.io.bind_hosted_file_identity(domain, 0x9000, file)
                .unwrap();
        if fail_create {
            f.deny_create.set(true);
            assert_eq!(
                f.io.build_and_dispatch_external_to_device(
                    f.client,
                    device,
                    Some(file),
                    0,
                    42,
                    major::IRP_MJ_CREATE,
                    IoParameters::Create(CreateParameters {
                        desired_access: AccessMask::GENERIC_READ,
                        share_access: ShareAccess::READ,
                        ..Default::default()
                    }),
                    0,
                    0,
                    &mut [],
                ),
                Ok(ExternalDispatchResult::Completed {
                    status: NtStatus::ACCESS_DENIED,
                    information: 0,
                    file_context: None,
                })
            );
        }
        let expected_state = if fail_create {
            FileState::Closed
        } else {
            FileState::Allocated
        };
        assert_eq!(f.io.file(file).unwrap().state, expected_state);
        assert_eq!(
            f.io.release_external_file(f.client, file),
            Err(NtStatus::DELETE_PENDING)
        );
        assert!(!f.io.file(file).unwrap().close_deferred);
        assert!(!f.io.file(file).unwrap().close_retry_queued);
        let calls_before = f.calls.borrow().clone();
        assert_eq!(
            f.io.defer_unopened_external_file_release(f.client, file),
            Ok(())
        );
        assert!(f.io.file(file).unwrap().close_deferred);
        assert!(f.io.file(file).unwrap().close_retry_queued);
        assert_eq!(
            f.io.defer_unopened_external_file_release(f.client, file),
            Ok(())
        );
        assert_eq!(*f.calls.borrow(), calls_before);
        f.io.pump();
        assert_eq!(f.io.file(file).unwrap().state, expected_state);
        assert_eq!(*f.calls.borrow(), calls_before);
        assert_eq!(
            f.io.hosted_file_identity_at(domain, file, 0x9000),
            Ok(Some(binding))
        );
        f.io.unbind_hosted_file_identity(binding).unwrap();
        f.io.pump();
        assert!(f.io.file(file).is_none());
        assert_eq!(
            *f.calls.borrow(),
            calls_before,
            "unopened File must not receive CLEANUP or CLOSE"
        );
        assert_eq!(f.io.irp_count(), 0);
        f.io.unregister_hosted_domain(domain).unwrap();
        f.io.close(f.client, f.handle).unwrap();
        f.io.pump();
        assert_eq!(f.io.file_count(), 0);
    }
}

#[test]
fn unopened_handoff_rejects_wrong_identity_and_open_lifetime_without_mutation() {
    let mut f = Fixture::new(false);
    let other_client = f.io.register_client();
    let device = f.io.file(f.file).unwrap().device_id;
    let file =
        f.io.allocate_external_file(
            f.client,
            device,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            UnicodeString::from_str("Unpublished"),
        )
        .unwrap();
    let calls_before = f.calls.borrow().clone();
    assert_eq!(
        f.io.defer_unopened_external_file_release(other_client, file),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(
        f.io.defer_unopened_external_file_release(f.client, FileId::NULL),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(
        f.io.defer_unopened_external_file_release(f.client, f.file),
        Err(NtStatus::INVALID_PARAMETER)
    );
    for (id, state) in [(file, FileState::Allocated), (f.file, FileState::Open)] {
        let record = f.io.file(id).unwrap();
        assert_eq!(record.state, state);
        assert!(!record.close_deferred);
        assert!(!record.close_retry_queued);
        assert!(!record.cleanup_dispatched);
        assert!(!record.close_dispatched);
        assert_eq!(record.outstanding_irp_refs, 0);
    }
    assert_eq!(*f.calls.borrow(), calls_before);
    assert_eq!(f.io.irp_count(), 0);
    f.io.release_external_file(f.client, file).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert_eq!(f.io.file_count(), 0);
}
