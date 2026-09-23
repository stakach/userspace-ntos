use super::*;
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::{Cell, RefCell};
use nt_types::{NtPath, UnicodeString};

use crate::{
    CreateOptions, CreateParameters, DeviceCharacteristics, DeviceFlags, DeviceType,
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend,
    ExternalDispatchResult, IrpProjection, MockObjectPort, ShareAccess,
};

struct RecordingBackend {
    majors: Rc<RefCell<Vec<u8>>>,
    cancels: Rc<Cell<usize>>,
    pending_create: bool,
}

impl DriverDispatchBackend for RecordingBackend {
    fn dispatch_irp(
        &mut self,
        _context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.majors.borrow_mut().push(irp.major);
        if irp.major == major::IRP_MJ_CREATE && self.pending_create {
            return Ok(DispatchOutcome::Pending);
        }
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: (irp.major == major::IRP_MJ_CREATE).then_some(0x1234),
        })
    }

    fn cancel_irp(&mut self, _irp: IrpId) -> Result<(), NtStatus> {
        self.cancels.set(self.cancels.get() + 1);
        Ok(())
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        None
    }

    fn acknowledge_completion(&mut self, _irp: IrpId) -> Result<(), NtStatus> {
        Ok(())
    }
}

fn external_file(
    pending_create: bool,
) -> (
    IoManager<MockObjectPort>,
    ClientId,
    FileId,
    Rc<RefCell<Vec<u8>>>,
    Rc<Cell<usize>>,
    ExternalDispatchResult,
) {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let majors = Rc::new(RefCell::new(Vec::new()));
    let cancels = Rc::new(Cell::new(0));
    let driver = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\QueuedRelease").unwrap(),
            Box::new(RecordingBackend {
                majors: majors.clone(),
                cancels: cancels.clone(),
                pending_create,
            }),
        )
        .unwrap();
    let device = io
        .create_device(
            driver,
            Some(&NtPath::parse_str(r"\Device\QueuedRelease").unwrap()),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let file = io
        .allocate_external_file(
            client,
            device,
            AccessMask::GENERIC_READ,
            ShareAccess::READ,
            CreateOptions::empty(),
            UnicodeString::from_str("QueuedRelease"),
        )
        .unwrap();
    let create = io
        .build_and_dispatch_external_to_device(
            client,
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
        )
        .unwrap();
    (io, client, file, majors, cancels, create)
}

#[test]
fn final_external_file_release_queues_cleanup_without_backend_entry() {
    let (mut io, client, file, majors, cancels, create) = external_file(false);
    assert!(matches!(
        create,
        ExternalDispatchResult::Completed {
            status: NtStatus::SUCCESS,
            ..
        }
    ));
    assert_eq!(io.file(file).unwrap().state, FileState::Open);
    assert_eq!(&*majors.borrow(), &[major::IRP_MJ_CREATE]);

    io.queue_external_file_release(client, file).unwrap();
    let record = io.file(file).unwrap();
    assert_eq!(record.state, FileState::CleanupPending);
    assert!(record.close_deferred);
    assert!(record.close_retry_queued);
    assert!(!record.cleanup_dispatched);
    assert!(!record.close_dispatched);
    assert_eq!(io.irp_count(), 0);
    assert_eq!(&*majors.borrow(), &[major::IRP_MJ_CREATE]);
    assert_eq!(cancels.get(), 0);
    io.queue_external_file_release(client, file).unwrap();
    assert_eq!(&*majors.borrow(), &[major::IRP_MJ_CREATE]);
    assert_eq!(cancels.get(), 0);
    let prepared = io.prepare_file_lifecycle_owned(client, file).unwrap();
    assert_eq!(prepared.projection().major, major::IRP_MJ_CLEANUP);
    io.discard_prepared_file_lifecycle(prepared).unwrap();
}

#[test]
fn pending_external_create_queues_abandonment_without_inline_cancel() {
    let (mut io, client, file, majors, cancels, create) = external_file(true);
    let irp_id = match create {
        ExternalDispatchResult::Pending { irp_id } => irp_id,
        other => panic!("expected pending CREATE, got {other:?}"),
    };
    assert_eq!(io.file(file).unwrap().state, FileState::CreateIrpDispatched);
    io.queue_external_file_release(client, file).unwrap();
    let record = io.file(file).unwrap();
    assert_eq!(record.state, FileState::ClosePending);
    assert!(record.close_deferred);
    assert!(record.close_retry_queued);
    assert_eq!(io.irp(irp_id).unwrap().state, IrpState::CancelRequested);
    assert!(io.manager_owned_irps.contains(&irp_id));
    assert!(io.cancel_dispatch_retries.contains(&irp_id));
    assert_eq!(&*majors.borrow(), &[major::IRP_MJ_CREATE]);
    assert_eq!(cancels.get(), 0);
    io.queue_external_file_release(client, file).unwrap();
    assert_eq!(io.cancel_dispatch_retries.iter().filter(|id| **id == irp_id).count(), 1);
    assert_eq!(cancels.get(), 0);
    assert_eq!(
        io.prepare_file_lifecycle_owned(client, file).unwrap_err(),
        NtStatus::DELETE_PENDING
    );
}
