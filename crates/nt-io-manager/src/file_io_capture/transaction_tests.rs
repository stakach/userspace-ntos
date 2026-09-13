//! Canonical multi-IRP source lifetime; only driver execution is fixture-supplied.

use super::{FileIoCapture, FileIoCaptureTable};
use crate::*;
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;
use nt_io_abi::major;
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath, UnicodeString};

struct CaptureOwner {
    capture: FileIoCapture,
    table: Rc<RefCell<FileIoCaptureTable>>,
}

impl Drop for CaptureOwner {
    fn drop(&mut self) {
        self.table.borrow_mut().retire(&mut self.capture).unwrap();
    }
}

struct TransactionDriver {
    lifecycle: MockDriverBackend,
    creates: usize,
    ready: Vec<DriverCompletion>,
    calls: Rc<RefCell<Vec<IrpProjection>>>,
}

impl DriverDispatchBackend for TransactionDriver {
    fn dispatch_irp(
        &mut self,
        context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push(irp.clone());
        if irp.major == major::IRP_MJ_CREATE {
            self.creates += 1;
        }
        if matches!(
            irp.major,
            major::IRP_MJ_QUERY_INFORMATION | major::IRP_MJ_SET_INFORMATION
        ) || (irp.major == major::IRP_MJ_CREATE && self.creates > 1)
        {
            let information = if irp.major == major::IRP_MJ_QUERY_INFORMATION {
                context.system_buffer.fill(0);
                40
            } else {
                0
            };
            self.ready.push(DriverCompletion {
                irp_id: irp.irp_id,
                status: NtStatus::SUCCESS,
                information,
                file_context: None,
            });
            return Ok(DispatchOutcome::Pending);
        }
        self.lifecycle.dispatch_irp(context, irp)
    }

    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        if let Some(completion) = self
            .ready
            .iter_mut()
            .find(|completion| completion.irp_id == irp)
        {
            completion.status = NtStatus::CANCELLED;
            return Ok(());
        }
        self.lifecycle.cancel_irp(irp)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.ready
            .pop()
            .or_else(|| self.lifecycle.poll_completion())
    }
}

fn pending(result: Result<ExternalDispatchResult, NtStatus>) -> IrpId {
    let ExternalDispatchResult::Pending { irp_id } = result.unwrap() else {
        panic!("transaction fixture requires a retained canonical IRP");
    };
    irp_id
}

#[test]
fn capture_owned_transaction_pins_async_source_across_query_ack_target_create_and_source_set() {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let driver = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\CaptureTransaction").unwrap(),
            Box::new(TransactionDriver {
                lifecycle: MockDriverBackend::new(),
                creates: 0,
                ready: Vec::new(),
                calls: calls.clone(),
            }),
        )
        .unwrap();
    let dispatch = io
        .driver(driver)
        .unwrap()
        .dispatch
        .get(major::IRP_MJ_CREATE);
    for major in [
        major::IRP_MJ_QUERY_INFORMATION,
        major::IRP_MJ_SET_INFORMATION,
    ] {
        io.driver_mut(driver).unwrap().dispatch.set(major, dispatch);
    }
    let path = NtPath::parse_str(r"\Device\CaptureTransaction").unwrap();
    let device = io
        .create_device(
            driver,
            Some(&path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let access = AccessMask::DELETE;
    let handle = io
        .open(
            client,
            &path,
            access,
            ShareAccess::READ | ShareAccess::WRITE,
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let (source, _) = io
        .reference_open_file(client, handle, AccessMask::empty())
        .unwrap();
    let captures = Rc::new(RefCell::new(FileIoCaptureTable::new()));
    let mut initial = captures
        .borrow_mut()
        .capture(&mut io, source, device, access.bits())
        .unwrap();
    let mut query_output = [0; 40];
    let query_irp = pending(io.build_and_dispatch_external_to_device(
        client,
        device,
        Some(source),
        0,
        20,
        major::IRP_MJ_QUERY_INFORMATION,
        IoParameters::QueryInformation(InformationParameters {
            info_class: 4,
            length: 40,
        }),
        0,
        40,
        &mut query_output,
    ));
    // Async final-handle cleanup is not postponed by a policy reference.
    io.close(client, handle).unwrap();
    assert_eq!(io.file(source).unwrap().state, FileState::ClosePending);
    let retained = captures
        .borrow_mut()
        .capture_owned(&mut io, source, device, access.bits())
        .unwrap();
    let owner = CaptureOwner {
        capture: retained,
        table: captures.clone(),
    };
    let mut rename = alloc::vec![0; 24];
    rename[16..20].copy_from_slice(&2u32.to_le_bytes());
    rename[20..22].copy_from_slice(&(b'x' as u16).to_le_bytes());
    let transaction = PendingSetFileName::awaiting_source_query(
        source.raw(),
        10,
        SetInformationControl::ReplaceIfExists(false),
        alloc::vec![b'x', 0],
        rename,
    )
    .unwrap()
    .with_source_owner(owner);
    let mut transactions = PendingSetFileNameTable::new();
    let slot = transactions.reserve().unwrap();
    let transaction_id = transactions.park_reserved(slot, transaction).unwrap();
    captures.borrow_mut().retire(&mut initial).unwrap();
    captures.borrow_mut().redrive(&mut io, usize::MAX);
    assert_eq!(io.file_reference_count(source), 1);
    io.pump();
    assert_eq!(io.completed_irp(query_irp).unwrap().information, 40);
    io.acknowledge_completed_irp(query_irp).unwrap();
    io.pump();
    assert!(io.file(source).is_some());
    assert_eq!(io.file(source).unwrap().outstanding_irp_refs, 0);
    let metadata = io.owned_file_metadata(client, source).unwrap();
    assert_eq!(metadata.device_id, device);

    let target_access = AccessMask::from_bits_retain(0x02);
    let target = io
        .allocate_external_file(
            client,
            metadata.device_id,
            target_access,
            ShareAccess::READ | ShareAccess::WRITE,
            CreateOptions::OPEN_FOR_BACKUP_INTENT,
            UnicodeString::from_str(r"\Device\CaptureTransaction\target"),
        )
        .unwrap();
    let mut transaction = transactions.take_for_update(transaction_id).unwrap();
    assert!(transaction.advance_to_target_create(target.raw()));
    assert!(transactions.restore_update(transaction_id, transaction));
    let target_irp = pending(io.build_and_dispatch_external_to_device(
        client,
        device,
        Some(target),
        0,
        20,
        major::IRP_MJ_CREATE,
        IoParameters::Create(CreateParameters {
            desired_access: target_access,
            share_access: ShareAccess::READ | ShareAccess::WRITE,
            create_options: CreateOptions::OPEN_FOR_BACKUP_INTENT,
            create_disposition: 1,
            ..Default::default()
        }),
        0,
        0,
        &mut [],
    ));
    io.pump();
    assert!(
        io.file(source).is_some(),
        "pending target CREATE owns no source IRP reference"
    );
    assert_eq!(io.file(source).unwrap().outstanding_irp_refs, 0);
    assert_eq!(io.file_reference_count(source), 1);
    io.acknowledge_completed_irp(target_irp).unwrap();
    io.pump();
    assert_eq!(io.file(target).unwrap().state, FileState::Open);

    let mut transaction = transactions.take_for_update(transaction_id).unwrap();
    assert!(transaction.advance_to_source_set());
    let mut input = transaction.set_information().to_vec();
    let parameters = IoParameters::SetInformation(SetInformationParameters {
        info_class: 10,
        length: input.len() as u32,
        target_file: Some(target),
        control: transaction.control,
    });
    assert!(transactions.restore_update(transaction_id, transaction));
    let set_irp = pending(io.build_and_dispatch_external_to_device(
        client,
        device,
        Some(source),
        0,
        20,
        major::IRP_MJ_SET_INFORMATION,
        parameters.clone(),
        input.len() as u32,
        0,
        &mut input,
    ));
    let set_request = calls.borrow().last().unwrap().clone();
    assert_eq!(set_request.file_id, Some(source));
    assert_eq!(set_request.parameters, parameters);
    io.pump();
    io.acknowledge_completed_irp(set_irp).unwrap();
    io.pump();
    assert!(
        io.file(source).is_some(),
        "transaction terminal teardown still owns pointer"
    );
    let transaction = transactions.take_for_update(transaction_id).unwrap();
    assert!(transactions.finish_update(transaction_id));
    drop(transaction);
    assert_eq!(
        io.file_reference_count(source),
        1,
        "Drop retires, explicit redrive releases"
    );
    assert_eq!(
        captures.borrow_mut().redrive(&mut io, usize::MAX).released,
        1
    );
    assert_eq!(io.file_reference_count(source), 0);
    let body = io
        .file(source)
        .expect("unowned source is queued for CLOSE, not deleted");
    assert_eq!(body.state, FileState::ClosePending);
    assert!(!body.close_dispatched);
    assert_eq!(body.outstanding_irp_refs, 0);
    let before = calls.borrow().len();
    assert_eq!(
        io.build_and_dispatch_external_to_device(
            client,
            device,
            Some(source),
            0,
            20,
            major::IRP_MJ_SET_INFORMATION,
            parameters,
            input.len() as u32,
            0,
            &mut input,
        ),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        calls.borrow().len(),
        before,
        "unowned closed source cannot enter driver"
    );
    io.pump();
    assert!(io.file(source).is_none());
    io.release_external_file(client, target).unwrap();
    io.pump();
    assert!(io.file(target).is_none());
    assert!(captures.borrow().is_empty());
    assert!(transactions.is_empty());
    assert_eq!(
        calls
            .borrow()
            .iter()
            .filter(|irp| irp.major == major::IRP_MJ_CLOSE && irp.file_id == Some(source))
            .count(),
        1
    );
}
