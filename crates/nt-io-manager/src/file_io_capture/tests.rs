use super::*;
use crate::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext,
    DispatchOutcome, DriverCompletion, DriverDispatchBackend, IrpId, IrpProjection,
    MockDriverBackend, MockObjectPort, ShareAccess,
};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::RefCell;
use nt_io_abi::major;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath};

struct Recording {
    driver: MockDriverBackend,
    calls: Rc<RefCell<Vec<u8>>>,
}

impl DriverDispatchBackend for Recording {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.calls.borrow_mut().push(irp.major);
        self.driver.dispatch_irp(ctx, irp)
    }
    fn cancel_irp(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.driver.cancel_irp(irp)
    }
    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.driver.poll_completion()
    }
    fn acknowledge_completion(&mut self, irp: IrpId) -> Result<(), NtStatus> {
        self.driver.acknowledge_completion(irp)
    }
}

type Setup = (
    IoManager<MockObjectPort>,
    ClientId,
    HandleValue,
    FileId,
    DeviceId,
    Rc<RefCell<Vec<u8>>>,
);

fn opened() -> Setup {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let calls = Rc::new(RefCell::new(Vec::new()));
    let driver = io
        .create_driver(
            &NtPath::parse_str("\\Driver\\Capture").unwrap(),
            Box::new(Recording {
                driver: MockDriverBackend::new(),
                calls: calls.clone(),
            }),
        )
        .unwrap();
    let path = NtPath::parse_str("\\Device\\Capture").unwrap();
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
    let handle = io
        .open(
            client,
            &path,
            AccessMask::GENERIC_READ,
            ShareAccess::empty(),
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let (file, _) = io
        .reference_open_file(client, handle, AccessMask::empty())
        .unwrap();
    io.file_mut(file).unwrap().driver_context = Some(0x1234);
    (io, client, handle, file, device, calls)
}

fn count(calls: &Rc<RefCell<Vec<u8>>>, major: u8) -> usize {
    calls
        .borrow()
        .iter()
        .filter(|&&value| value == major)
        .count()
}

#[test]
fn capture_survives_last_handle_cleanup_and_release_only_queues_close() {
    let (mut io, client, handle, file, device, calls) = opened();
    let mut table = FileIoCaptureTable::new();
    let mut capture = table.capture(&mut io, file, device, 0x80).unwrap();
    assert_eq!(io.file_reference_count(file), 1);
    io.close(client, handle).unwrap();
    assert_eq!(count(&calls, major::IRP_MJ_CLEANUP), 1);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    io.pump();
    assert!(io.file(file).is_some());
    assert_eq!(capture.fs_context(), 0x1234);
    assert_eq!(capture.granted_access(), 0x80);
    table.retire(&mut capture).unwrap();
    assert!(!capture.is_held());
    assert_eq!(io.file_reference_count(file), 1);
    table.release_retired(&mut io, capture.identity()).unwrap();
    assert!(table.is_empty());
    assert!(io.file(file).unwrap().close_retry_queued);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    io.pump();
    assert!(io.file(file).is_none());
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn snapshot_does_not_relookup_replaced_handle_or_mutable_driver_context() {
    let (mut io, client, handle, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    let mut capture = table.capture(&mut io, file, device, 0x80).unwrap();
    io.close(client, handle).unwrap();
    let path = NtPath::parse_str("\\Device\\Capture").unwrap();
    let replacement_handle = io
        .open(
            client,
            &path,
            AccessMask::GENERIC_WRITE,
            ShareAccess::empty(),
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let (replacement, _) = io
        .reference_open_file(client, replacement_handle, AccessMask::empty())
        .unwrap();
    assert_ne!(replacement, file);
    io.file_mut(file).unwrap().driver_context = Some(0x9876);
    assert_eq!(capture.file_id(), file);
    assert_eq!(capture.device_id(), device);
    assert_eq!(capture.fs_context(), 0x1234);
    assert_eq!(capture.granted_access(), 0x80);
    table.retire(&mut capture).unwrap();
    table.redrive(&mut io, 1);
    io.pump();
    assert!(io.file(file).is_none());
    assert!(io.file(replacement).is_some());
}

#[test]
fn wrong_manager_release_refusal_retains_owner_then_recovers() {
    let (mut io, _, _, file, device, _) = opened();
    let (mut wrong, _, _, foreign, _, _) = opened();
    assert_eq!(file, foreign);
    let mut table = FileIoCaptureTable::new();
    let mut capture = table.capture(&mut io, file, device, 7).unwrap();
    table.retire(&mut capture).unwrap();
    assert_eq!(
        table.release_retired(&mut wrong, capture.identity()),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        table.get(capture.identity()).unwrap().last_error,
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.file_reference_count(file), 1);
    assert_eq!(wrong.file_reference_count(foreign), 0);
    assert_eq!(
        table.redrive(&mut io, 1),
        FileIoCaptureRedrive {
            attempted: 1,
            released: 1,
            refused: 0
        }
    );
    assert!(table.is_empty());
    assert_eq!(io.file_reference_count(file), 0);
}

#[test]
fn foreign_retirement_preserves_token_and_active_release_is_refused() {
    let (mut io, _, _, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    let mut wrong = FileIoCaptureTable::new();
    let mut capture = table.capture(&mut io, file, device, 7).unwrap();
    assert_eq!(wrong.retire(&mut capture), Err(NtStatus::INVALID_PARAMETER));
    assert!(capture.is_held());
    assert_eq!(
        table.release_retired(&mut io, capture.identity()),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(table.redrive(&mut io, 8).attempted, 0);
    assert_eq!(io.file_reference_count(file), 1);
    table.retire(&mut capture).unwrap();
    assert_eq!(table.retire(&mut capture), Err(NtStatus::INVALID_PARAMETER));
    table.release_retired(&mut io, capture.identity()).unwrap();
}

#[test]
fn reset_and_slot_reuse_cannot_revalidate_stale_identity() {
    let (mut io, _, _, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    let mut first = table.capture(&mut io, file, device, 7).unwrap();
    let stale = first.identity();
    assert_eq!(table.reset(), Err(NtStatus::INVALID_PARAMETER));
    table.retire(&mut first).unwrap();
    assert_eq!(table.reset(), Err(NtStatus::INVALID_PARAMETER));
    table.release_retired(&mut io, stale).unwrap();
    table.reset().unwrap();
    let mut next = table.capture(&mut io, file, device, 8).unwrap();
    assert_eq!(stale.slot(), next.identity().slot());
    assert_ne!(stale, next.identity());
    assert!(table.get(stale).is_none());
    assert_eq!(
        table.release_retired(&mut io, stale),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(io.file_reference_count(file), 1);
    table.retire(&mut next).unwrap();
    table.redrive(&mut io, 1);
}

#[test]
fn invalid_capture_and_exhaustion_do_not_retain() {
    let (mut io, _, _, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    assert_eq!(
        table.capture(&mut io, FileId::NULL, device, 7).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
    assert_eq!(
        table.capture(&mut io, file, DeviceId::NULL, 7).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
    table.next_generation = 0;
    assert_eq!(
        table.capture(&mut io, file, device, 7).unwrap_err(),
        NtStatus::INSUFFICIENT_RESOURCES
    );
    assert_eq!(io.file_reference_count(file), 0);
    assert!(table.is_empty());
}

#[test]
fn generation_exhaustion_cannot_reset_into_reuse() {
    let (mut io, _, _, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    table.next_generation = u64::MAX;
    let mut last = table.capture(&mut io, file, device, 7).unwrap();
    assert_eq!(last.identity().generation, u64::MAX);
    table.retire(&mut last).unwrap();
    table.release_retired(&mut io, last.identity()).unwrap();
    table.reset().unwrap();
    assert_eq!(
        table.capture(&mut io, file, device, 7).unwrap_err(),
        NtStatus::INSUFFICIENT_RESOURCES
    );
    assert_eq!(io.file_reference_count(file), 0);
}

#[test]
fn last_handle_cleanup_does_not_authorize_a_fresh_capture() {
    let (mut io, client, handle, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    let mut existing = table.capture(&mut io, file, device, 7).unwrap();
    io.close(client, handle).unwrap();
    assert_eq!(
        table.capture(&mut io, file, device, 7).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
    assert_eq!(io.file_reference_count(file), 1);
    table.retire(&mut existing).unwrap();
    table.redrive(&mut io, 1);
    io.pump();
    assert!(io.file(file).is_none());
}

#[test]
fn dropped_token_keeps_reference_and_cannot_be_redriven_implicitly() {
    let (mut io, _, _, file, device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    let capture = table.capture(&mut io, file, device, 7).unwrap();
    let identity = capture.identity();
    drop(capture);
    assert!(!table.get(identity).unwrap().retiring);
    assert_eq!(table.redrive(&mut io, usize::MAX).attempted, 0);
    assert_eq!(io.file_reference_count(file), 1);
    assert_eq!(table.reset(), Err(NtStatus::INVALID_PARAMETER));
}

#[test]
fn bounded_redrive_is_fair_when_an_earlier_manager_refuses() {
    let (mut io, _, _, file, device, _) = opened();
    let (mut other, _, _, other_file, other_device, _) = opened();
    let mut table = FileIoCaptureTable::new();
    let mut first = table
        .capture(&mut other, other_file, other_device, 7)
        .unwrap();
    let mut second = table.capture(&mut io, file, device, 8).unwrap();
    table.retire(&mut first).unwrap();
    table.retire(&mut second).unwrap();
    assert_eq!(table.redrive(&mut io, 0).attempted, 0);
    assert_eq!(table.redrive(&mut io, 1).refused, 1);
    assert_eq!(table.redrive(&mut io, 1).released, 1);
    assert!(table.get(first.identity()).is_some());
    assert!(table.get(second.identity()).is_none());
    assert_eq!(table.redrive(&mut other, 1).released, 1);
    assert!(table.is_empty());
    assert_eq!(table.redrive(&mut io, 1).attempted, 0);
}

#[test]
fn every_pre_dispatch_exit_retires_without_fabricating_irps() {
    let (mut io, _, _, file, device, calls) = opened();
    let mut table = FileIoCaptureTable::new();
    let before = calls.borrow().len();
    // Model access, buffer, event, capacity and Busy-admission failures after capture.
    for _failure_stage in 0..5 {
        let mut capture = table.capture(&mut io, file, device, 7).unwrap();
        table.retire(&mut capture).unwrap();
        table.release_retired(&mut io, capture.identity()).unwrap();
        assert!(table.is_empty());
        assert_eq!(io.file_reference_count(file), 0);
    }
    assert_eq!(calls.borrow().len(), before);
}

#[test]
fn canonical_capture_keeps_policy_cleanup_owner_until_real_close() {
    use nt_io_completion::{FileCompletionTable, FileIoAcquireResult};
    let (mut io, client, handle, file, device, _) = opened();
    let mut policy = FileCompletionTable::<1>::new();
    policy.insert_file(file.raw(), device.raw(), false).unwrap();
    let mut table = FileIoCaptureTable::new();
    let mut capture = table.capture(&mut io, file, device, 7).unwrap();
    assert!(policy.release_handle(file.raw()).unwrap().cleanup_required);
    assert_eq!(
        policy.begin_cleanup(file.raw()).unwrap(),
        FileIoAcquireResult::Bypassed
    );
    assert!(policy.mark_cleanup_lifecycle_started(file.raw()).unwrap());
    io.close(client, handle).unwrap();
    io.pump();
    assert!(io.file(file).is_some());
    assert_eq!(policy.active_cleanup_from(0).unwrap().1, file.raw());
    table.retire(&mut capture).unwrap();
    table.release_retired(&mut io, capture.identity()).unwrap();
    io.pump();
    assert!(io.file(file).is_none());
    assert!(
        policy
            .release_cleanup_reference(file.raw())
            .unwrap()
            .close_required
    );
    assert!(policy.active_cleanup_from(0).is_none());
}

#[test]
fn capture_owned_extends_existing_pointer_after_cleanup_without_reopening_handle() {
    let (mut io, client, handle, file, device, calls) = opened();
    let mut captures = FileIoCaptureTable::new();
    let mut first = captures.capture(&mut io, file, device, 0x80).unwrap();
    io.close(client, handle).unwrap();
    assert_eq!(count(&calls, major::IRP_MJ_CLEANUP), 1);
    assert_eq!(
        captures.capture(&mut io, file, device, 0x80).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
    let mut retained = captures
        .capture_owned(&mut io, file, device, first.granted_access())
        .unwrap();
    assert_eq!(retained.snapshot(), first.snapshot());
    assert_eq!(io.file_reference_count(file), 2);
    captures.retire(&mut first).unwrap();
    captures.release_retired(&mut io, first.identity()).unwrap();
    io.pump();
    assert!(io.file(file).is_some());
    assert_eq!(io.file_reference_count(file), 1);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    captures.retire(&mut retained).unwrap();
    captures
        .release_retired(&mut io, retained.identity())
        .unwrap();
    assert!(captures.is_empty());
    assert_eq!(io.file_reference_count(file), 0);
    assert!(
        io.file(file).is_some(),
        "pointer retirement queues rather than enters CLOSE"
    );
    assert_eq!(
        captures
            .capture_owned(&mut io, file, device, 0x80)
            .unwrap_err(),
        NtStatus::FILE_CLOSED
    );
    io.pump();
    assert!(io.file(file).is_none());
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn retained_pointer_does_not_bypass_irp_state_or_identity_barriers() {
    use crate::{FileState, InformationParameters, IoParameters};

    let (mut io, client, handle, file, device, calls) = opened();
    let driver = io.device(device).unwrap().driver_id;
    let dispatch = io
        .driver(driver)
        .unwrap()
        .dispatch
        .get(major::IRP_MJ_CREATE);
    io.driver_mut(driver)
        .unwrap()
        .dispatch
        .set(major::IRP_MJ_QUERY_INFORMATION, dispatch);
    let other_device = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let other_client = io.register_client();
    let mut captures = FileIoCaptureTable::new();
    let mut capture = captures.capture(&mut io, file, device, 0x80).unwrap();
    io.close(client, handle).unwrap();
    assert_eq!(io.file(file).unwrap().state, FileState::ClosePending);
    let before = calls.borrow().len();

    // Exercise admission barriers independently; the composed transaction test uses real
    // lifecycle transitions for the valid post-CLEANUP path.
    for (state, entered_close, request_client, request_device, request_file) in [
        (FileState::Open, true, client, device, file),
        (FileState::ClosePending, true, client, device, file),
        (FileState::Allocated, false, client, device, file),
        (FileState::CreateIrpDispatched, false, client, device, file),
        (FileState::Closed, false, client, device, file),
        (FileState::ClosePending, false, other_client, device, file),
        (FileState::ClosePending, false, client, other_device, file),
        (
            FileState::ClosePending,
            false,
            client,
            device,
            FileId(u64::MAX),
        ),
    ] {
        let body = io.file_mut(file).unwrap();
        body.state = state;
        body.close_dispatched = entered_close;
        let mut output = [0; 40];
        assert!(
            io.build_and_dispatch_external_to_device(
                request_client,
                request_device,
                Some(request_file),
                0,
                20,
                major::IRP_MJ_QUERY_INFORMATION,
                IoParameters::QueryInformation(InformationParameters {
                    info_class: 4,
                    length: 40
                }),
                0,
                40,
                &mut output,
            )
            .is_err(),
            "state={state:?} entered_close={entered_close}"
        );
        assert_eq!(calls.borrow().len(), before);
        assert_eq!(io.file_reference_count(file), 1);
        assert_eq!(io.file(file).unwrap().outstanding_irp_refs, 0);
        assert_eq!(output, [0; 40]);
    }
    let body = io.file_mut(file).unwrap();
    body.state = FileState::ClosePending;
    body.close_dispatched = false;
    captures.retire(&mut capture).unwrap();
    assert_eq!(captures.redrive(&mut io, usize::MAX).released, 1);
    io.pump();
    assert!(io.file(file).is_none());
    assert!(captures.is_empty());
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 1);
}

#[test]
fn capture_owned_refuses_entered_close_even_while_body_is_addressable() {
    let (mut io, client, handle, file, device, calls) = opened();
    let mut captures = FileIoCaptureTable::new();
    let mut retained = captures.capture(&mut io, file, device, 0x80).unwrap();
    // Model the terminal entry barrier independently of ordinary lifecycle scheduling.
    io.file_mut(file).unwrap().close_dispatched = true;
    assert_eq!(
        captures
            .capture_owned(&mut io, file, device, 0x80)
            .unwrap_err(),
        NtStatus::FILE_CLOSED
    );
    assert_eq!(io.file_reference_count(file), 1);
    assert_eq!(count(&calls, major::IRP_MJ_CLOSE), 0);
    io.file_mut(file).unwrap().close_dispatched = false;
    captures.retire(&mut retained).unwrap();
    captures
        .release_retired(&mut io, retained.identity())
        .unwrap();
    io.close(client, handle).unwrap();
    assert!(io.file(file).is_none());
}

#[test]
fn capture_owned_wrong_route_and_exhaustion_do_not_consume_existing_owner() {
    let (mut io, _, _, file, device, _) = opened();
    let mut captures = FileIoCaptureTable::new();
    let mut retained = captures.capture(&mut io, file, device, 0x80).unwrap();
    for wrong_device in [
        DeviceId::NULL,
        DeviceId::new(device.generation(), device.slot() + 1),
    ] {
        assert_eq!(
            captures
                .capture_owned(&mut io, file, wrong_device, 0x80)
                .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(io.file_reference_count(file), 1);
    }
    captures.next_generation = 0;
    assert_eq!(
        captures
            .capture_owned(&mut io, file, device, 0x80)
            .unwrap_err(),
        NtStatus::INSUFFICIENT_RESOURCES
    );
    assert_eq!(io.file_reference_count(file), 1);
    assert!(retained.is_held());
    captures.retire(&mut retained).unwrap();
    captures
        .release_retired(&mut io, retained.identity())
        .unwrap();
    assert!(captures.is_empty());
}
