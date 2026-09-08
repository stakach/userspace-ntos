use super::*;
use crate::{
    CreateOptions, CreateParameters, DeviceCharacteristics, DeviceFlags, DeviceType,
    DispatchContext, DispatchOutcome, DispatchTarget, DriverCompletion, DriverDispatchBackend,
    MajorFunctionTable, MockDriverBackend, MockObjectPort, ReadWriteParameters, ShareAccess,
};
use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use nt_types::{AccessMask, HandleValue, NtPath, UnicodeString};

mod operations_tests;

#[derive(Default)]
struct Trace {
    calls: Vec<u8>,
    acknowledgements: Vec<IrpId>,
    ready: Vec<DriverCompletion>,
    cancellations: Vec<IrpId>,
    copies: Vec<IrpId>,
}
struct Backend {
    trace: Rc<RefCell<Trace>>,
    inner: MockDriverBackend,
}
impl DriverDispatchBackend for Backend {
    fn cancel_irp(&mut self, id: IrpId) -> Result<(), NtStatus> {
        self.trace.borrow_mut().cancellations.push(id);
        self.inner.cancel_irp(id)
    }
    fn copy_completion_output(
        &mut self,
        id: IrpId,
        _offset: u64,
        _output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        self.trace.borrow_mut().copies.push(id);
        Err(NtStatus::UNSUCCESSFUL)
    }
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        self.trace.borrow_mut().calls.push(irp.major);
        self.inner.dispatch_irp(ctx, irp)
    }
    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.trace.borrow_mut().ready.pop()
    }
    fn acknowledge_completion(&mut self, id: IrpId) -> Result<(), NtStatus> {
        self.trace.borrow_mut().acknowledgements.push(id);
        Ok(())
    }
}
struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    device: DeviceId,
    driver: DriverId,
    handle: HandleValue,
    file: FileId,
    trace: Rc<RefCell<Trace>>,
}
fn fixture() -> Fixture {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let trace = Rc::new(RefCell::new(Trace::default()));
    let mut majors = MajorFunctionTable::new();
    majors.set_all(DispatchTarget::DriverPeer(DriverPeerId(0)));
    let driver = io
        .create_driver_peer_with_major_table(
            &NtPath::parse_str("\\Driver\\Detached").unwrap(),
            Box::new(Backend {
                trace: trace.clone(),
                inner: MockDriverBackend::new(),
            }),
            majors,
        )
        .unwrap();
    let path = NtPath::parse_str("\\Device\\Detached").unwrap();
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
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
            ShareAccess::empty(),
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let (file, _) = io
        .reference_open_file(client, handle, AccessMask::empty())
        .unwrap();
    trace.borrow_mut().calls.clear();
    Fixture {
        io,
        client,
        device,
        driver,
        handle,
        file,
        trace,
    }
}
fn read(f: &Fixture) -> ExternalFileIrpRequest {
    ExternalFileIrpRequest {
        client: f.client,
        device_id: f.device,
        file_id: Some(f.file),
        user_data: 99,
        requestor_tid: 42,
        major: major::IRP_MJ_READ,
        parameters: IoParameters::Read(ReadWriteParameters {
            length: 4,
            ..Default::default()
        }),
        stack_flags: StackFlags::empty(),
    }
}
fn buffers() -> ExternalFileIrpBuffers {
    ExternalFileIrpBuffers::new(vec![], vec![7; 4])
}
fn capture_and_ack(
    f: &mut Fixture,
    completion: ExternalFileIrpCompletionInvocation,
) -> ExternalFileIrpAckInvocation {
    let completion = if completion.capture_complete() {
        completion
    } else {
        let mut copy =
            f.io.begin_external_file_irp_copy(completion, usize::MAX)
                .unwrap();
        let length = copy.requested_len();
        copy.staging_mut().copy_from_slice(&[5, 6, 7, 8][..length]);
        f.io.finish_external_file_irp_copy(
            copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: length }),
        )
        .unwrap()
    };
    f.io.begin_external_file_irp_acknowledgement(completion)
        .unwrap()
}
fn create_file(f: &mut Fixture, related: bool) -> FileId {
    if related {
        f.io.allocate_external_relative_file(
            f.client,
            f.file,
            AccessMask::GENERIC_READ,
            ShareAccess::empty(),
            CreateOptions::empty(),
            UnicodeString::from_str("child"),
        )
        .unwrap()
    } else {
        f.io.allocate_external_file(
            f.client,
            f.device,
            AccessMask::GENERIC_READ,
            ShareAccess::empty(),
            CreateOptions::empty(),
            UnicodeString::from_str("child"),
        )
        .unwrap()
    }
}
fn create(f: &Fixture, file: FileId) -> ExternalFileIrpRequest {
    ExternalFileIrpRequest {
        client: f.client,
        device_id: f.device,
        file_id: Some(file),
        user_data: 99,
        requestor_tid: 42,
        major: major::IRP_MJ_CREATE,
        parameters: IoParameters::Create(CreateParameters::default()),
        stack_flags: StackFlags::empty(),
    }
}
fn returned(invocation: ExternalFileIrpInvocation) -> ExternalFileIrpReturn {
    invocation.returned(ExternalFileIrpOutcome::Returned {
        status: NtStatus::SUCCESS,
        information: 4,
        file_context: None,
    })
}
fn terminal(f: &mut Fixture, invocation: ExternalFileIrpInvocation) -> ExternalFileIrpTerminal {
    match f.io.finish_external_file_irp(returned(invocation)).unwrap() {
        ExternalFileIrpResult::Returned(terminal) => terminal,
        other => panic!("unexpected {other:?}"),
    }
}
fn pending(f: &mut Fixture, indeterminate: bool) -> RetainedExternalFileIrp {
    let prepared =
        f.io.prepare_external_file_irp_owned(read(f), buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let outcome = if indeterminate {
        ExternalFileIrpOutcome::Indeterminate {
            transport_status: NtStatus::UNSUCCESSFUL,
        }
    } else {
        ExternalFileIrpOutcome::Pending
    };
    match f
        .io
        .finish_external_file_irp(invocation.returned(outcome))
        .unwrap()
    {
        ExternalFileIrpResult::Pending(owner)
        | ExternalFileIrpResult::Indeterminate {
            retained: owner, ..
        } => owner,
        other => panic!("unexpected {other:?}"),
    }
}
fn complete(f: &mut Fixture, id: IrpId) {
    f.trace.borrow_mut().ready.push(DriverCompletion {
        irp_id: id,
        status: NtStatus::SUCCESS,
        information: 4,
        file_context: None,
    });
    f.io.pump();
}

#[test]
fn detached_execution_uses_no_backend_borrow_and_retains_output_until_retirement() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let id = prepared.irp_id();
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
    let mut invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    assert_eq!(invocation.route().driver_id(), f.driver);
    invocation
        .buffers_mut()
        .split()
        .1
        .copy_from_slice(&[1, 2, 3, 4]);
    let terminal = terminal(&mut f, invocation);
    assert!(f.io.free_irp(id).is_none());
    assert!(f.trace.borrow().calls.is_empty());
    let (receipt, output) = f.io.retire_external_file_irp_terminal(terminal).unwrap();
    assert_eq!(output.output(), &[1, 2, 3, 4]);
    assert!(!receipt.backend_acknowledged());
    assert!(f.io.accepts_external_file_irp_receipt(&receipt));
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
}

#[test]
fn foreign_manager_cannot_begin_discard_finish_or_retire_matching_numeric_irp() {
    let mut f = fixture();
    let mut foreign = fixture();
    let a =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let b = foreign
        .io
        .prepare_external_file_irp_owned(read(&foreign), buffers())
        .unwrap();
    assert_eq!(a.irp_id(), b.irp_id());
    let a = foreign
        .io
        .begin_prepared_external_file_irp(a)
        .unwrap_err()
        .into_owner();
    let a = foreign
        .io
        .discard_prepared_external_file_irp(a)
        .unwrap_err()
        .into_owner();
    let invocation = f.io.begin_prepared_external_file_irp(a).unwrap();
    let report = foreign
        .io
        .finish_external_file_irp(returned(invocation))
        .unwrap_err()
        .into_owner();
    let ExternalFileIrpResult::Returned(owner) = f.io.finish_external_file_irp(report).unwrap()
    else {
        panic!()
    };
    let owner = foreign
        .io
        .retire_external_file_irp_terminal(owner)
        .unwrap_err()
        .into_owner();
    f.io.retire_external_file_irp_terminal(owner).unwrap();
    foreign.io.discard_prepared_external_file_irp(b).unwrap();
}

#[test]
fn owner_generation_cannot_be_freed_or_peer_rebound_during_dispatch() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let id = prepared.irp_id();
    assert!(f.io.free_irp(id).is_none());
    assert!(f.io.driver_mut(f.driver).is_none());
    assert!(f.io.remove_driver(f.driver).is_none());
    let current = f.io.irp(id).unwrap().current_stack().unwrap().clone();
    assert!(f
        .io
        .irp_mut(id)
        .unwrap()
        .handoff_to_next_stack(f.driver, current)
        .is_err());
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    let next =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    assert_ne!(id, next.irp_id());
    f.io.discard_prepared_external_file_irp(next).unwrap();
}

#[test]
fn relative_create_discard_restores_relation_and_blocks_duplicate_preparation() {
    let mut f = fixture();
    let child = create_file(&mut f, true);
    let prepared =
        f.io.prepare_external_file_irp_owned(
            create(&f, child),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap();
    assert_eq!(f.io.file(child).unwrap().related_file, None);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
    assert!(f
        .io
        .prepare_external_file_irp_owned(
            create(&f, child),
            ExternalFileIrpBuffers::new(vec![], vec![])
        )
        .is_err());
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    assert_eq!(f.io.file(child).unwrap().related_file, Some(f.file));
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    let again =
        f.io.prepare_external_file_irp_owned(
            create(&f, child),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap();
    f.io.discard_prepared_external_file_irp(again).unwrap();
}

#[test]
fn abandoned_allocated_create_cannot_begin_after_release() {
    let mut f = fixture();
    let child = create_file(&mut f, false);
    let mut reference = f.io.retain_file_reference(child).unwrap();
    let prepared =
        f.io.prepare_external_file_irp_owned(
            create(&f, child),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap();
    f.io.release_external_file(f.client, child).unwrap();
    let prepared =
        f.io.begin_prepared_external_file_irp(prepared)
            .unwrap_err()
            .into_owner();
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    f.io.release_file_reference(&mut reference).unwrap();
}

#[test]
fn not_entered_is_retryable_without_second_irp_or_lost_buffers() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let id = prepared.irp_id();
    let pointer = prepared.buffers().output().as_ptr();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::NotEntered { prepared, .. } =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: NtStatus::DEVICE_NOT_CONNECTED,
        }))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(id, prepared.irp_id());
    assert_eq!(pointer, prepared.buffers().output().as_ptr());
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let owner = terminal(&mut f, invocation);
    f.io.retire_external_file_irp_terminal(owner).unwrap();
}

#[test]
fn ordinary_cleanup_can_precede_prepared_read_discard_and_close_is_rescheduled() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
    assert!(f.trace.borrow().calls.contains(&major::IRP_MJ_CLOSE));
}

#[test]
fn ordinary_cleanup_can_precede_synchronous_retirement() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    let terminal = terminal(&mut f, invocation);
    f.io.retire_external_file_irp_terminal(terminal).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
}

#[test]
fn pending_completion_requires_detached_ack_and_keeps_accepted_ack_on_wrong_manager() {
    let mut f = fixture();
    let mut foreign = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    complete(&mut f, id);
    assert_eq!(
        f.io.acknowledge_completed_irp(id).unwrap_err(),
        NtStatus::DELETE_PENDING
    );
    assert!(f.trace.borrow().acknowledgements.is_empty());
    let invocation = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let invocation = capture_and_ack(&mut f, invocation);
    let report = invocation.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged);
    let report = foreign
        .io
        .finish_external_file_irp_completion(report)
        .unwrap_err()
        .into_owner();
    let report = report.retry().unwrap_err();
    let (receipt, output) = f.io.finish_external_file_irp_completion(report).unwrap();
    assert!(receipt.backend_acknowledged());
    assert_eq!(output.output(), &[5, 6, 7, 8]);
    assert!(f.io.irp(id).is_none());
}

#[test]
fn rejected_ack_can_retry_but_unknown_ack_cannot_be_replayed() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    complete(&mut f, owner.irp_id());
    let invocation = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let invocation = capture_and_ack(&mut f, invocation);
    let report = invocation.acknowledged(ExternalFileIrpAcknowledgement::Rejected {
        status: NtStatus::DEVICE_BUSY,
    });
    let report =
        f.io.finish_external_file_irp_completion(report)
            .unwrap_err()
            .into_owner();
    let invocation = report.retry().unwrap();
    let report = invocation.acknowledged(ExternalFileIrpAcknowledgement::Indeterminate {
        transport_status: NtStatus::UNSUCCESSFUL,
    });
    let report =
        f.io.finish_external_file_irp_completion(report)
            .unwrap_err()
            .into_owner();
    assert!(report.retry().is_err());
}

#[test]
fn indeterminate_outer_return_retains_owner_and_accepts_real_late_completion() {
    let mut f = fixture();
    let owner = pending(&mut f, true);
    assert!(owner.is_indeterminate());
    assert_eq!(
        f.io.irp(owner.irp_id()).unwrap().state,
        IrpState::Indeterminate
    );
    complete(&mut f, owner.irp_id());
    let invocation = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let invocation = capture_and_ack(&mut f, invocation);
    f.io.finish_external_file_irp_completion(
        invocation.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}

#[test]
fn actual_reentrant_completion_is_not_replaced_by_outer_return() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    complete(&mut f, invocation.irp_id());
    let ExternalFileIrpResult::Pending(owner) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Returned {
            status: NtStatus::UNSUCCESSFUL,
            information: 0,
            file_context: None,
        }))
        .unwrap()
    else {
        panic!()
    };
    let invocation = f.io.prepare_external_file_irp_completion(owner).unwrap();
    assert_eq!(invocation.completion().status, NtStatus::SUCCESS);
    let invocation = capture_and_ack(&mut f, invocation);
    f.io.finish_external_file_irp_completion(
        invocation.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}

#[test]
fn changed_state_without_backend_completion_proof_is_not_pending_success() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let id = invocation.irp_id();
    f.io.irp_mut(id).unwrap().state = IrpState::Completed;
    let report =
        f.io.finish_external_file_irp(returned(invocation))
            .unwrap_err()
            .into_owner();
    assert!(f.io.free_irp(id).is_none());
    f.io.irp_mut(id).unwrap().state = IrpState::Dispatched;
    let ExternalFileIrpResult::Returned(terminal) = f.io.finish_external_file_irp(report).unwrap()
    else {
        panic!()
    };
    f.io.retire_external_file_irp_terminal(terminal).unwrap();
}

#[test]
fn strict_extent_and_lifecycle_rejections_happen_before_reference_acquisition() {
    let mut f = fixture();
    assert!(f
        .io
        .prepare_external_file_irp_owned(read(&f), ExternalFileIrpBuffers::new(vec![], vec![0; 3]))
        .is_err());
    assert!(f
        .io
        .prepare_external_file_irp_owned(read(&f), ExternalFileIrpBuffers::new(vec![1], vec![0; 4]))
        .is_err());
    for (major, parameters) in [
        (major::IRP_MJ_CLEANUP, IoParameters::Cleanup),
        (major::IRP_MJ_CLOSE, IoParameters::Close),
    ] {
        let mut request = read(&f);
        request.major = major;
        request.parameters = parameters;
        assert!(f
            .io
            .prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![], vec![]))
            .is_err());
    }
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert!(f.trace.borrow().calls.is_empty());
}

#[test]
fn fileless_device_control_is_admitted_but_fileless_create_is_not() {
    let mut f = fixture();
    let mut request = read(&f);
    request.file_id = None;
    request.major = major::IRP_MJ_DEVICE_CONTROL;
    request.parameters = IoParameters::DeviceControl(crate::DeviceControlParameters {
        ioctl_code: 0x222000,
        input_len: 2,
        output_len: 4,
    });
    let owner =
        f.io.prepare_external_file_irp_owned(
            request,
            ExternalFileIrpBuffers::new(vec![1, 2], vec![3; 4]),
        )
        .unwrap();
    assert_eq!(owner.buffers().input(), &[1, 2]);
    f.io.discard_prepared_external_file_irp(owner).unwrap();
    let mut request = create(&f, f.file);
    request.file_id = None;
    assert!(f
        .io
        .prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![], vec![]))
        .is_err());
}

#[test]
fn fsctl_preserves_independent_input_and_initial_output() {
    let mut f = fixture();
    for method in 0..4 {
        let mut request = read(&f);
        request.major = major::IRP_MJ_FILE_SYSTEM_CONTROL;
        request.parameters = IoParameters::DeviceControl(crate::DeviceControlParameters {
            ioctl_code: 0x119000 | method,
            input_len: 2,
            output_len: 3,
        });
        let prepared =
            f.io.prepare_external_file_irp_owned(
                request,
                ExternalFileIrpBuffers::new(vec![1, 2], vec![3, 4, 5]),
            )
            .unwrap();
        let mut invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
        let (input, output) = invocation.buffers_mut().split();
        assert_eq!(input, &[1, 2]);
        assert_eq!(output, &[3, 4, 5]);
        output[0] = 8;
        let terminal = terminal(&mut f, invocation);
        let (_, buffers) = f.io.retire_external_file_irp_terminal(terminal).unwrap();
        assert_eq!(buffers.input(), &[1, 2]);
        assert_eq!(buffers.output(), &[8, 4, 5]);
    }
}

#[test]
fn pending_transport_fault_cannot_fabricate_terminal_completion() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    f.io.fault_driver(f.driver);
    assert_eq!(f.io.irp(id).unwrap().state, IrpState::Indeterminate);
    assert!(f.io.completed_irp(id).is_none());
    assert!(f.io.free_irp(id).is_none());
    let owner =
        f.io.prepare_external_file_irp_completion(owner)
            .unwrap_err()
            .into_owner();
    complete(&mut f, id);
    let invocation = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let invocation = capture_and_ack(&mut f, invocation);
    f.io.finish_external_file_irp_completion(
        invocation.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}

#[test]
fn reentrant_transport_fault_keeps_outstanding_invocation_indeterminate() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let id = invocation.irp_id();
    f.io.fault_driver(f.driver);
    let ExternalFileIrpResult::Indeterminate { retained, .. } =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Indeterminate {
            transport_status: NtStatus::DEVICE_NOT_CONNECTED,
        }))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(retained.irp_id(), id);
    assert!(f.io.completed_irp(id).is_none());
    assert!(f.trace.borrow().acknowledgements.is_empty());
}

#[test]
fn faulted_prepared_route_is_rejected_before_entry_but_can_be_discarded() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    f.io.fault_driver(f.driver);
    let failure = f.io.begin_prepared_external_file_irp(prepared).unwrap_err();
    assert_eq!(failure.status(), NtStatus::DEVICE_NOT_CONNECTED);
    f.io.discard_prepared_external_file_irp(failure.into_owner())
        .unwrap();
}

#[test]
fn async_wrong_file_reference_set_cannot_consume_original_owner() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    complete(&mut f, id);
    let original = f.io.irp(id).unwrap().file_id;
    f.io.irp_mut(id).unwrap().file_id = None;
    let owner =
        f.io.prepare_external_file_irp_completion(owner)
            .unwrap_err()
            .into_owner();
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
    f.io.irp_mut(id).unwrap().file_id = original;
    let invocation = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let invocation = capture_and_ack(&mut f, invocation);
    f.io.finish_external_file_irp_completion(
        invocation.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}

#[test]
fn relative_create_not_entered_discard_restores_parent_once() {
    let mut f = fixture();
    let child = create_file(&mut f, true);
    let prepared =
        f.io.prepare_external_file_irp_owned(
            create(&f, child),
            ExternalFileIrpBuffers::new(vec![], vec![]),
        )
        .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::NotEntered { prepared, .. } =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::NotEntered {
            status: NtStatus::DEVICE_BUSY,
        }))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(f.io.file(child).unwrap().state, FileState::Allocated);
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    assert_eq!(f.io.file(child).unwrap().related_file, Some(f.file));
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
}

#[test]
fn immutable_request_mutations_reject_return_without_releasing_owner() {
    for mutation in 0..4 {
        let mut f = fixture();
        let prepared =
            f.io.prepare_external_file_irp_owned(read(&f), buffers())
                .unwrap();
        let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
        let id = invocation.irp_id();
        let original = invocation.projection().clone();
        let record = f.io.irp_mut(id).unwrap();
        match mutation {
            0 => record.buffer.as_mut().unwrap().output_len += 1,
            1 => record.stack[record.current_location as usize].major = major::IRP_MJ_WRITE,
            2 => record.stack[record.current_location as usize].flags = StackFlags::CASE_SENSITIVE,
            _ => record.user_data ^= 1,
        }
        let report =
            f.io.finish_external_file_irp(returned(invocation))
                .unwrap_err()
                .into_owner();
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 1);
        assert!(f.io.free_irp(id).is_none());
        let record = f.io.irp_mut(id).unwrap();
        record.buffer = original.buffer;
        record.stack[record.current_location as usize].major = original.major;
        record.stack[record.current_location as usize].flags = original.flags;
        record.user_data = original.user_data;
        let ExternalFileIrpResult::Returned(terminal) =
            f.io.finish_external_file_irp(report).unwrap()
        else {
            panic!()
        };
        f.io.retire_external_file_irp_terminal(terminal).unwrap();
    }
}

#[test]
fn set_information_target_reference_survives_close_until_discard() {
    let mut f = fixture();
    f.io.file_mut(f.file).unwrap().desired_access |= AccessMask::DELETE;
    let path = NtPath::parse_str("\\Device\\Detached").unwrap();
    let target_handle =
        f.io.open(
            f.client,
            &path,
            AccessMask::empty(),
            ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
            CreateOptions::empty(),
            0,
        )
        .unwrap();
    let (target, _) =
        f.io.reference_open_file(f.client, target_handle, AccessMask::empty())
            .unwrap();
    let mut request = read(&f);
    request.major = major::IRP_MJ_SET_INFORMATION;
    request.parameters = IoParameters::SetInformation(crate::SetInformationParameters {
        info_class: 10,
        length: 2,
        target_file: Some(target),
        control: crate::SetInformationControl::ReplaceIfExists(false),
    });
    let prepared = f
        .io
        .prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![0; 2], vec![]))
        .unwrap();
    assert_eq!(f.io.file(target).unwrap().outstanding_irp_refs, 1);
    f.io.close(f.client, target_handle).unwrap();
    f.io.pump();
    assert_eq!(f.io.file(target).unwrap().state, FileState::ClosePending);
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    f.io.pump();
    assert!(f.io.file(target).is_none());
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
}
