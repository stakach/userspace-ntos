use super::*;

#[test]
fn owner_out_cancel_is_durable_selection_without_backend_entry() {
    let mut f = fixture();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let id = invocation.irp_id();
    assert!(f.io.cancel_if_pending(f.client, id).unwrap());
    assert_eq!(f.io.irp(id).unwrap().state, IrpState::Dispatched);
    assert_eq!(
        f.io.detached_file_irp_intent(f.client, id).unwrap().cancel,
        ExternalFileIrpCancelPhase::Queued
    );
    assert!(f.trace.borrow().cancellations.is_empty());
    let ExternalFileIrpResult::Pending(owner) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!()
    };
    assert_eq!(f.io.irp(id).unwrap().state, IrpState::CancelRequested);
    let cancel = f.io.begin_external_file_irp_cancel(owner).unwrap();
    assert!(f.io.cancel_if_pending(f.client, id).unwrap());
    let (owner, _) = f
        .io
        .finish_external_file_irp_cancel(cancel.returned(ExternalFileIrpCancelOutcome::Accepted))
        .unwrap()
        .into_parts();
    assert_eq!(
        f.io.detached_file_irp_intent(f.client, id).unwrap().cancel,
        ExternalFileIrpCancelPhase::Accepted
    );
    let owner =
        f.io.begin_external_file_irp_cancel(owner)
            .unwrap_err()
            .into_owner();
    complete(&mut f, id);
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    assert_eq!(completion.completion().status, NtStatus::SUCCESS);
}

#[test]
fn cancellation_wrong_client_and_prepared_cancel_are_failure_atomic() {
    let mut f = fixture();
    let wrong = f.io.register_client();
    let prepared =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let id = prepared.irp_id();
    assert_eq!(
        f.io.cancel_if_pending(wrong, id).unwrap_err(),
        NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        f.io.abandon_irp_delivery(wrong, id).unwrap_err(),
        NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        f.io.detached_file_irp_intent(f.client, id).unwrap(),
        ExternalFileIrpIntent::default()
    );
    assert!(f.io.cancel_if_pending(f.client, id).unwrap());
    let error = f.io.begin_prepared_external_file_irp(prepared).unwrap_err();
    assert_eq!(error.status(), NtStatus::CANCELLED);
    f.io.discard_prepared_external_file_irp(error.into_owner())
        .unwrap();
    assert!(f.io.irp(id).is_none());
    assert!(f.trace.borrow().cancellations.is_empty());
}

#[test]
fn exact_thread_cancel_selection_terminates_with_owner_out_and_indeterminate() {
    let mut f = fixture();
    let selected = pending(&mut f, true);
    let mut request = read(&f);
    request.requestor_tid = 99;
    let sibling =
        f.io.prepare_external_file_irp_owned(request, buffers())
            .unwrap();
    let selected_out =
        f.io.prepare_external_file_irp_owned(read(&f), buffers())
            .unwrap();
    let selected_out = f.io.begin_prepared_external_file_irp(selected_out).unwrap();
    let state = f.io.cancel_file_thread_io(f.client, f.file, 42).unwrap();
    assert_eq!(state.total, 2);
    assert_eq!(state.cancel_requested, 2);
    assert_eq!(
        f.io.cancel_file_thread_io(f.client, f.file, 42).unwrap(),
        state
    );
    assert_eq!(
        f.io.detached_file_irp_intent(f.client, sibling.irp_id())
            .unwrap()
            .cancel,
        ExternalFileIrpCancelPhase::None
    );
    assert!(f.io.cancel_if_pending(f.client, selected.irp_id()).unwrap());
    assert!(f
        .io
        .cancel_if_pending(f.client, selected_out.irp_id())
        .unwrap());
    assert!(f.trace.borrow().cancellations.is_empty());
}

#[test]
fn cancel_return_preserves_accepted_evidence_on_wrong_manager_and_completion_race() {
    let mut f = fixture();
    let mut other = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    f.io.cancel(f.client, id).unwrap();
    let invocation = f.io.begin_external_file_irp_cancel(owner).unwrap();
    complete(&mut f, id);
    let report = invocation.returned(ExternalFileIrpCancelOutcome::Accepted);
    let report = other
        .io
        .finish_external_file_irp_cancel(report)
        .unwrap_err()
        .into_owner();
    assert_eq!(report.outcome(), ExternalFileIrpCancelOutcome::Accepted);
    let (owner, _) =
        f.io.finish_external_file_irp_cancel(report)
            .unwrap()
            .into_parts();
    assert_eq!(f.io.completed_irp(id).unwrap().status, NtStatus::SUCCESS);
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let ack = capture_and_ack(&mut f, completion);
    f.io.finish_external_file_irp_completion(
        ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}

#[test]
fn cancel_retries_only_definite_nonacceptance() {
    for first in [
        ExternalFileIrpCancelOutcome::NotEntered {
            status: NtStatus::DEVICE_BUSY,
        },
        ExternalFileIrpCancelOutcome::Rejected {
            status: NtStatus::INVALID_PARAMETER,
        },
    ] {
        let mut f = fixture();
        let owner = pending(&mut f, false);
        let id = owner.irp_id();
        f.io.cancel(f.client, id).unwrap();
        let invocation = f.io.begin_external_file_irp_cancel(owner).unwrap();
        let (owner, result) =
            f.io.finish_external_file_irp_cancel(invocation.returned(first))
                .unwrap()
                .into_parts();
        assert_eq!(result, first);
        let invocation = f.io.begin_external_file_irp_cancel(owner).unwrap();
        let (owner, _) =
            f.io.finish_external_file_irp_cancel(invocation.returned(
                ExternalFileIrpCancelOutcome::Indeterminate {
                    transport_status: NtStatus::UNSUCCESSFUL,
                },
            ))
            .unwrap()
            .into_parts();
        assert_eq!(
            f.io.detached_file_irp_intent(f.client, id).unwrap().cancel,
            ExternalFileIrpCancelPhase::Indeterminate
        );
        let owner =
            f.io.begin_external_file_irp_cancel(owner)
                .unwrap_err()
                .into_owner();
        complete(&mut f, id);
        assert!(f.io.prepare_external_file_irp_completion(owner).is_ok());
    }
}

#[test]
fn partial_copy_wrong_manager_and_unknown_read_preserve_range_and_original_output() {
    let mut f = fixture();
    let mut other = fixture();
    let owner = pending(&mut f, false);
    complete(&mut f, owner.irp_id());
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let completion =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap_err()
            .into_owner();
    let mut copy = f.io.begin_external_file_irp_copy(completion, 2).unwrap();
    copy.staging_mut().copy_from_slice(&[1, 2]);
    let report = copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: 1 });
    let report =
        f.io.finish_external_file_irp_copy(report)
            .unwrap_err()
            .into_owner();
    let copy = report.retry();
    assert_eq!(copy.offset(), 0);
    let report = copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: 2 });
    let report = other
        .io
        .finish_external_file_irp_copy(report)
        .unwrap_err()
        .into_owner();
    let completion = f.io.finish_external_file_irp_copy(report).unwrap();
    assert_eq!(completion.buffers().output(), &[1, 2, 7, 7]);
    assert_eq!(completion.captured_len(), 2);
    let completion =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap_err()
            .into_owner();
    let mut copy = f.io.begin_external_file_irp_copy(completion, 64).unwrap();
    copy.staging_mut().copy_from_slice(&[3, 4]);
    let report = copy.returned(ExternalFileIrpCopyOutcome::Indeterminate {
        transport_status: NtStatus::UNSUCCESSFUL,
    });
    let report =
        f.io.finish_external_file_irp_copy(report)
            .unwrap_err()
            .into_owner();
    let copy = report.retry();
    assert_eq!(copy.offset(), 2);
    assert_eq!(copy.requested_len(), 2);
    let completion =
        f.io.finish_external_file_irp_copy(
            copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: 2 }),
        )
        .unwrap();
    assert_eq!(completion.buffers().output(), &[1, 2, 3, 4]);
    let ack =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap();
    let (_, buffers) =
        f.io.finish_external_file_irp_completion(
            ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
        )
        .unwrap();
    assert_eq!(buffers.output(), &[1, 2, 3, 4]);
}

#[test]
fn discarded_failed_copy_never_commits_staging_and_abandonment_allows_ack() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    complete(&mut f, id);
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let mut copy = f.io.begin_external_file_irp_copy(completion, 4).unwrap();
    copy.staging_mut().fill(0xff);
    f.io.abandon_irp_delivery(f.client, id).unwrap();
    let completion = copy
        .returned(ExternalFileIrpCopyOutcome::Copied { bytes: 9 })
        .into_completion();
    assert_eq!(completion.buffers().output(), &[7; 4]);
    assert_eq!(completion.captured_len(), 0);
    let ack =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap();
    f.io.finish_external_file_irp_completion(
        ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}

#[test]
fn abandonment_never_fabricates_completion_or_releases_file_before_real_ack() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    f.io.close(f.client, f.handle).unwrap();
    f.io.abandon_irp_delivery(f.client, id).unwrap();
    f.io.pump();
    assert!(f.io.completed_irp(id).is_none());
    assert!(f.io.file(f.file).is_some());
    assert!(!f.io.manager_owned_irps.contains(&id));
    let owner =
        f.io.prepare_external_file_irp_completion(owner)
            .unwrap_err()
            .into_owner();
    complete(&mut f, id);
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    assert_eq!(completion.completion().status, NtStatus::SUCCESS);
    let ack =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_some());
    f.io.finish_external_file_irp_completion(
        ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
}

#[test]
fn legacy_copy_cancel_retry_and_ack_cannot_bypass_detached_owner() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    let id = owner.irp_id();
    f.io.cancel(f.client, id).unwrap();
    f.io.cancel_dispatch_retries.push(id);
    f.io.pump();
    assert!(f.trace.borrow().cancellations.is_empty());
    assert!(!f.io.cancel_dispatch_retries.contains(&id));
    complete(&mut f, id);
    assert_eq!(
        f.io.copy_completed_irp_output(id, 0, &mut [0; 4])
            .unwrap_err(),
        NtStatus::DELETE_PENDING
    );
    assert_eq!(
        f.io.copy_completed_pnp_payload(id, 0, &mut [0; 4])
            .unwrap_err(),
        NtStatus::DELETE_PENDING
    );
    assert_eq!(
        f.io.copy_completed_buffered_device_control_payload(id, 0, &mut [0; 4])
            .unwrap_err(),
        NtStatus::DELETE_PENDING
    );
    assert_eq!(
        f.io.acknowledge_completed_irp(id).unwrap_err(),
        NtStatus::DELETE_PENDING
    );
    assert!(f.trace.borrow().copies.is_empty());
    assert!(f.trace.borrow().acknowledgements.is_empty());
    assert!(!f.io.cancel_if_pending(f.client, id).unwrap());
}

#[test]
fn zero_copy_budget_and_overreported_chunk_do_not_advance_owner() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    complete(&mut f, owner.irp_id());
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    let completion =
        f.io.begin_external_file_irp_copy(completion, 0)
            .unwrap_err()
            .into_owner();
    let copy = f.io.begin_external_file_irp_copy(completion, 4).unwrap();
    let completion =
        f.io.finish_external_file_irp_copy(
            copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: 5 }),
        )
        .unwrap_err()
        .into_owner()
        .into_completion();
    assert_eq!(completion.captured_len(), 0);
    assert_eq!(completion.buffers().output(), &[7; 4]);
}

#[test]
fn declared_buffered_control_capture_is_explicit_and_not_information_bounded() {
    let mut f = fixture();
    let request = ExternalFileIrpRequest {
        major: major::IRP_MJ_DEVICE_CONTROL,
        parameters: IoParameters::DeviceControl(crate::DeviceControlParameters {
            ioctl_code: 0x222000,
            input_len: 0,
            output_len: 4,
        }),
        ..read(&f)
    };
    let prepared =
        f.io.prepare_external_file_irp_owned(request, buffers())
            .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::Pending(owner) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!()
    };
    f.trace.borrow_mut().ready.push(DriverCompletion {
        irp_id: owner.irp_id(),
        status: NtStatus(0x8000_0005u32 as i32),
        information: 0,
        file_context: None,
    });
    f.io.pump();
    let completion =
        f.io.prepare_external_file_irp_completion_with_capture(
            owner,
            ExternalFileIrpOutputCapture::BufferedDeviceControlCapacity,
        )
        .unwrap();
    assert_eq!(completion.capture_len(), 4);
    let completion =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap_err()
            .into_owner();
    let ack = capture_and_ack(&mut f, completion);
    let (receipt, output) =
        f.io.finish_external_file_irp_completion(
            ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
        )
        .unwrap();
    assert_eq!(receipt.completion().information, 0);
    assert_eq!(receipt.completion().status, NtStatus(0x8000_0005u32 as i32));
    assert_eq!(output.output(), &[5, 6, 7, 8]);
}

#[test]
fn read_cannot_claim_buffered_control_capacity_and_write_information_is_not_output() {
    let mut f = fixture();
    let owner = pending(&mut f, false);
    complete(&mut f, owner.irp_id());
    let owner =
        f.io.prepare_external_file_irp_completion_with_capture(
            owner,
            ExternalFileIrpOutputCapture::BufferedDeviceControlCapacity,
        )
        .unwrap_err()
        .into_owner();
    assert!(f.io.prepare_external_file_irp_completion(owner).is_ok());

    let request = ExternalFileIrpRequest {
        major: major::IRP_MJ_WRITE,
        parameters: IoParameters::Write(ReadWriteParameters {
            length: 4,
            ..Default::default()
        }),
        ..read(&f)
    };
    let prepared = f
        .io
        .prepare_external_file_irp_owned(request, ExternalFileIrpBuffers::new(vec![1; 4], vec![]))
        .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::Pending(owner) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!()
    };
    complete(&mut f, owner.irp_id());
    let completion = f.io.prepare_external_file_irp_completion(owner).unwrap();
    assert_eq!(completion.completion().information, 4);
    assert_eq!(completion.capture_len(), 0);
    let ack =
        f.io.begin_external_file_irp_acknowledgement(completion)
            .unwrap();
    f.io.finish_external_file_irp_completion(
        ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
    )
    .unwrap();
}
