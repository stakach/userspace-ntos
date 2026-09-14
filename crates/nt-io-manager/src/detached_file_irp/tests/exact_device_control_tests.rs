use super::*;

fn device(f: &mut Fixture, path: &str) -> (DriverId, DeviceId) {
    let mut majors = MajorFunctionTable::new();
    majors.set_all(DispatchTarget::DriverPeer(DriverPeerId(0)));
    let driver =
        f.io.create_driver_peer_with_major_table(
            &NtPath::parse_str(path).unwrap(),
            Box::new(MockDriverBackend::new()),
            majors,
        )
        .unwrap();
    let device =
        f.io.create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    (driver, device)
}

fn stack_fixture() -> (Fixture, DeviceId, DriverId, DeviceId) {
    let mut f = fixture();
    let (_, lower) = device(&mut f, r"\Driver\ExactLower");
    let (upper_driver, upper) = device(&mut f, r"\Driver\ExactUpper");
    f.io.attach_device_to_stack(f.device, lower).unwrap();
    f.io.attach_device_to_stack(upper, f.device).unwrap();
    (f, lower, upper_driver, upper)
}

fn request(f: &Fixture, method: u32, internal: bool) -> ExternalFileIrpRequest {
    let control = crate::DeviceControlParameters {
        ioctl_code: 0x0022_0000 | method,
        input_len: 4,
        output_len: 4,
    };
    ExternalFileIrpRequest {
        file_id: None,
        user_data: 0,
        major: if internal {
            major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        } else {
            major::IRP_MJ_DEVICE_CONTROL
        },
        parameters: if internal {
            IoParameters::InternalDeviceControl(control)
        } else {
            IoParameters::DeviceControl(control)
        },
        ..read(f)
    }
}

fn control_buffers() -> ExternalFileIrpBuffers {
    ExternalFileIrpBuffers::new(vec![1, 2, 3, 4], vec![9; 4])
}

#[test]
fn exact_middle_control_skips_upper_but_ordinary_preparation_keeps_top_routing() {
    let (mut f, lower, upper_driver, upper) = stack_fixture();
    for internal in [false, true] {
        let prepared =
            f.io.prepare_external_device_control_irp_owned_at_device(
                request(&f, 0, internal),
                control_buffers(),
            )
            .unwrap();
        assert_eq!(prepared.route().driver_id(), f.driver);
        assert_eq!(prepared.route().device_id(), f.device);
        let record = f.io.irp(prepared.irp_id()).unwrap();
        assert_eq!(record.file_id, None);
        assert_eq!(record.origin_device_id, f.device);
        assert_eq!(
            record
                .stack
                .iter()
                .map(|entry| entry.device_id)
                .collect::<Vec<_>>(),
            vec![f.device, lower]
        );
        f.io.discard_prepared_external_file_irp(prepared).unwrap();
    }
    let prepared =
        f.io.prepare_external_file_irp_owned(request(&f, 0, false), control_buffers())
            .unwrap();
    assert_eq!(prepared.route().driver_id(), upper_driver);
    assert_eq!(prepared.route().device_id(), upper);
    assert_eq!(
        f.io.irp(prepared.irp_id())
            .unwrap()
            .stack
            .iter()
            .map(|entry| entry.device_id)
            .collect::<Vec<_>>(),
        vec![upper, f.device, lower]
    );
    f.io.discard_prepared_external_file_irp(prepared).unwrap();
    assert!(f.trace.borrow().calls.is_empty());
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn exact_control_rejects_file_and_noncontrol_admission_before_retaining_irp() {
    let mut f = fixture();
    for case in 0..7 {
        let mut request = request(&f, 0, false);
        let mut buffers = control_buffers();
        match case {
            0 => request.file_id = Some(f.file),
            1 => request.major = major::IRP_MJ_FILE_SYSTEM_CONTROL,
            2 => request.major = major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            3 => request = create(&f, f.file),
            4 => {
                request.major = major::IRP_MJ_FLUSH_BUFFERS;
                request.parameters = IoParameters::FlushBuffers;
            }
            5 => buffers = ExternalFileIrpBuffers::new(vec![1; 3], vec![9; 4]),
            6 => request.initial_information = 1,
            _ => unreachable!(),
        }
        assert_eq!(
            f.io.prepare_external_device_control_irp_owned_at_device(request, buffers)
                .err(),
            Some(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(f.io.irp_count(), 0);
        assert_eq!(f.io.file_count(), 1);
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    }
    let (_, stale) = device(&mut f, r"\Driver\ExactStale");
    f.io.destroy_device(stale).unwrap();
    let mut request = request(&f, 0, false);
    request.device_id = stale;
    assert_eq!(
        f.io.prepare_external_device_control_irp_owned_at_device(request, control_buffers())
            .err(),
        Some(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn pending_exact_controls_retain_topology_until_method_aware_copy_and_strict_ack() {
    for method in 0..4 {
        for status in [
            NtStatus::SUCCESS,
            NtStatus(0x8000_0005u32 as i32),
            NtStatus(0x8000_0016u32 as i32),
            NtStatus::INVALID_PARAMETER,
        ] {
            let (mut f, lower, _, _) = stack_fixture();
            let prepared =
                f.io.prepare_external_device_control_irp_owned_at_device(
                    request(&f, method, false),
                    control_buffers(),
                )
                .unwrap();
            let id = prepared.irp_id();
            assert_eq!(
                f.io.detach_device_from_stack(f.device),
                Err(NtStatus::DEVICE_BUSY)
            );
            let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
            let owner = match f
                .io
                .finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
                .unwrap()
            {
                ExternalFileIrpResult::Pending(owner) => owner,
                other => panic!("unexpected {other:?}"),
            };
            f.trace.borrow_mut().ready.push(DriverCompletion {
                irp_id: id,
                status,
                information: 2,
                file_context: None,
            });
            f.io.pump();
            assert_eq!(
                f.io.acknowledge_completed_irp(id),
                Err(NtStatus::DELETE_PENDING)
            );
            let completion =
                f.io.prepare_external_file_irp_completion_with_capture(
                    owner,
                    ExternalFileIrpOutputCapture::DeviceControl,
                )
                .unwrap();
            let ack = capture_and_ack(&mut f, completion);
            assert_eq!(
                f.io.detach_device_from_stack(f.device),
                Err(NtStatus::DEVICE_BUSY)
            );
            let (_, output) =
                f.io.finish_external_file_irp_completion(
                    ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
                )
                .unwrap();
            let expected = if method != 0 {
                vec![5, 6, 7, 8]
            } else if status.raw() as u32 >> 30 == 3 || status.raw() as u32 == 0x8000_0016 {
                vec![9; 4]
            } else {
                vec![5, 6, 9, 9]
            };
            assert_eq!(output.output(), expected);
            assert!(f.io.irp(id).is_none());
            assert_eq!(f.io.file_count(), 1);
            assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
            assert_eq!(f.io.detach_device_from_stack(f.device), Ok(lower));
        }
    }
}

fn prepare_policy_owner(
    f: &mut Fixture,
    policy: ExternalFileIrpDispatchPolicy,
    method: u32,
    seed: u8,
) -> RetainedExternalFileIrp {
    let request = request(f, method, false);
    let prepared = policy
        .prepare(
            &mut f.io,
            request,
            ExternalFileIrpBuffers::new(vec![1, 2, 3, 4], vec![seed; 4]),
        )
        .unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    match f
        .io
        .finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
        .unwrap()
    {
        ExternalFileIrpResult::Pending(owner) => owner,
        other => panic!("expected retained policy owner, got {other:?}"),
    }
}

fn publish_policy_completion(
    f: &mut Fixture,
    owner: &RetainedExternalFileIrp,
    status: NtStatus,
    information: u64,
) {
    assert!(f.io.publish_driver_completion(
        owner.route().driver_id(),
        DriverCompletion {
            irp_id: owner.irp_id(),
            status,
            information,
            file_context: None,
        }
    ));
}

#[test]
fn explicit_policy_prepares_same_request_with_distinct_route_and_completion_capture() {
    let (mut f, _, upper_driver, upper) = stack_fixture();
    for policy in [
        ExternalFileIrpDispatchPolicy::File,
        ExternalFileIrpDispatchPolicy::DeviceControlAtDevice,
    ] {
        let owner = prepare_policy_owner(&mut f, policy, 3, 9);
        let expected_route = match policy {
            ExternalFileIrpDispatchPolicy::File => (upper_driver, upper),
            ExternalFileIrpDispatchPolicy::DeviceControlAtDevice => (f.driver, f.device),
        };
        assert_eq!(
            (owner.route().driver_id(), owner.route().device_id()),
            expected_route
        );
        assert_eq!(owner.projection().file_id, None);
        publish_policy_completion(&mut f, &owner, NtStatus::SUCCESS, 1);
        let completion =
            f.io.prepare_external_file_irp_completion_with_capture(owner, policy.output_capture())
                .unwrap();
        let mut copy =
            f.io.begin_external_file_irp_copy(completion, usize::MAX)
                .unwrap();
        let expected_len = if policy == ExternalFileIrpDispatchPolicy::File {
            1
        } else {
            4
        };
        assert_eq!(copy.requested_len(), expected_len);
        copy.staging_mut()
            .copy_from_slice(&[5, 6, 9, 9][..expected_len]);
        let completion =
            f.io.finish_external_file_irp_copy(copy.returned(ExternalFileIrpCopyOutcome::Copied {
                bytes: expected_len,
            }))
            .unwrap();
        let ack =
            f.io.begin_external_file_irp_acknowledgement(completion)
                .unwrap();
        let (_, output) =
            f.io.finish_external_file_irp_completion(
                ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
            )
            .unwrap();
        assert_eq!(
            output.output(),
            if expected_len == 1 {
                &[5, 9, 9, 9]
            } else {
                &[5, 6, 9, 9]
            }
        );
    }
    assert_eq!(f.io.irp_count(), 0);
    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
    assert!(f.trace.borrow().calls.is_empty());
}

#[test]
fn concurrent_policy_owners_complete_out_of_order_and_keep_capture_through_cancel_copy_and_ack_retries(
) {
    for method in 0..4 {
        for (status, information) in [
            (NtStatus(0x8000_0005u32 as i32), 2),
            (NtStatus::INVALID_PARAMETER, 2),
            (NtStatus::INVALID_PARAMETER, 0),
            (NtStatus::SUCCESS, 0),
        ] {
            let (mut f, _, _, upper) = stack_fixture();
            let file_policy = ExternalFileIrpDispatchPolicy::File;
            let control_policy = ExternalFileIrpDispatchPolicy::DeviceControlAtDevice;
            let file_owner = prepare_policy_owner(&mut f, file_policy, method, 0x11);
            let control_owner = prepare_policy_owner(&mut f, control_policy, method, 0x99);
            let file_id = file_owner.irp_id();
            let control_id = control_owner.irp_id();
            assert_ne!(file_id, control_id);
            assert_eq!(file_owner.route().device_id(), upper);
            assert_eq!(control_owner.route().device_id(), f.device);
            assert_eq!(f.io.irp_count(), 2);

            f.io.cancel(f.client, control_id).unwrap();
            let cancel = f.io.begin_external_file_irp_cancel(control_owner).unwrap();
            let (control_owner, outcome) =
                f.io.finish_external_file_irp_cancel(
                    cancel.returned(ExternalFileIrpCancelOutcome::Accepted),
                )
                .unwrap()
                .into_parts();
            assert_eq!(outcome, ExternalFileIrpCancelOutcome::Accepted);
            assert_eq!(
                f.io.detached_file_irp_intent(f.client, control_id)
                    .unwrap()
                    .cancel,
                ExternalFileIrpCancelPhase::Accepted
            );
            assert_eq!(
                control_policy.output_capture(),
                ExternalFileIrpOutputCapture::DeviceControl
            );
            publish_policy_completion(&mut f, &control_owner, status, information);
            let control_completion =
                f.io.prepare_external_file_irp_completion_with_capture(
                    control_owner,
                    control_policy.output_capture(),
                )
                .unwrap();
            let control_len = if method != 0 {
                4
            } else if status.raw() as u32 >> 30 == 3 {
                0
            } else {
                information as usize
            };
            assert_eq!(control_completion.capture_complete(), control_len == 0);
            // Retain the no-copy owner too while the older File-policy request completes.
            let (mut control_copy, mut no_copy) = if control_len == 0 {
                (None, Some(control_completion))
            } else {
                (
                    Some(
                        f.io.begin_external_file_irp_copy(control_completion, usize::MAX)
                            .unwrap(),
                    ),
                    None,
                )
            };

            publish_policy_completion(&mut f, &file_owner, status, information);
            let file_completion =
                f.io.prepare_external_file_irp_completion_with_capture(
                    file_owner,
                    file_policy.output_capture(),
                )
                .unwrap();
            let file_completion = if information == 0 {
                file_completion
            } else {
                let mut copy =
                    f.io.begin_external_file_irp_copy(file_completion, usize::MAX)
                        .unwrap();
                assert_eq!(copy.requested_len(), information as usize);
                copy.staging_mut()
                    .copy_from_slice(&[0x21, 0x22][..information as usize]);
                f.io.finish_external_file_irp_copy(copy.returned(
                    ExternalFileIrpCopyOutcome::Copied {
                        bytes: information as usize,
                    },
                ))
                .unwrap()
            };
            let ack =
                f.io.begin_external_file_irp_acknowledgement(file_completion)
                    .unwrap();
            let (_, file_output) =
                f.io.finish_external_file_irp_completion(
                    ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
                )
                .unwrap();
            assert_eq!(
                file_output.output(),
                if information == 0 {
                    &[0x11; 4]
                } else {
                    &[0x21, 0x22, 0x11, 0x11]
                }
            );
            assert!(f.io.irp(file_id).is_none());
            assert!(f.io.irp(control_id).is_some());

            let control_completion = if let Some(mut copy) = control_copy.take() {
                assert_eq!(copy.requested_len(), control_len);
                copy.staging_mut().fill(0xee);
                let rejected =
                    f.io.finish_external_file_irp_copy(copy.returned(
                        ExternalFileIrpCopyOutcome::Rejected {
                            status: NtStatus::UNSUCCESSFUL,
                        },
                    ))
                    .unwrap_err();
                assert_eq!(rejected.status(), NtStatus::UNSUCCESSFUL);
                let mut copy = rejected.into_owner().retry();
                assert_eq!(copy.irp_id(), control_id);
                assert_eq!(copy.route().device_id(), f.device);
                copy.staging_mut()
                    .copy_from_slice(&[0xa1, 0xa2, 0x99, 0x99][..control_len]);
                f.io.finish_external_file_irp_copy(
                    copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: control_len }),
                )
                .unwrap()
            } else {
                no_copy.take().unwrap()
            };
            let ack =
                f.io.begin_external_file_irp_acknowledgement(control_completion)
                    .unwrap();
            assert_eq!(ack.completion().status, status);
            assert_eq!(ack.completion().information, information);
            let rejected =
                f.io.finish_external_file_irp_completion(ack.acknowledged(
                    ExternalFileIrpAcknowledgement::Rejected {
                        status: NtStatus::UNSUCCESSFUL,
                    },
                ))
                .unwrap_err();
            assert_eq!(rejected.status(), NtStatus::UNSUCCESSFUL);
            let ack = rejected.into_owner().retry().unwrap();
            assert_eq!(ack.irp_id(), control_id);
            let (_, output) =
                f.io.finish_external_file_irp_completion(
                    ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
                )
                .unwrap();
            assert_eq!(
                output.output(),
                if control_len == 0 {
                    &[0x99; 4]
                } else {
                    &[0xa1, 0xa2, 0x99, 0x99]
                }
            );
            assert_eq!(f.io.irp_count(), 0);
            assert_eq!(f.io.file_count(), 1);
            assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
            assert!(f.trace.borrow().calls.is_empty());
            assert!(f.trace.borrow().cancellations.is_empty());
        }
    }
}

#[test]
fn nonbuffered_seed_and_retained_output_preserve_untouched_bytes_through_owned_capture() {
    // Compose production wire/capture policies with a modeled partial native write. This does not
    // execute native IPC; the prepared owner supplies the actual captured caller-output seed.
    for internal in [false, true] {
        for method in 1..=3 {
            for status in [NtStatus::SUCCESS, NtStatus::INVALID_PARAMETER] {
                for information in [0, 1] {
                    let (mut f, _, _, _) = stack_fixture();
                    let policy = ExternalFileIrpDispatchPolicy::DeviceControlAtDevice;
                    let request = request(&f, method, internal);
                    let request_major = request.major;
                    let ioctl_code = 0x0022_0000 | method;
                    let prepared = policy
                        .prepare(
                            &mut f.io,
                            request,
                            ExternalFileIrpBuffers::new(
                                vec![1, 2, 3, 4],
                                vec![0xa1, 0xb2, 0xc3, 0xd4],
                            ),
                        )
                        .unwrap();
                    assert_eq!(prepared.route().device_id(), f.device);
                    let mut native_output = [0; 4];
                    assert!(nt_io_abi::initial_output_required(
                        request_major,
                        ioctl_code,
                        4
                    ));
                    if nt_io_abi::initial_output_required(request_major, ioctl_code, 4) {
                        native_output.copy_from_slice(prepared.buffers().output());
                    }
                    native_output[..2].copy_from_slice(&[0x51, 0x52]);
                    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
                    let owner = match f
                        .io
                        .finish_external_file_irp(
                            invocation.returned(ExternalFileIrpOutcome::Pending),
                        )
                        .unwrap()
                    {
                        ExternalFileIrpResult::Pending(owner) => owner,
                        other => panic!("expected retained seeded control, got {other:?}"),
                    };
                    let retained_length = crate::retained_control_output_transfer_len(
                        request_major,
                        method as u8,
                        information,
                        native_output.len() as u64,
                    ) as usize;
                    assert_eq!(retained_length, 4);
                    let retained_source = &native_output[..retained_length];
                    publish_policy_completion(&mut f, &owner, status, information);
                    let completion =
                        f.io.prepare_external_file_irp_completion_with_capture(
                            owner,
                            policy.output_capture(),
                        )
                        .unwrap();
                    let mut copy =
                        f.io.begin_external_file_irp_copy(completion, usize::MAX)
                            .unwrap();
                    assert_eq!(copy.requested_len(), retained_length);
                    copy.staging_mut().copy_from_slice(retained_source);
                    let completion =
                        f.io.finish_external_file_irp_copy(copy.returned(
                            ExternalFileIrpCopyOutcome::Copied {
                                bytes: retained_length,
                            },
                        ))
                        .unwrap();
                    let ack =
                        f.io.begin_external_file_irp_acknowledgement(completion)
                            .unwrap();
                    assert_eq!(ack.completion().status, status);
                    assert_eq!(ack.completion().information, information);
                    let (_, output) =
                        f.io.finish_external_file_irp_completion(
                            ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
                        )
                        .unwrap();
                    assert_eq!(output.output(), &[0x51, 0x52, 0xc3, 0xd4]);
                    assert_eq!(f.io.irp_count(), 0);
                    assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
                }
            }
        }
    }
}
