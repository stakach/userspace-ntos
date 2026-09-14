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
