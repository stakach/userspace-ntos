use super::*;

const CLASSES: [u32; 4] = [8, 16, 17, 18];

fn encode(f: &Fixture, class: u32, output: &mut [u8]) -> Result<usize, NtStatus> {
    f.io.encode_owned_file_query_information(f.client, f.file, f.device, 0x1234, class, output)
}

fn check_topology_failure(f: &Fixture, status: NtStatus) {
    for class in CLASSES {
        let mut output = [0xa5; 104];
        let result = encode(f, class, &mut output);
        if class == 8 || class == 16 {
            assert_eq!(result, Ok(4));
            let expected: u32 = if class == 8 {
                0x1234
            } else {
                CreateOptions::WRITE_THROUGH.bits()
            };
            assert_eq!(&output[..4], &expected.to_le_bytes());
            assert_eq!(&output[4..], &[0xa5; 100]);
        } else {
            assert_eq!(result, Err(status));
            assert_eq!(output, [0xa5; 104]);
        }
    }
}

#[test]
fn access_and_mode_do_not_resolve_deleted_or_missing_topology() {
    let mut f = Fixture::new(CreateOptions::WRITE_THROUGH);
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    f.io.device_mut(f.device).unwrap().delete_pending = true;
    check_topology_failure(&f, NtStatus::DELETE_PENDING);
    f.io.device_mut(f.device).unwrap().delete_pending = false;
    f.io.device_mut(f.device).unwrap().top_of_stack = DeviceId::NULL;
    check_topology_failure(&f, NtStatus::INVALID_PARAMETER);
    f.io.device_mut(f.device).unwrap().top_of_stack = f.device;
    f.io.release_file_reference(&mut owner).unwrap();
}

#[test]
fn attached_top_alignment_is_live_but_never_an_authenticated_base_route() {
    let mut f = Fixture::new(CreateOptions::WRITE_THROUGH);
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    f.io.device_mut(f.device).unwrap().alignment_requirement = 0x1ff;
    let driver =
        f.io.create_driver(
            &NtPath::parse_str(r"\Driver\QueryEncodingFilter").unwrap(),
            Box::new(MockDriverBackend::new()),
        )
        .unwrap();
    let top =
        f.io.create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    f.io.device_mut(top).unwrap().alignment_requirement = 0xfff;
    f.io.attach_device_to_stack(top, f.device).unwrap();
    for class in CLASSES {
        let mut output = [0xa5; 104];
        assert_eq!(
            f.io.encode_owned_file_query_information(
                f.client,
                f.file,
                top,
                0x1234,
                class,
                &mut output,
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(output, [0xa5; 104]);
    }
    let mut output = [0xa5; 104];
    assert_eq!(encode(&f, 18, &mut output), Ok(12));
    assert_eq!(&output[92..96], &0xfffu32.to_le_bytes());
    f.io.device_mut(top).unwrap().delete_pending = true;
    check_topology_failure(&f, NtStatus::DELETE_PENDING);
    f.io.device_mut(top).unwrap().delete_pending = false;
    f.io.detach_device_from_stack(top).unwrap();
    assert_eq!(encode(&f, 18, &mut output), Ok(12));
    assert_eq!(&output[92..96], &0x1ffu32.to_le_bytes());
    f.io.release_file_reference(&mut owner).unwrap();
}

#[test]
fn file_all_seeds_only_manager_fields_and_preserves_captured_grant() {
    let mut f = Fixture::new(CreateOptions::WRITE_THROUGH | CreateOptions::NON_DIRECTORY_FILE);
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    f.io.device_mut(f.device).unwrap().alignment_requirement = 0x1ff;
    let mut output = [0xa5; 112];
    assert_eq!(encode(&f, 18, &mut output), Ok(12));
    let mut expected = [0xa5; 112];
    expected[76..80].copy_from_slice(&0x1234u32.to_le_bytes());
    expected[88..92].copy_from_slice(&CreateOptions::WRITE_THROUGH.bits().to_le_bytes());
    expected[92..96].copy_from_slice(&0x1ffu32.to_le_bytes());
    assert_eq!(output, expected);
    assert_ne!(0x1234, AccessMask::GENERIC_READ.bits());
    f.io.release_file_reference(&mut owner).unwrap();
}

#[test]
fn unsupported_classes_and_short_outputs_never_mutate_output() {
    let mut f = Fixture::new(CreateOptions::empty());
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    for class in [0, 4, 14, 41, u32::MAX] {
        let mut output = [0xa5; 104];
        assert_eq!(
            encode(&f, class, &mut output),
            Err(NtStatus(nt_fs::STATUS_INVALID_INFO_CLASS as i32))
        );
        assert_eq!(output, [0xa5; 104]);
    }
    for class in CLASSES {
        let mut output = [0xa5; 104];
        let length = if class == 18 {
            nt_fs::FILE_ALL_INFORMATION_MINIMUM_LENGTH - 1
        } else {
            3
        };
        assert_eq!(
            encode(&f, class, &mut output[..length]),
            Err(NtStatus(nt_fs::STATUS_INFO_LENGTH_MISMATCH as i32))
        );
        assert_eq!(output, [0xa5; 104]);
    }
    f.io.release_file_reference(&mut owner).unwrap();
}

#[test]
fn identity_and_body_failures_precede_topology_and_preserve_output() {
    let mut f = Fixture::new(CreateOptions::empty());
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    let other_client = f.io.register_client();
    f.io.device_mut(f.device).unwrap().top_of_stack = DeviceId::NULL;
    f.io.file_mut(f.file).unwrap().close_dispatched = true;
    for class in CLASSES {
        for (client, file, device) in [
            (other_client, f.file, f.device),
            (f.client, FileId::NULL, f.device),
            (f.client, f.file, DeviceId::NULL),
            (f.client, f.file, DeviceId(f.device.raw() + 1)),
        ] {
            let mut output = [0xa5; 104];
            assert_eq!(
                f.io.encode_owned_file_query_information(
                    client,
                    file,
                    device,
                    0x1234,
                    class,
                    &mut output,
                ),
                Err(NtStatus::INVALID_HANDLE)
            );
            assert_eq!(output, [0xa5; 104]);
        }
        let mut output = [0xa5; 104];
        assert_eq!(encode(&f, class, &mut output), Err(NtStatus::FILE_CLOSED));
        assert_eq!(output, [0xa5; 104]);
    }
    f.io.file_mut(f.file).unwrap().close_dispatched = false;
    for state in [
        FileState::Allocated,
        FileState::CreateIrpDispatched,
        FileState::Closed,
    ] {
        f.io.file_mut(f.file).unwrap().state = state;
        for class in CLASSES {
            let mut output = [0xa5; 104];
            let status = if state == FileState::Closed {
                NtStatus::FILE_CLOSED
            } else {
                NtStatus::INVALID_HANDLE
            };
            assert_eq!(encode(&f, class, &mut output), Err(status));
            assert_eq!(output, [0xa5; 104]);
        }
    }
    f.io.file_mut(f.file).unwrap().state = FileState::Open;
    f.io.device_mut(f.device).unwrap().top_of_stack = f.device;
    f.io.release_file_reference(&mut owner).unwrap();
}

#[test]
fn every_query_class_survives_real_cleanup_with_retained_capture() {
    let mut f = Fixture::new(CreateOptions::WRITE_THROUGH);
    let mut captures = FileIoCaptureTable::new();
    let mut capture = captures
        .capture(&mut f.io, f.file, f.device, 0x1234)
        .unwrap();
    let before: alloc::vec::Vec<_> = CLASSES
        .iter()
        .map(|&class| {
            let mut output = [0xa5; 104];
            let result = encode(&f, class, &mut output);
            assert_eq!(result, Ok(if class == 18 { 12 } else { 4 }));
            (result, output)
        })
        .collect();
    f.io.close(f.client, f.handle).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).unwrap().cleanup_dispatched);
    assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
    for (class, expected) in CLASSES.into_iter().zip(before) {
        let mut output = [0xa5; 104];
        assert_eq!((encode(&f, class, &mut output), output), expected);
    }
    captures.retire(&mut capture).unwrap();
    captures
        .release_retired(&mut f.io, capture.identity())
        .unwrap();
    f.io.pump();
    for class in CLASSES {
        let mut output = [0xa5; 104];
        assert_eq!(
            encode(&f, class, &mut output),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(output, [0xa5; 104]);
    }
}
