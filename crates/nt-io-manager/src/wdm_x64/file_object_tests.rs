use super::*;

fn initialization(create_options: u32, opened_case_sensitive: bool) -> WdmFileObjectInit {
    WdmFileObjectInit {
        file_object_address: 0x1234_0000,
        create_options,
        opened_case_sensitive,
        device_object: 0x1000_2000_3000_4000,
        fs_context: 0x5000_6000_7000_8000,
        related_file_object: 0x9000_a000_b000_c000,
        file_name_len: 6,
        file_name_max_len: 8,
        file_name_buffer: 0xd000_e000_f000_0000,
    }
}

#[test]
fn initial_file_flags_match_nt5_create_options_byte_for_byte() {
    for (options, flags) in [
        (0, 0),
        (2, 0x10),
        (4, 0x20),
        (8, 8),
        (0x10, 6),
        (0x20, 2),
        (0x800, 0x100000),
        (0x1000, 0),
        (0x181e, 0x10003e),
        (0x182e, 0x10003a),
    ] {
        for sensitive in [false, true] {
            let init = initialization(options, sensitive);
            let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
            assert_eq!(write_wdm_file_object(&mut bytes, init), Ok(()));
            let mut expected = [0; WDM_X64_FILE_OBJECT_SIZE];
            expected[..2].copy_from_slice(&5i16.to_le_bytes());
            expected[2..4].copy_from_slice(&0x100u16.to_le_bytes());
            expected[8..16].copy_from_slice(&init.device_object.to_le_bytes());
            expected[0x18..0x20].copy_from_slice(&init.fs_context.to_le_bytes());
            expected[0x40..0x48].copy_from_slice(&init.related_file_object.to_le_bytes());
            let flags: u32 = flags | if sensitive { 0x20000 } else { 0 };
            expected[0x50..0x54].copy_from_slice(&flags.to_le_bytes());
            expected[0x58..0x5a].copy_from_slice(&init.file_name_len.to_le_bytes());
            expected[0x5a..0x5c].copy_from_slice(&init.file_name_max_len.to_le_bytes());
            expected[0x60..0x68].copy_from_slice(&init.file_name_buffer.to_le_bytes());
            if options & 0x30 != 0 {
                expected[0x80] = 1;
                expected[0x82] = 6;
                expected[0x88..0x90].copy_from_slice(&0x1234_0088u64.to_le_bytes());
                expected[0x90..0x98].copy_from_slice(&0x1234_0088u64.to_le_bytes());
            }
            expected[0x9a] = 6;
            expected[0xa0..0xa8].copy_from_slice(&0x1234_00a0u64.to_le_bytes());
            expected[0xa8..0xb0].copy_from_slice(&0x1234_00a0u64.to_le_bytes());
            assert_eq!(
                bytes, expected,
                "options={options:#x} sensitive={sensitive}"
            );
        }
    }
}

#[test]
fn other_create_options_never_become_file_object_flags() {
    let projected = 2 | 4 | 8 | 0x10 | 0x20 | 0x800;
    for bit in 0..24 {
        let options = 1u32 << bit;
        if options & projected != 0 {
            continue;
        }
        let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
        assert_eq!(
            write_wdm_file_object(&mut bytes, initialization(options, false)),
            Ok(())
        );
        assert_eq!(&bytes[0x50..0x54], &[0; 4], "options={options:#x}");
    }
}

#[test]
fn malformed_initial_options_leave_every_output_byte_untouched() {
    for options in [
        0x30,
        0x183e,
        0x0100_0000,
        0x8000_0000,
        0xff00_0000,
        u32::MAX,
    ] {
        let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE + 16];
        assert_eq!(
            write_wdm_file_object(&mut bytes, initialization(options, true)),
            Err(WdmLayoutError::InvalidField)
        );
        assert_eq!(bytes, [0xa5; WDM_X64_FILE_OBJECT_SIZE + 16]);
    }
}

#[test]
fn short_file_object_buffer_is_untouched_even_with_invalid_options() {
    for options in [0, 0x10, 0x30, 0xff00_0000] {
        let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE - 1];
        assert_eq!(
            write_wdm_file_object(&mut bytes, initialization(options, true)),
            Err(WdmLayoutError::BufferTooSmall)
        );
        assert_eq!(bytes, [0xa5; WDM_X64_FILE_OBJECT_SIZE - 1]);
    }
}

#[test]
fn invalid_final_file_addresses_do_not_mutate_any_projection() {
    for address in [
        0,
        1,
        7,
        0x1234_0001,
        0xffff_ffff_ffff_ff00,
        0xffff_ffff_ffff_fff8,
    ] {
        let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
        let mut init = initialization(0x10, false);
        init.file_object_address = address;
        assert_eq!(
            write_wdm_file_object(&mut bytes, init),
            Err(WdmLayoutError::InvalidField)
        );
        assert_eq!(bytes, [0xa5; WDM_X64_FILE_OBJECT_SIZE]);
        let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
        let mut device = [0xa5; WDM_X64_DEVICE_OBJECT_SIZE];
        assert_eq!(
            write_wdm_open_device_projection(
                &mut driver,
                &mut device,
                &mut bytes,
                WdmOpenDeviceProjectionInit {
                    file_object_address: address,
                    driver_object: 0x1000,
                    driver_extension: 0x2000,
                    device_object: 0x3000,
                    file_object_context: 0,
                    device_type: 7,
                    device_stack_size: 1,
                    ..Default::default()
                }
            ),
            Err(WdmLayoutError::InvalidField)
        );
        assert_eq!(driver, [0xa5; WDM_X64_DRIVER_OBJECT_SIZE]);
        assert_eq!(device, [0xa5; WDM_X64_DEVICE_OBJECT_SIZE]);
        assert_eq!(bytes, [0xa5; WDM_X64_FILE_OBJECT_SIZE]);
    }
}

#[test]
fn open_device_projection_uses_canonical_device_and_file_metadata() {
    let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
    let mut device = [0xa5; WDM_X64_DEVICE_OBJECT_SIZE];
    let mut file = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
    write_wdm_open_device_projection(
        &mut driver,
        &mut device,
        &mut file,
        WdmOpenDeviceProjectionInit {
            file_object_address: 0x4000,
            driver_object: 0x1000,
            driver_extension: 0x1150,
            driver_name_len: 8,
            driver_name_max_len: 10,
            driver_name_buffer: 0x7000,
            device_object: 0x2000,
            file_object_context: 0x77,
            device_type: 0x23,
            device_flags: 0x14,
            device_characteristics: 0x28,
            device_stack_size: 3,
            file_create_options: 0x20,
            file_opened_case_sensitive: true,
            file_related_file_object: 0x5000,
            file_name_len: 6,
            file_name_max_len: 8,
            file_name_buffer: 0x6000,
        },
    )
    .unwrap();
    assert_eq!(&driver[0x38..0x3a], &8u16.to_le_bytes());
    assert_eq!(&driver[0x3a..0x3c], &10u16.to_le_bytes());
    assert_eq!(&driver[0x40..0x48], &0x7000u64.to_le_bytes());
    assert_eq!(&device[0x30..0x34], &0x14u32.to_le_bytes());
    assert_eq!(&device[0x34..0x38], &0x28u32.to_le_bytes());
    assert_eq!(device[0x4c], 3);
    assert_eq!(&file[0x40..0x48], &0x5000u64.to_le_bytes());
    assert_eq!(&file[0x50..0x54], &0x0002_0002u32.to_le_bytes());
    assert_eq!(&file[0x58..0x5a], &6u16.to_le_bytes());
    assert_eq!(&file[0x5a..0x5c], &8u16.to_le_bytes());
    assert_eq!(&file[0x60..0x68], &0x6000u64.to_le_bytes());
}

#[test]
fn invalid_open_device_projection_metadata_leaves_all_outputs_untouched() {
    let mut driver = [0xa5; WDM_X64_DRIVER_OBJECT_SIZE];
    let mut device = [0xa5; WDM_X64_DEVICE_OBJECT_SIZE];
    let mut file = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
    let mut init = WdmOpenDeviceProjectionInit {
        file_object_address: 0x4000,
        driver_object: 0x1000,
        device_object: 0x2000,
        device_stack_size: 0,
        ..Default::default()
    };
    for invalid in [
        init,
        WdmOpenDeviceProjectionInit {
            device_stack_size: 1,
            file_create_options: 0x30,
            ..init
        },
        WdmOpenDeviceProjectionInit {
            device_stack_size: 1,
            file_name_len: 2,
            file_name_max_len: 2,
            ..init
        },
        WdmOpenDeviceProjectionInit {
            device_stack_size: 1,
            driver_name_len: 2,
            driver_name_max_len: 2,
            ..init
        },
        WdmOpenDeviceProjectionInit {
            device_stack_size: 1,
            driver_name_len: 3,
            driver_name_max_len: 4,
            driver_name_buffer: 0x7000,
            ..init
        },
        WdmOpenDeviceProjectionInit {
            device_stack_size: 1,
            driver_name_len: 2,
            driver_name_max_len: 4,
            driver_name_buffer: u64::MAX - 1,
            ..init
        },
        WdmOpenDeviceProjectionInit {
            device_stack_size: 1,
            file_name_len: 2,
            file_name_max_len: 2,
            file_name_buffer: 0x6001,
            ..init
        },
    ] {
        assert_eq!(
            write_wdm_open_device_projection(&mut driver, &mut device, &mut file, invalid),
            Err(WdmLayoutError::InvalidField)
        );
        assert_eq!(driver, [0xa5; WDM_X64_DRIVER_OBJECT_SIZE]);
        assert_eq!(device, [0xa5; WDM_X64_DEVICE_OBJECT_SIZE]);
        assert_eq!(file, [0xa5; WDM_X64_FILE_OBJECT_SIZE]);
    }
    init.device_stack_size = 1;
    init.file_name_len = 2;
    init.file_name_max_len = 2;
    init.file_name_buffer = 0x6000;
    assert_eq!(
        write_wdm_open_device_projection(&mut driver, &mut device, &mut file, init),
        Ok(())
    );
}

#[test]
fn event_self_links_use_final_virtual_address_not_the_writer_buffer() {
    let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
    let mut init = initialization(0x20, false);
    init.file_object_address = 0x5678_0000;
    assert_ne!(bytes.as_ptr() as u64, init.file_object_address);
    write_wdm_file_object(&mut bytes, init).unwrap();
    for (offset, kind, head) in [(0x80, 1, 0x5678_0088u64), (0x98, 0, 0x5678_00a0u64)] {
        assert_eq!(&bytes[offset..offset + 8], &[kind, 0, 6, 0, 0, 0, 0, 0]);
        assert_eq!(&bytes[offset + 8..offset + 0x10], &head.to_le_bytes());
        assert_eq!(&bytes[offset + 0x10..offset + 0x18], &head.to_le_bytes());
    }
}
