use super::*;

fn process() -> ProcessInitialization {
    ProcessInitialization {
        body: GuestAddr(0x10_0000),
        process_id: 4,
        peb: GuestAddr::NULL,
    }
}

fn thread() -> ThreadInitialization {
    ThreadInitialization {
        body: GuestAddr(0x20_0000),
        process_body: process().body,
        process_id: 4,
        thread_id: 16,
        teb: GuestAddr::NULL,
        system_thread: true,
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn activation_refresh_preserves_all_bytes_except_teb_and_system_thread_bit() {
    let init = thread();
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 16];
    initialize_thread(&mut bytes, init).unwrap();
    for &offset in THREAD_LIST_HEADS {
        expected_u64(&mut bytes, offset, 0x11_0000 + offset as u64);
        expected_u64(&mut bytes, offset + 8, 0x22_0000 + offset as u64);
    }
    bytes[KTHREAD_PREVIOUS_MODE] = 1;
    expected_u64(&mut bytes, KTHREAD_WIN32_THREAD, 0x50_0000);
    expected_u64(&mut bytes, ETHREAD_THREAD_NAME, 0x60_0000);
    let old_flags = 0xabcd_ffffu32;
    bytes[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&old_flags.to_le_bytes());
    let mut expected = bytes;
    expected_u64(&mut expected, KTHREAD_TEB, 0x70_0000);
    expected[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&(old_flags & !ETHREAD_SYSTEM_THREAD).to_le_bytes());
    let fields = ThreadInitialization {
        teb: GuestAddr(0x70_0000),
        system_thread: false,
        ..init
    };
    let before_validation = bytes;
    validate_thread_activation(&bytes, fields).unwrap();
    assert_eq!(bytes, before_validation);
    refresh_thread_activation(&mut bytes, fields).unwrap();
    assert_eq!(bytes, expected);
    refresh_thread_activation(&mut bytes, fields).unwrap();
    assert_eq!(bytes, expected, "repeated exact refresh must be idempotent");
    refresh_thread_activation(
        &mut bytes,
        ThreadInitialization {
            teb: GuestAddr::NULL,
            system_thread: true,
            ..init
        },
    )
    .unwrap();
    expected_u64(&mut expected, KTHREAD_TEB, 0);
    expected[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&old_flags.to_le_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn activation_refresh_rejects_wrong_stored_identity_before_writes() {
    let init = thread();
    let fields = ThreadInitialization {
        teb: GuestAddr(0x70_0000),
        system_thread: false,
        ..init
    };
    for offset in [
        0,
        ETHREAD_CLIENT_ID_PROCESS,
        ETHREAD_CLIENT_ID_THREAD,
        KTHREAD_PROCESS,
        ETHREAD_THREADS_PROCESS,
        KTHREAD_APC_STATE_PROCESS,
        KTHREAD_APC_STATE_POINTERS,
        KTHREAD_APC_STATE_POINTERS + 8,
    ] {
        let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 16];
        initialize_thread(&mut bytes, init).unwrap();
        bytes[offset] ^= 1;
        let before = bytes;
        assert_eq!(
            validate_thread_activation(&bytes, fields),
            Err(ProjectionError::IdentityMismatch)
        );
        assert_eq!(bytes, before);
        assert_eq!(
            refresh_thread_activation(&mut bytes, fields),
            Err(ProjectionError::IdentityMismatch)
        );
        assert_eq!(bytes, before);
    }
}

#[test]
fn activation_refresh_cannot_relabel_a_body_or_change_its_owner() {
    let init = thread();
    for fields in [
        ThreadInitialization {
            body: GuestAddr(init.body.0 + 0x1000),
            ..init
        },
        ThreadInitialization {
            process_body: GuestAddr(init.process_body.0 + 0x1000),
            ..init
        },
        ThreadInitialization {
            process_id: init.process_id + 4,
            ..init
        },
        ThreadInitialization {
            thread_id: init.thread_id + 4,
            ..init
        },
    ] {
        let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 16];
        initialize_thread(&mut bytes, init).unwrap();
        let before = bytes;
        assert_eq!(
            refresh_thread_activation(&mut bytes, fields),
            Err(ProjectionError::IdentityMismatch)
        );
        assert_eq!(bytes, before);
    }
}

#[test]
fn activation_refresh_validates_all_input_extents_without_partial_write() {
    let init = thread();
    for (fields, error) in [
        (
            ThreadInitialization {
                body: GuestAddr::NULL,
                ..init
            },
            ProjectionError::NullBody,
        ),
        (
            ThreadInitialization {
                process_body: GuestAddr::NULL,
                ..init
            },
            ProjectionError::NullBody,
        ),
        (
            ThreadInitialization {
                body: GuestAddr(init.body.0 + 1),
                ..init
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ThreadInitialization {
                process_body: GuestAddr(init.process_body.0 + 1),
                ..init
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ThreadInitialization {
                teb: GuestAddr(1),
                ..init
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ThreadInitialization {
                body: GuestAddr(u64::MAX - 7),
                ..init
            },
            ProjectionError::AddressOverflow,
        ),
        (
            ThreadInitialization {
                process_body: GuestAddr(u64::MAX - 7),
                ..init
            },
            ProjectionError::AddressOverflow,
        ),
        (
            ThreadInitialization {
                process_id: 0,
                ..init
            },
            ProjectionError::InvalidProcessId,
        ),
        (
            ThreadInitialization {
                thread_id: 0,
                ..init
            },
            ProjectionError::InvalidThreadId,
        ),
    ] {
        let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 16];
        initialize_thread(&mut bytes, init).unwrap();
        let before = bytes;
        assert_eq!(refresh_thread_activation(&mut bytes, fields), Err(error));
        assert_eq!(bytes, before);
    }
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 16];
    initialize_thread(&mut bytes, init).unwrap();
    for len in [0, KTHREAD_TEB + 8, ETHREAD_BODY_BYTES - 1] {
        let before = bytes;
        assert_eq!(
            refresh_thread_activation(&mut bytes[..len], init),
            Err(ProjectionError::BufferTooSmall)
        );
        assert_eq!(bytes, before);
    }
}

fn expected_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn system_process_has_real_identity_and_no_synthetic_user_storage() {
    let init = process();
    let mut bytes = [0xa5; EPROCESS_BODY_BYTES + 8];
    initialize_process(&mut bytes, init).unwrap();
    let mut expected = [0; EPROCESS_BODY_BYTES];
    expected[0] = 3;
    expected[2] = 0x2c;
    for offset in [0x08, 0x18, 0x50, 0x70, 0x288] {
        expected_u64(&mut expected, offset, init.body.0 + offset as u64);
        expected_u64(&mut expected, offset + 8, init.body.0 + offset as u64);
    }
    expected_u64(&mut expected, 0xd0, 4);
    assert_eq!(&bytes[..EPROCESS_BODY_BYTES], expected);
    assert_eq!(&bytes[EPROCESS_BODY_BYTES..], [0xa5; 8]);
    assert_eq!(u64_at(&bytes, EPROCESS_PEB), 0);
    assert_eq!(u64_at(&bytes, EPROCESS_WIN32_PROCESS), 0);
    assert!(bytes[0x800..0xc00].iter().all(|byte| *byte == 0));
}

#[test]
fn system_thread_has_real_cid_process_links_and_cross_thread_flag() {
    let init = thread();
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 8];
    initialize_thread(&mut bytes, init).unwrap();
    let mut expected = [0; ETHREAD_BODY_BYTES];
    expected[0] = 6;
    for offset in [0x08, 0x18, 0x48, 0x58, 0x330, 0x348, 0x368, 0x3b8] {
        expected_u64(&mut expected, offset, init.body.0 + offset as u64);
        expected_u64(&mut expected, offset + 8, init.body.0 + offset as u64);
    }
    for offset in [0x68, 0x200, 0x3d8] {
        expected_u64(&mut expected, offset, init.process_body.0);
    }
    expected_u64(&mut expected, 0x210, init.body.0 + 0x48);
    expected_u64(&mut expected, 0x218, init.body.0 + 0x220);
    expected_u64(&mut expected, 0x378, 4);
    expected_u64(&mut expected, 0x380, 16);
    expected[0x41c] = 0x10;
    assert_eq!(&bytes[..ETHREAD_BODY_BYTES], expected);
    assert_eq!(&bytes[ETHREAD_BODY_BYTES..], [0xa5; 8]);
    assert_eq!(u64_at(&bytes, KTHREAD_TEB), 0);
    assert_eq!(u64_at(&bytes, KTHREAD_WIN32_THREAD), 0);
    assert_eq!(bytes[KTHREAD_PREVIOUS_MODE], 0);
    assert_eq!(ETHREAD_THREAD_NAME + 8, ETHREAD_BODY_BYTES);
}

#[test]
fn supplied_user_addresses_are_preserved_without_building_user_structures() {
    let mut process_init = process();
    process_init.peb = GuestAddr(0x30_0000);
    let mut process_bytes = [0; EPROCESS_BODY_BYTES];
    initialize_process(&mut process_bytes, process_init).unwrap();
    assert_eq!(u64_at(&process_bytes, EPROCESS_PEB), 0x30_0000);
    let mut thread_init = thread();
    thread_init.teb = GuestAddr(0x40_0000);
    thread_init.system_thread = false;
    let mut thread_bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut thread_bytes, thread_init).unwrap();
    assert_eq!(u64_at(&thread_bytes, KTHREAD_TEB), 0x40_0000);
    assert_eq!(
        &thread_bytes[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4],
        &[0; 4]
    );
}

#[test]
fn invalid_process_inputs_leave_all_caller_bytes_unchanged() {
    let valid = process();
    for (init, error) in [
        (
            ProcessInitialization {
                body: GuestAddr::NULL,
                ..valid
            },
            ProjectionError::NullBody,
        ),
        (
            ProcessInitialization {
                body: GuestAddr(1),
                ..valid
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ProcessInitialization {
                body: GuestAddr(u64::MAX - 7),
                ..valid
            },
            ProjectionError::AddressOverflow,
        ),
        (
            ProcessInitialization {
                peb: GuestAddr(1),
                ..valid
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ProcessInitialization {
                process_id: 0,
                ..valid
            },
            ProjectionError::InvalidProcessId,
        ),
    ] {
        let mut bytes = [0xa5; EPROCESS_BODY_BYTES + 8];
        assert_eq!(initialize_process(&mut bytes, init), Err(error));
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn invalid_thread_inputs_leave_all_caller_bytes_unchanged() {
    let valid = thread();
    for (init, error) in [
        (
            ThreadInitialization {
                body: GuestAddr::NULL,
                ..valid
            },
            ProjectionError::NullBody,
        ),
        (
            ThreadInitialization {
                process_body: GuestAddr::NULL,
                ..valid
            },
            ProjectionError::NullBody,
        ),
        (
            ThreadInitialization {
                body: GuestAddr(1),
                ..valid
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ThreadInitialization {
                process_body: GuestAddr(1),
                ..valid
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ThreadInitialization {
                teb: GuestAddr(1),
                ..valid
            },
            ProjectionError::UnalignedAddress,
        ),
        (
            ThreadInitialization {
                body: GuestAddr(u64::MAX - 7),
                ..valid
            },
            ProjectionError::AddressOverflow,
        ),
        (
            ThreadInitialization {
                process_body: GuestAddr(u64::MAX - 7),
                ..valid
            },
            ProjectionError::AddressOverflow,
        ),
        (
            ThreadInitialization {
                process_id: 0,
                ..valid
            },
            ProjectionError::InvalidProcessId,
        ),
        (
            ThreadInitialization {
                thread_id: 0,
                ..valid
            },
            ProjectionError::InvalidThreadId,
        ),
    ] {
        let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 8];
        assert_eq!(initialize_thread(&mut bytes, init), Err(error));
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn short_projection_storage_is_rejected_before_zeroing() {
    let mut process_bytes = [0xa5; EPROCESS_BODY_BYTES - 1];
    assert_eq!(
        initialize_process(&mut process_bytes, process()),
        Err(ProjectionError::BufferTooSmall)
    );
    assert!(process_bytes.iter().all(|byte| *byte == 0xa5));
    let mut old_thread_bytes = [0xa5; 0x400];
    assert_eq!(
        initialize_thread(&mut old_thread_bytes, thread()),
        Err(ProjectionError::BufferTooSmall)
    );
    assert_eq!(old_thread_bytes, [0xa5; 0x400]);
}

#[test]
fn self_relative_list_addresses_do_not_wrap_near_address_space_end() {
    let mut init = thread();
    init.body = GuestAddr(u64::MAX - ETHREAD_BODY_BYTES as u64 - 7);
    let mut bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, init).unwrap();
    assert_eq!(u64_at(&bytes, 0x3b8), init.body.0 + 0x3b8);
    assert_eq!(u64_at(&bytes, 0x218), init.body.0 + 0x220);
}
