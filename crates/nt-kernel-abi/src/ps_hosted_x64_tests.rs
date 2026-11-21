use super::*;

fn process() -> ProcessInitialization {
    ProcessInitialization {
        body: GuestAddr(0x10_0000),
        process_id: 4,
        peb: GuestAddr::NULL,
        image_file_name: [0; 16],
        section_base_address: GuestAddr::NULL,
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
        suspend_count: 0,
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn verify_device_updates_only_the_exact_live_ethread_projection() {
    // `IoSetDeviceToVerify` in the pinned ntoskrnl.exe stores at [ETHREAD + 0x558].
    assert_eq!(ETHREAD_DEVICE_TO_VERIFY, 0x558);
    let init = thread();
    let mut bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, init).unwrap();
    let before = bytes;
    set_thread_device_to_verify(&mut bytes, init, GuestAddr(0x40_0000)).unwrap();
    assert_eq!(u64_at(&bytes, ETHREAD_DEVICE_TO_VERIFY), 0x40_0000);
    assert_eq!(
        &bytes[..ETHREAD_DEVICE_TO_VERIFY],
        &before[..ETHREAD_DEVICE_TO_VERIFY]
    );
    assert_eq!(
        &bytes[ETHREAD_DEVICE_TO_VERIFY + 8..],
        &before[ETHREAD_DEVICE_TO_VERIFY + 8..]
    );

    let written = bytes;
    assert_eq!(
        set_thread_device_to_verify(
            &mut bytes,
            ThreadInitialization {
                thread_id: init.thread_id + 1,
                ..init
            },
            GuestAddr(0x50_0000),
        ),
        Err(ProjectionError::IdentityMismatch)
    );
    assert_eq!(bytes, written, "wrong thread identity must not write");

    let mut too_short = [0xa5; ETHREAD_DEVICE_TO_VERIFY + 7];
    let unchanged = too_short;
    assert_eq!(
        set_thread_device_to_verify(&mut too_short, init, GuestAddr(0x50_0000)),
        Err(ProjectionError::BufferTooSmall)
    );
    assert_eq!(too_short, unchanged);
}

#[test]
fn released_libernt_win32k_reads_the_projected_peb_at_0x2e0() {
    // The pinned win32k.sys IntFixWindowCoordinates calls IoGetCurrentProcess, then reads
    // [EPROCESS + 0x2e0] and [PEB + 0x20] for ProcessParameters (RVA 0xAB3C9..0xAB3D6).
    assert_eq!(EPROCESS_PEB, 0x2e0);
    let mut bytes = [0; EPROCESS_BODY_BYTES];
    initialize_process(
        &mut bytes,
        ProcessInitialization {
            peb: GuestAddr(0x30_0000),
            ..process()
        },
    )
    .unwrap();
    assert_eq!(u64_at(&bytes, 0x2e0), 0x30_0000);
    assert_eq!(u64_at(&bytes, 0x2b8), 0);
}

#[test]
fn released_libernt_win32k_reads_the_thread_win32_slot_at_0x1c8() {
    // The pinned win32k.sys never asks the kernel for another thread's Win32Thread; it reads
    // `Thread->Tcb.Win32Thread` out of the thread object. LiberNT's AMD64 KTHREAD places it at
    // 0x1C8 (`sdk/include/ndk/ketypes.h`), and the released image agrees:
    //   IntSetTimer (TMRF_TIFROMWND)  RVA 0xA457C  mov rcx,[rdi+0x10]; mov rcx,[rcx];
    //                                              mov rcx,[rcx+0x1c8]
    //   PsGetCurrentThread()->Tcb...  RVA 0x9CA8E  mov rax,gs:[0x188]; mov rcx,[rax+0x1c8]
    //   after PsLookupThreadByThreadId RVA 0x7CFB6 and 0xAAB37  mov ..,[rcx+0x1c8]
    // A slot published anywhere else leaves every window timer with a NULL owner, which
    // `ProcessTimers` asserts on (`win32ss/user/ntuser/timer.c:519`).
    assert_eq!(KTHREAD_WIN32_THREAD, 0x1c8);
    let init = ThreadInitialization {
        teb: GuestAddr(0x30_0000),
        system_thread: false,
        ..thread()
    };
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, init).unwrap();
    // A fresh thread is not a GUI thread, and no projected field shares the slot's bytes.
    assert_eq!(u64_at(&bytes, 0x1c8), 0);
    expected_u64(&mut bytes, KTHREAD_WIN32_THREAD, 0x50_0000);
    let published = bytes;
    refresh_thread_activation(&mut bytes, init).unwrap();
    exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::UserMode).unwrap();
    exchange_thread_stack_swap_enable(&mut bytes, false).unwrap();
    assert_eq!(u64_at(&bytes, 0x1c8), 0x50_0000);
    assert_eq!(&bytes[0x1c8..0x1d0], &published[0x1c8..0x1d0]);
}

#[test]
fn apc_state_index_has_the_pinned_offset_and_survives_activation_refresh() {
    assert_eq!(KTHREAD_APC_STATE_INDEX, 0x24a);
    let init = thread();
    let mut bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, init).unwrap();
    assert_eq!(bytes[KTHREAD_APC_STATE_INDEX], 0);
    bytes[KTHREAD_APC_STATE_INDEX] = 1;
    refresh_thread_activation(&mut bytes, init).unwrap();
    assert_eq!(bytes[KTHREAD_APC_STATE_INDEX], 1);
}

#[test]
fn activation_refresh_changes_only_teb_system_thread_bit_and_suspend_count() {
    let init = thread();
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 16];
    initialize_thread(&mut bytes, init).unwrap();
    for &offset in THREAD_LIST_HEADS {
        expected_u64(&mut bytes, offset, 0x11_0000 + offset as u64);
        expected_u64(&mut bytes, offset + 8, 0x22_0000 + offset as u64);
    }
    bytes[KTHREAD_PREVIOUS_MODE] = 1;
    expected_u64(&mut bytes, KTHREAD_WIN32_THREAD, 0x50_0000);
    expected_u64(&mut bytes, ETHREAD_BODY_BYTES - 8, 0x60_0000);
    let old_flags = 0xabcd_ffffu32;
    bytes[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&old_flags.to_le_bytes());
    let mut expected = bytes;
    expected_u64(&mut expected, KTHREAD_TEB, 0x70_0000);
    expected[KTHREAD_SUSPEND_COUNT] = 1;
    expected[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&(old_flags & !ETHREAD_SYSTEM_THREAD).to_le_bytes());
    let fields = ThreadInitialization {
        teb: GuestAddr(0x70_0000),
        system_thread: false,
        suspend_count: 1,
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
    expected[KTHREAD_SUSPEND_COUNT] = 0;
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
    expected[2] = 0x72;
    for offset in [0x08, 0x18, 0x30, 0x68, 0x370] {
        expected_u64(&mut expected, offset, init.body.0 + offset as u64);
        expected_u64(&mut expected, offset + 8, init.body.0 + offset as u64);
    }
    expected_u64(&mut expected, 0x1d0, 4);
    assert_eq!(&bytes[..EPROCESS_BODY_BYTES], expected);
    assert_eq!(&bytes[EPROCESS_BODY_BYTES..], [0xa5; 8]);
    assert_eq!(u64_at(&bytes, EPROCESS_PEB), 0);
    assert_eq!(u64_at(&bytes, EPROCESS_WIN32_PROCESS), 0);
    assert!(bytes[0x800..0xc00].iter().all(|byte| *byte == 0));
}

#[test]
fn process_image_file_name_is_stable_inside_its_exact_eprocess_body() {
    let mut init = process();
    init.image_file_name[..13].copy_from_slice(b"Explorer.EXE\0");
    let mut bytes = [0xa5; EPROCESS_BODY_BYTES + 8];
    initialize_process(&mut bytes, init).unwrap();
    assert_eq!(&bytes[0x338..0x347], &init.image_file_name[..15]);
    // The sixteenth byte is `PriorityClass`, not part of the name.
    assert_eq!(bytes[0x347], 0);
    assert_eq!(&bytes[EPROCESS_BODY_BYTES..], [0xa5; 8]);
}

#[test]
fn system_thread_has_real_cid_process_links_and_cross_thread_flag() {
    let init = thread();
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 8];
    initialize_thread(&mut bytes, init).unwrap();
    let mut expected = [0; ETHREAD_BODY_BYTES];
    expected[0] = 6;
    expected[KTHREAD_THREAD_FLAGS] = 0x40;
    for offset in [0x08, 0x98, 0xa8, 0x308, 0x4c8, 0x4d8, 0x4f8, 0x540] {
        expected_u64(&mut expected, offset, init.body.0 + offset as u64);
        expected_u64(&mut expected, offset + 8, init.body.0 + offset as u64);
    }
    for offset in [0xb8, 0x220] {
        expected_u64(&mut expected, offset, init.process_body.0);
    }
    expected_u64(&mut expected, 0x4a0, init.body.0 + 0x98);
    expected_u64(&mut expected, 0x4a8, init.body.0 + 0x258);
    expected_u64(&mut expected, 0x508, 4);
    expected_u64(&mut expected, 0x510, 16);
    expected[0x5a0] = 0x10;
    assert_eq!(&bytes[..ETHREAD_BODY_BYTES], expected);
    assert_eq!(&bytes[ETHREAD_BODY_BYTES..], [0xa5; 8]);
    assert_eq!(u64_at(&bytes, KTHREAD_TEB), 0);
    assert_eq!(u64_at(&bytes, KTHREAD_WIN32_THREAD), 0);
    assert_eq!(bytes[KTHREAD_PREVIOUS_MODE], 0);
}

#[test]
fn thread_execution_state_uses_exact_x64_fields_and_preserves_neighbors() {
    // `KeSetKernelStackSwapEnable` in the pinned ntoskrnl.exe exchanges bit 6 of [KTHREAD + 0x78].
    assert_eq!((KTHREAD_THREAD_FLAGS, KTHREAD_ENABLE_STACK_SWAP), (0x78, 0x40));
    let mut bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, thread()).unwrap();
    bytes[KTHREAD_THREAD_FLAGS..KTHREAD_THREAD_FLAGS + 4]
        .copy_from_slice(&(0xa5a5_a500u32 | KTHREAD_ENABLE_STACK_SWAP).to_le_bytes());
    assert_eq!(thread_previous_mode(&bytes), Ok(ThreadPreviousMode::KernelMode));
    let before = bytes;
    assert_eq!(exchange_thread_stack_swap_enable(&mut bytes, false), Ok(true));
    assert_eq!(bytes[KTHREAD_THREAD_FLAGS..KTHREAD_THREAD_FLAGS + 4], 0xa5a5_a500u32.to_le_bytes());
    assert_eq!(exchange_thread_stack_swap_enable(&mut bytes, false), Ok(false));
    assert_eq!(exchange_thread_stack_swap_enable(&mut bytes, true), Ok(false));
    assert_eq!(bytes, before);
    assert_eq!(exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::UserMode),
        Ok(ThreadPreviousMode::KernelMode));
    assert_eq!(thread_previous_mode(&bytes), Ok(ThreadPreviousMode::UserMode));
    assert_eq!(exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::KernelMode),
        Ok(ThreadPreviousMode::UserMode));
    assert_eq!(bytes, before);
}

#[test]
fn invalid_execution_state_and_short_projections_refuse_mutation() {
    let mut bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, thread()).unwrap();
    bytes[KTHREAD_PREVIOUS_MODE] = 2;
    let before = bytes;
    assert_eq!(thread_previous_mode(&bytes), Err(ProjectionError::InvalidPreviousMode));
    assert_eq!(exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::KernelMode),
        Err(ProjectionError::InvalidPreviousMode));
    assert_eq!(bytes, before);
    assert_eq!(exchange_thread_previous_mode(&mut bytes[..KTHREAD_PREVIOUS_MODE],
        ThreadPreviousMode::UserMode), Err(ProjectionError::BufferTooSmall));
    assert_eq!(exchange_thread_stack_swap_enable(&mut bytes[..KTHREAD_THREAD_FLAGS + 3], false),
        Err(ProjectionError::BufferTooSmall));
    assert_eq!(bytes, before);
}

/// win32k.sys tests `pti->pEThread->Tcb.SuspendCount` (a CHAR at +0x284) for its hung-window
/// decision (`msgqueue.c:2307`, image RVAs 0x856E6 and 0x861B1).
#[test]
fn suspend_count_is_published_in_the_exact_live_body_only() {
    let init = thread();
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 8];
    initialize_thread(&mut bytes, ThreadInitialization { suspend_count: 1, ..init }).unwrap();
    assert_eq!(bytes[KTHREAD_SUSPEND_COUNT], 1);
    let mut expected = bytes;
    set_thread_suspend_count(&mut bytes, init, 2).unwrap();
    expected[0x284] = 2;
    assert_eq!(bytes, expected);
    set_thread_suspend_count(&mut bytes, init, 0).unwrap();
    expected[0x284] = 0;
    assert_eq!(bytes, expected);

    assert_eq!(
        set_thread_suspend_count(&mut bytes, init, MAXIMUM_SUSPEND_COUNT + 1),
        Err(ProjectionError::InvalidSuspendCount)
    );
    let other = ThreadInitialization { thread_id: init.thread_id + 4, ..init };
    assert_eq!(
        set_thread_suspend_count(&mut bytes, other, 1),
        Err(ProjectionError::IdentityMismatch)
    );
    assert_eq!(bytes, expected);
}

/// The window station win32k assigns with `PsSetProcessWindowStation` is read back by
/// `UserGetShellWindow` and `NtUserSetShellWindowEx` from [EPROCESS + 0x2c8] directly (image
/// RVAs 0xAF43E and 0xAF567); `IntIsGuiImage` reads the section base at +0x2b0 (RVA 0x242B3).
#[test]
fn process_fields_win32k_reads_directly_are_inside_the_body_and_distinct() {
    let mut init = process();
    init.peb = GuestAddr(0x30_0000);
    init.section_base_address = GuestAddr(0x1_4000_0000);
    let mut bytes = [0xa5; EPROCESS_BODY_BYTES];
    initialize_process(&mut bytes, init).unwrap();
    assert_eq!(u64_at(&bytes, 0x2b0), 0x1_4000_0000);
    assert_eq!(u64_at(&bytes, 0x2c8), 0);
    assert_eq!(u64_at(&bytes, 0x298), 0);
    assert_eq!(u64_at(&bytes, 0x2e0), 0x30_0000);
}

#[test]
fn pinned_fields_fit_their_bodies_without_overlapping() {
    assert_eq!((KPROCESS_BYTES, EPROCESS_BYTES), (0x1c8, 0x840));
    assert_eq!((KTHREAD_BYTES, ETHREAD_BODY_BYTES), (0x4c0, 0x6c0));
    assert!(EPROCESS_BYTES <= EPROCESS_BODY_BYTES);
    for (index, field) in PINNED_LAYOUT.iter().enumerate() {
        let (thread_object, limit) = match field.object {
            "KPROCESS" => (false, KPROCESS_BYTES),
            "EPROCESS" => (false, EPROCESS_BYTES),
            "KTHREAD" => (true, KTHREAD_BYTES),
            "ETHREAD" => (true, ETHREAD_BODY_BYTES),
            other => panic!("unknown object {other}"),
        };
        assert!(field.pinned + field.bytes <= limit, "{}.{}", field.object, field.name);
        for other in &PINNED_LAYOUT[index + 1..] {
            let same_body = thread_object == matches!(other.object, "KTHREAD" | "ETHREAD");
            // `SuspendCount` lives in the tail of `SavedApcState`'s fill bytes by declaration.
            let declared_overlay = matches!(
                (field.name, other.name),
                ("SavedApcState", "SuspendCount") | ("ApcState.ApcListHead", "ApcState.Process")
            );
            assert!(
                !same_body
                    || declared_overlay
                    || field.pinned + field.bytes <= other.pinned
                    || other.pinned + other.bytes <= field.pinned,
                "{}.{} overlaps {}.{}", field.object, field.name, other.object, other.name
            );
        }
    }
}

#[test]
fn nested_execution_modes_restore_the_parked_user_continuation() {
    let mut bytes = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut bytes, thread()).unwrap();
    let initial = exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::UserMode).unwrap();
    let outer = exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::KernelMode).unwrap();
    let kernel = exchange_thread_previous_mode(&mut bytes, ThreadPreviousMode::UserMode).unwrap();
    exchange_thread_previous_mode(&mut bytes, kernel).unwrap();
    assert_eq!(thread_previous_mode(&bytes), Ok(ThreadPreviousMode::KernelMode));
    exchange_thread_previous_mode(&mut bytes, outer).unwrap();
    assert_eq!(thread_previous_mode(&bytes), Ok(ThreadPreviousMode::UserMode));
    exchange_thread_previous_mode(&mut bytes, initial).unwrap();
    assert_eq!(thread_previous_mode(&bytes), Ok(ThreadPreviousMode::KernelMode));
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
    assert_eq!(u64_at(&bytes, 0x540), init.body.0 + 0x540);
    assert_eq!(u64_at(&bytes, 0x4a8), init.body.0 + 0x258);
}

/// Every projected field sits where the pinned LiberNT release (8e478a22) keeps it. The offsets
/// are those of its AMD64 headers and of the accessors in its ntoskrnl.exe; the hosted
/// win32k.sys reads several of them itself, without calling an accessor.
#[test]
fn projected_fields_follow_the_pinned_libernt_layout() {
    for field in PINNED_LAYOUT {
        assert_eq!(
            field.projected, field.pinned,
            "{}.{} ({})", field.object, field.name, field.header
        );
    }
}

#[test]
fn idle_process_has_cid_zero_and_the_nt_image_file_name() {
    // PsIdleProcess: UniqueProcessId 0 and `strcpy(PsIdleProcess->ImageFileName, "Idle")`.
    let body = GuestAddr(0x30_0000);
    let mut bytes = [0xa5; EPROCESS_BODY_BYTES + 8];
    initialize_idle_process(&mut bytes, body).unwrap();
    let mut system = [0; EPROCESS_BODY_BYTES];
    initialize_process(&mut system, ProcessInitialization { body, ..process() }).unwrap();
    expected_u64(&mut system, EPROCESS_UNIQUE_PROCESS_ID, 0);
    system[EPROCESS_IMAGE_FILE_NAME..EPROCESS_IMAGE_FILE_NAME + 4].copy_from_slice(b"Idle");
    assert_eq!(&bytes[..EPROCESS_BODY_BYTES], system);
    assert_eq!(&bytes[EPROCESS_BODY_BYTES..], [0xa5; 8]);
    assert_eq!(initialize_idle_process(&mut bytes, GuestAddr::NULL), Err(ProjectionError::NullBody));
    assert_eq!(
        initialize_idle_process(&mut [0; EPROCESS_BODY_BYTES - 1], body),
        Err(ProjectionError::BufferTooSmall),
    );
}

#[test]
fn idle_thread_has_cid_zero_no_teb_and_no_ps_system_thread_flag() {
    // KiInitializeKernel builds each idle thread with KeInitializeThread only: no CID, no TEB
    // and no PS_CROSS_THREAD_FLAGS_SYSTEM, since PspCreateThread never runs for it.
    let init = thread();
    let mut bytes = [0xa5; ETHREAD_BODY_BYTES + 8];
    initialize_idle_thread(&mut bytes, init.body, init.process_body).unwrap();
    let mut expected = [0; ETHREAD_BODY_BYTES];
    initialize_thread(&mut expected, init).unwrap();
    expected_u64(&mut expected, ETHREAD_CLIENT_ID_PROCESS, 0);
    expected_u64(&mut expected, ETHREAD_CLIENT_ID_THREAD, 0);
    expected[ETHREAD_CROSS_THREAD_FLAGS] = 0;
    assert_eq!(&bytes[..ETHREAD_BODY_BYTES], expected);
    assert_eq!(&bytes[ETHREAD_BODY_BYTES..], [0xa5; 8]);
    assert_eq!(u64_at(&bytes, KTHREAD_TEB), 0);
    assert_eq!(
        initialize_idle_thread(&mut bytes, init.body, GuestAddr::NULL),
        Err(ProjectionError::NullBody),
    );
    assert_eq!(
        initialize_idle_thread(&mut bytes, GuestAddr(init.body.0 + 4), init.process_body),
        Err(ProjectionError::UnalignedAddress),
    );
}
