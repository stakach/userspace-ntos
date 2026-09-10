//! Real directory enumeration composed with retained terminal delivery. User-copy outcomes and
//! completion admissions are explicit external boundaries, not execution of the native adapter.

use nt_fs::*;
use nt_io_manager::*;

const ID: u64 = 0xf200_0000_0000_0001;
const FILE: u64 = 0;
const REPLY: u64 = 61;
const PATTERN: [u16; 5] = [
    b'*' as u16,
    b'.' as u16,
    b't' as u16,
    b'x' as u16,
    b't' as u16,
];

fn fixture(synchronous: bool) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\queries\alpha.txt", b"alpha"));
    assert!(fs.provision_file(r"\??\C:\queries\bravo.txt", b"bravo"));
    let opened = fs.zw_create_file(
        r"\??\C:\queries",
        FILE_LIST_DIRECTORY | if synchronous { SYNCHRONIZE } else { 0 },
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE
            | if synchronous {
                FILE_SYNCHRONOUS_IO_NONALERT
            } else {
                0
            },
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    (fs, opened.handle)
}

fn query(fs: &mut FileSystem, handle: u64, output: &mut [u8]) -> DirectoryQueryResult {
    fs.zw_query_directory_file(
        handle,
        FILE_NAMES_INFORMATION,
        true,
        Some(&PATTERN),
        false,
        output,
    )
}

fn name(output: &[u8], information: usize) -> String {
    let length = u32::from_le_bytes(output[8..12].try_into().unwrap()) as usize;
    assert_eq!(information, 12 + length);
    String::from_utf16(
        &output[12..information]
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn terminal(status: u32, information: usize, synchronous: bool, event: u64) -> PendingFileIo {
    let publish = nt_io_completion::file_io_status_publishes_completion(status, true);
    PendingFileIo {
        route: PendingFileRoute::Local(LocalFileObject::Overlay(FILE)),
        irp_id: ID,
        major: nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status,
            information: information as u64,
        }),
        tid: 60,
        iosb_va: if publish { 0x1000 } else { 0 },
        apc_routine: if publish { 0x2000 } else { 0 },
        event_obj_idx: if publish { event } else { u64::MAX },
        signal_file: publish && (synchronous || event == u64::MAX),
        reply_required: true,
        reply_cap: REPLY,
        ..PendingFileIo::default()
    }
}

fn settle_surfaces(fs: &mut FileSystem, handle: u64, table: &mut PendingFileIoTable, slot: usize) {
    let owner = table.get(slot).unwrap();
    for (required, flag) in [
        (owner.iosb_va != 0, IO_DELIVERY_IOSB_PUBLISHED),
        (owner.event_obj_idx != u64::MAX, IO_DELIVERY_EVENT_PUBLISHED),
        (owner.apc_routine != 0, IO_DELIVERY_APC_PUBLISHED),
    ] {
        if required {
            // A refused external admission performs no effect and preserves terminal state.
            let before = table.get(slot);
            assert!(!table.completion_surfaces_settled_exact(slot, ID));
            assert!(table.mark_backend_acked_exact(slot, ID).is_none());
            assert!(table.finish_exact(slot, ID).is_none());
            assert_eq!(table.get(slot), before);
            table.mark_delivery_exact(slot, ID, flag).unwrap();
        }
    }
    if owner.signal_file {
        assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
        fs.zw_set_file_signaled(handle, true).unwrap();
        table
            .mark_delivery_exact(slot, ID, IO_DELIVERY_FILE_PUBLISHED)
            .unwrap();
    }
}

fn settle_reply(table: &mut PendingFileIoTable, slot: usize) {
    let terminal = table.get(slot).unwrap().local_terminal_result();
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(REPLY)));
    table.restore_reply_cap_exact(slot, ID, REPLY).unwrap();
    assert_eq!(table.get(slot).unwrap().local_terminal_result(), terminal);
    assert!(table.finish_exact(slot, ID).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(REPLY)));
    table.mark_reply_published_exact(slot, ID).unwrap();
    table.mark_backend_acked_exact(slot, ID).unwrap();
    assert!(table.finish_exact(slot, ID).is_none());
}

fn release(fs: &mut FileSystem, handle: u64, table: &mut PendingFileIoTable, slot: usize) {
    fs.zw_release_io_reference(handle).unwrap();
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    table.finish_exact(slot, ID).unwrap();
}

#[test]
fn accepted_enumeration_is_not_repeated_by_late_surface_or_reply_retry() {
    let (mut fs, handle) = fixture(true);
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    let mut staging = [0; 256];
    let result = query(&mut fs, handle, &mut staging);
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(name(&staging, result.information), "alpha.txt");
    let user_output = staging[..result.information].to_vec();
    let slot = table
        .park_reserved(
            reservation,
            terminal(result.status, result.information, true, 62),
        )
        .unwrap();
    assert_eq!(
        (
            table.get(slot).unwrap().output_va,
            table.get(slot).unwrap().output_len
        ),
        (0, 0)
    );
    assert!(table.advance_output_exact(slot, ID, 0, 0).is_none());
    settle_surfaces(&mut fs, handle, &mut table, slot);
    settle_reply(&mut table, slot);
    assert_eq!(name(&user_output, result.information), "alpha.txt");
    release(&mut fs, handle, &mut table, slot);

    // A new real request proves the shared file cursor advanced exactly once, not per retry.
    let next = query(&mut fs, handle, &mut staging);
    assert_eq!(next.status, STATUS_SUCCESS);
    assert_eq!(name(&staging, next.information), "bravo.txt");
    assert_eq!(
        query(&mut fs, handle, &mut staging).status,
        STATUS_NO_MORE_FILES
    );
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
}

#[test]
fn definitive_copy_failure_keeps_the_accepted_directory_cursor() {
    let (mut fs, handle) = fixture(true);
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    let mut staging = [0; 256];
    let result = query(&mut fs, handle, &mut staging);
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(name(&staging, result.information), "alpha.txt");
    // Explicit partial-copy failure after filesystem completion, not a native page-fault model.
    let mut user_output = vec![0xcc; result.information];
    user_output[..14].copy_from_slice(&staging[..14]);
    let copy_status = 0xc000_0005;
    let pending = terminal(copy_status, result.information, true, 62);
    assert_eq!(
        (pending.iosb_va, pending.apc_routine, pending.event_obj_idx),
        (0, 0, u64::MAX)
    );
    assert!(!pending.signal_file);
    let slot = table.park_reserved(reservation, pending).unwrap();
    settle_reply(&mut table, slot);
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
    assert_eq!(&user_output[..14], &staging[..14]);
    assert!(user_output[14..].iter().all(|byte| *byte == 0xcc));
    release(&mut fs, handle, &mut table, slot);
    let next = query(&mut fs, handle, &mut staging);
    assert_eq!(next.status, STATUS_SUCCESS);
    assert_eq!(name(&staging, next.information), "bravo.txt");
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
}

#[test]
fn overflow_and_end_of_scan_publish_warning_completions_in_every_open_mode() {
    for synchronous in [false, true] {
        for event in [u64::MAX, 62] {
            for overflow in [false, true] {
                let (mut fs, handle) = fixture(synchronous);
                let mut staging = [0; 256];
                if !overflow {
                    assert_eq!(query(&mut fs, handle, &mut staging).status, STATUS_SUCCESS);
                    assert_eq!(query(&mut fs, handle, &mut staging).status, STATUS_SUCCESS);
                }
                let mut table = PendingFileIoTable::new();
                let reservation = table.reserve().unwrap();
                fs.zw_begin_file_io(handle).unwrap();
                let result = query(
                    &mut fs,
                    handle,
                    if overflow {
                        &mut staging[..16]
                    } else {
                        &mut staging
                    },
                );
                assert_eq!(
                    result.status,
                    if overflow {
                        STATUS_BUFFER_OVERFLOW
                    } else {
                        STATUS_NO_MORE_FILES
                    }
                );
                assert_eq!(result.information, if overflow { 16 } else { 0 });
                let user_output = staging[..result.information].to_vec();
                if overflow {
                    assert_eq!(u32::from_le_bytes(staging[8..12].try_into().unwrap()), 18);
                    assert_eq!(&user_output[12..], &[b'a', 0, b'l', 0]);
                }
                let pending = terminal(result.status, result.information, synchronous, event);
                assert_ne!(pending.iosb_va, 0);
                assert_ne!(pending.apc_routine, 0);
                assert_eq!(pending.event_obj_idx, event);
                assert_eq!(pending.signal_file, synchronous || event == u64::MAX);
                let slot = table.park_reserved(reservation, pending).unwrap();
                settle_surfaces(&mut fs, handle, &mut table, slot);
                settle_reply(&mut table, slot);
                assert_eq!(
                    fs.zw_is_file_signaled(handle),
                    Ok(synchronous || event == u64::MAX)
                );
                assert_eq!(
                    table.get(slot).unwrap().local_terminal_result(),
                    Some((result.status, result.information as u64))
                );
                release(&mut fs, handle, &mut table, slot);
                let next = query(&mut fs, handle, &mut staging);
                if overflow {
                    assert_eq!(next.status, STATUS_SUCCESS);
                    assert_eq!(name(&staging, next.information), "alpha.txt");
                } else {
                    assert_eq!(next.status, STATUS_NO_MORE_FILES);
                }
                assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
            }
        }
    }
}

#[test]
fn first_scan_no_such_file_does_not_publish_inline_completion() {
    for synchronous in [false, true] {
        for event in [u64::MAX, 62] {
            let (mut fs, handle) = fixture(synchronous);
            let mut table = PendingFileIoTable::new();
            let reservation = table.reserve().unwrap();
            fs.zw_begin_file_io(handle).unwrap();
            let pattern: Vec<u16> = "missing.*".encode_utf16().collect();
            let mut staging = [0xcc; 256];
            let result = fs.zw_query_directory_file(
                handle,
                FILE_NAMES_INFORMATION,
                true,
                Some(&pattern),
                false,
                &mut staging,
            );
            assert_eq!(
                (result.status, result.information),
                (STATUS_NO_SUCH_FILE, 0)
            );
            assert_eq!(staging, [0xcc; 256]);
            let pending = terminal(result.status, result.information, synchronous, event);
            assert_eq!(
                (pending.iosb_va, pending.apc_routine, pending.event_obj_idx),
                (0, 0, u64::MAX)
            );
            assert!(!pending.signal_file);
            let slot = table.park_reserved(reservation, pending).unwrap();
            settle_reply(&mut table, slot);
            assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
            assert_eq!(
                table.get(slot).unwrap().delivery_state
                    & (IO_DELIVERY_IOSB_PUBLISHED
                        | IO_DELIVERY_EVENT_PUBLISHED
                        | IO_DELIVERY_FILE_PUBLISHED
                        | IO_DELIVERY_APC_PUBLISHED),
                0
            );
            release(&mut fs, handle, &mut table, slot);
            assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
        }
    }
}
