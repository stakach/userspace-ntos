//! Real local file mutations composed with retained inline completion. Typed copy failures are
//! supplied by a host memory fixture; these tests do not execute native user-memory faults.

use nt_address_space::copy::MemoryCopyFailure;
use nt_address_space::native_output::publish_file_io_status_checked;
use nt_fs::*;
use nt_io_manager::*;

const PATH: &str = r"\??\C:\set-owned";
const RENAMED: &str = r"\??\C:\renamed";
const IOSB: u64 = 0x1000;
const REPLY: u64 = 111;
const TID: u64 = 110;
const AV: u32 = 0xc000_0005;

fn payload(class: u32) -> Vec<u8> {
    match class {
        FILE_POSITION_INFORMATION => 3u64.to_le_bytes().to_vec(),
        FILE_END_OF_FILE_INFORMATION => 9u64.to_le_bytes().to_vec(),
        FILE_BASIC_INFORMATION => {
            let mut bytes = vec![0; 40];
            bytes[16..24].copy_from_slice(&123i64.to_le_bytes());
            bytes[32..36].copy_from_slice(&FILE_ATTRIBUTE_HIDDEN.to_le_bytes());
            bytes
        }
        FILE_RENAME_INFORMATION => {
            let name: Vec<u8> = "renamed"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let mut bytes = vec![0; 20];
            bytes[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&name);
            bytes
        }
        _ => panic!("unsupported test mutation"),
    }
}

fn terminal(id: u64, file: u64, policy: LocalSetInformationPolicy, status: u32) -> PendingFileIo {
    PendingFileIo {
        file_id: file,
        irp_id: id,
        tid: TID,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status,
            information: 0,
        }),
        iosb_va: if policy.publishes_iosb(status) {
            IOSB
        } else {
            0
        },
        signal_file: policy.signals_file(status),
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        reply_required: true,
        reply_cap: REPLY,
        ..PendingFileIo::default()
    }
}

fn file(synchronous: bool) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(PATH, b"abcdef"));
    let opened = fs.zw_create_file(
        PATH,
        FILE_READ_DATA | FILE_WRITE_DATA | 0x0000_0100 | DELETE | SYNCHRONIZE,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE
            | if synchronous {
                FILE_SYNCHRONOUS_IO_NONALERT
            } else {
                0
            },
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    (fs, opened.handle)
}

struct Memory {
    bytes: [u8; 16],
    attempts: usize,
}

impl Memory {
    fn new() -> Self {
        Self {
            bytes: [0xcc; 16],
            attempts: 0,
        }
    }
    fn publish(
        &mut self,
        pending: PendingFileIo,
        fault: Option<(usize, MemoryCopyFailure)>,
    ) -> Result<(), MemoryCopyFailure> {
        let (status, information) = pending.local_terminal_result().unwrap();
        let mut store = 0;
        publish_file_io_status_checked(pending.iosb_va, status, information, |address, bytes| {
            let index = store;
            store += 1;
            self.attempts += 1;
            if let Some((failed, failure)) = fault {
                if index == failed {
                    return Err(failure);
                }
            }
            let offset = (address - IOSB) as usize;
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        })
    }
}

fn reply_and_ack(table: &mut PendingFileIoTable, slot: usize, id: u64) {
    let before = table.get(slot).unwrap().local_terminal_result();
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(REPLY)));
    table.restore_reply_cap_exact(slot, id, REPLY).unwrap();
    assert_eq!(table.get(slot).unwrap().local_terminal_result(), before);
    assert!(table.finish_exact(slot, id).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(REPLY)));
    table.mark_reply_published_exact(slot, id).unwrap();
    table.mark_backend_acked_exact(slot, id).unwrap();
    assert!(table.finish_exact(slot, id).is_none());
}

#[test]
fn accepted_metadata_name_and_position_changes_survive_iosb_and_reply_retry() {
    for synchronous in [false, true] {
        for class in [
            FILE_POSITION_INFORMATION,
            FILE_END_OF_FILE_INFORMATION,
            FILE_BASIC_INFORMATION,
            FILE_RENAME_INFORMATION,
        ] {
            for retry in [false, true] {
                for store in [0, 1] {
                    let (mut fs, handle) = file(synchronous);
                    let policy = LocalSetInformationPolicy::capture(class, synchronous);
                    let bytes = payload(class);
                    validate_local_set_information_value(class, &bytes).unwrap();
                    let mut table = PendingFileIoTable::new();
                    let reservation = table.reserve().unwrap();
                    let id = table.local_operation_id(reservation).unwrap();
                    if policy.resets_file_signal() {
                        fs.zw_begin_file_io(handle).unwrap();
                    } else {
                        fs.zw_retain_io_reference(handle).unwrap();
                    }
                    assert_eq!(
                        fs.zw_is_file_signaled(handle),
                        Ok(!policy.resets_file_signal())
                    );
                    let mut mutations = 0;
                    mutations += 1;
                    let status = fs.zw_set_information_file(handle, class, &bytes);
                    assert_eq!(status, STATUS_SUCCESS);
                    let info = fs.query_file_object_information(handle).unwrap();
                    match class {
                        FILE_POSITION_INFORMATION => assert_eq!(info.current_offset, 3),
                        FILE_END_OF_FILE_INFORMATION => assert_eq!(info.metadata.end_of_file, 9),
                        FILE_BASIC_INFORMATION => {
                            assert_eq!(info.metadata.last_write_time, 123);
                            assert_ne!(info.metadata.attributes & FILE_ATTRIBUTE_HIDDEN, 0);
                        }
                        FILE_RENAME_INFORMATION => {
                            assert!(fs.file_bytes_owned(PATH).is_none());
                            assert_eq!(
                                fs.file_bytes_owned(RENAMED).as_deref(),
                                Some(&b"abcdef"[..])
                            );
                        }
                        _ => unreachable!(),
                    }
                    let snapshot = fs.export_volume_snapshot().unwrap();
                    let slot = table
                        .park_reserved(
                            reservation,
                            terminal(id, 0xe700_0000_0000_0000 | handle, policy, status),
                        )
                        .unwrap();
                    let before = table.get(slot).unwrap();
                    let failure = if retry {
                        MemoryCopyFailure::Retry(AV)
                    } else {
                        MemoryCopyFailure::UserFault(AV)
                    };
                    let mut memory = Memory::new();
                    assert_eq!(memory.publish(before, Some((store, failure))), Err(failure));
                    assert_eq!(memory.attempts, store + 1);
                    assert_eq!(table.get(slot), Some(before));
                    if retry {
                        assert!(table.mark_backend_acked_exact(slot, id).is_none());
                        assert_eq!(memory.publish(before, None), Ok(()));
                        table
                            .mark_delivery_exact(slot, id, IO_DELIVERY_IOSB_PUBLISHED)
                            .unwrap();
                        assert_eq!(&memory.bytes[..4], &STATUS_SUCCESS.to_le_bytes());
                    } else {
                        table.mark_iosb_faulted_exact(slot, id, IOSB).unwrap();
                        assert_eq!(
                            table.get(slot).unwrap().delivery_state & IO_DELIVERY_IOSB_PUBLISHED,
                            0
                        );
                        assert_eq!(&memory.bytes[..4], &[0xcc; 4]);
                    }
                    assert_eq!(&memory.bytes[4..8], &[0xcc; 4]);
                    assert_eq!(
                        table.get(slot).unwrap().local_terminal_result(),
                        Some((STATUS_SUCCESS, 0))
                    );
                    assert_eq!(
                        table.get(slot).unwrap().local_syscall_status(),
                        Some(STATUS_SUCCESS)
                    );
                    assert_eq!(fs.query_file_object_information(handle).unwrap(), info);
                    if before.signal_file {
                        fs.zw_set_file_signaled(handle, true).unwrap();
                        table
                            .mark_delivery_exact(slot, id, IO_DELIVERY_FILE_PUBLISHED)
                            .unwrap();
                    }
                    reply_and_ack(&mut table, slot, id);
                    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
                    assert!(fs.query_file_object_information(handle).is_ok());
                    assert!(table.finish_exact(slot, id).is_none());
                    fs.zw_release_io_reference(handle).unwrap();
                    table.mark_local_reference_released_exact(slot, id).unwrap();
                    table.finish_exact(slot, id).unwrap();
                    assert_eq!(mutations, 1);
                    assert_eq!(fs.export_volume_snapshot().unwrap(), snapshot);
                    assert_eq!(
                        fs.query_file_object_information(handle),
                        Err(STATUS_INVALID_HANDLE)
                    );
                }
            }
        }
    }
}

#[test]
fn negative_signed_scalar_uses_fast_or_dispatched_error_timing_without_mutation() {
    for synchronous in [false, true] {
        for class in [
            FILE_POSITION_INFORMATION,
            FILE_ALLOCATION_INFORMATION,
            FILE_END_OF_FILE_INFORMATION,
        ] {
            for value in [-1i64, i64::MIN] {
                let (mut fs, handle) = file(synchronous);
                let before = fs.query_file_object_information(handle).unwrap();
                let policy = LocalSetInformationPolicy::capture(class, synchronous);
                let mut table = PendingFileIoTable::new();
                let reservation = if policy.resets_file_signal() {
                    let reservation = table.reserve().unwrap();
                    fs.zw_begin_file_io(handle).unwrap();
                    Some(reservation)
                } else {
                    None
                };
                let validation = validate_local_set_information_value(class, &value.to_le_bytes());
                assert_eq!(validation, Err(nt_status::NtStatus::INVALID_PARAMETER));
                assert_eq!(fs.query_file_object_information(handle).unwrap(), before);
                assert_eq!(
                    fs.zw_is_file_signaled(handle),
                    Ok(!policy.resets_file_signal())
                );
                assert_eq!(fs.file_bytes_owned(PATH).as_deref(), Some(&b"abcdef"[..]));
                if let Some(reservation) = reservation {
                    let id = table.local_operation_id(reservation).unwrap();
                    let pending = terminal(
                        id,
                        0xe700_0000_0000_0000 | handle,
                        policy,
                        nt_status::NtStatus::INVALID_PARAMETER.raw() as u32,
                    );
                    assert_eq!(pending.iosb_va, 0);
                    assert!(!pending.signal_file);
                    let slot = table.park_reserved(reservation, pending).unwrap();
                    reply_and_ack(&mut table, slot, id);
                    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
                    assert!(fs.query_file_object_information(handle).is_ok());
                    fs.zw_release_io_reference(handle).unwrap();
                    table.mark_local_reference_released_exact(slot, id).unwrap();
                    table.finish_exact(slot, id).unwrap();
                } else {
                    assert!(table.is_empty());
                    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
                }
                assert_eq!(
                    fs.query_file_object_information(handle),
                    Err(STATUS_INVALID_HANDLE)
                );
            }
        }
    }
}

#[test]
fn readonly_fast_position_retains_without_reset_or_signal_even_after_iosb_fault() {
    for signaled in [false, true] {
        let mut files = ReadOnlyFileOpenTable::<1>::new();
        let object = files
            .create(
                41,
                64,
                b"position.dat",
                FILE_READ_DATA,
                FILE_SHARE_READ,
                FILE_SYNCHRONOUS_IO_NONALERT,
                FileMetadata::default(),
                FatShortName::EMPTY,
            )
            .unwrap();
        files.set_signaled(object, signaled).unwrap();
        let policy = LocalSetInformationPolicy::capture(FILE_POSITION_INFORMATION, true);
        assert!(!policy.resets_file_signal());
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.local_operation_id(reservation).unwrap();
        let bytes = 53i64.to_le_bytes();
        validate_local_set_information_value(FILE_POSITION_INFORMATION, &bytes).unwrap();
        files.retain_io(object).unwrap();
        files.get_mut(object).unwrap().current_offset = u64::from_le_bytes(bytes);
        assert_eq!(files.is_signaled(object), Ok(signaled));
        let slot = table
            .park_reserved(
                reservation,
                terminal(
                    id,
                    0xe800_0000_0000_0000 | object as u64,
                    policy,
                    STATUS_SUCCESS,
                ),
            )
            .unwrap();
        files.release(object).unwrap();
        let mut memory = Memory::new();
        assert_eq!(
            memory.publish(
                table.get(slot).unwrap(),
                Some((1, MemoryCopyFailure::UserFault(AV)))
            ),
            Err(MemoryCopyFailure::UserFault(AV))
        );
        table.mark_iosb_faulted_exact(slot, id, IOSB).unwrap();
        assert!(!table.get(slot).unwrap().signal_file);
        assert_eq!(
            table.get(slot).unwrap().local_syscall_status(),
            Some(STATUS_SUCCESS)
        );
        reply_and_ack(&mut table, slot, id);
        assert_eq!(files.get(object).unwrap().current_offset, 53);
        assert_eq!(files.is_signaled(object), Ok(signaled));
        files.release_io(object).unwrap();
        table.mark_local_reference_released_exact(slot, id).unwrap();
        table.finish_exact(slot, id).unwrap();
        assert!(files.get(object).is_err());
    }
}

#[test]
fn abandoned_completed_rename_keeps_namespace_change_and_releases_exact_reference() {
    let (mut fs, handle) = file(false);
    let policy = LocalSetInformationPolicy::capture(FILE_RENAME_INFORMATION, false);
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    let id = table.local_operation_id(reservation).unwrap();
    fs.zw_begin_file_io(handle).unwrap();
    assert_eq!(
        fs.zw_set_information_file(
            handle,
            FILE_RENAME_INFORMATION,
            &payload(FILE_RENAME_INFORMATION)
        ),
        STATUS_SUCCESS
    );
    let slot = table
        .park_reserved(
            reservation,
            terminal(id, 0xe700_0000_0000_0000 | handle, policy, STATUS_SUCCESS),
        )
        .unwrap();
    let mut memory = Memory::new();
    assert_eq!(
        memory.publish(
            table.get(slot).unwrap(),
            Some((0, MemoryCopyFailure::Retry(AV)))
        ),
        Err(MemoryCopyFailure::Retry(AV))
    );
    let mut reply = None;
    assert_eq!(
        table.abandon_thread_transfers_with(TID, |owner| reply = Some(owner.reply_cap)),
        1
    );
    assert_eq!(reply, Some(REPLY));
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    table.mark_backend_acked_exact(slot, id).unwrap();
    assert!(table.finish_exact(slot, id).is_none());
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
    fs.zw_release_io_reference(handle).unwrap();
    table.mark_local_reference_released_exact(slot, id).unwrap();
    let retired = table.finish_exact(slot, id).unwrap();
    assert_eq!(retired.local_terminal_result(), Some((STATUS_SUCCESS, 0)));
    assert!(fs.file_bytes_owned(PATH).is_none());
    assert_eq!(
        fs.file_bytes_owned(RENAMED).as_deref(),
        Some(&b"abcdef"[..])
    );
}
