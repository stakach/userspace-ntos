//! Retained buffered-output composition with real local filesystem effects. The memory fixture
//! injects typed copy outcomes at page boundaries; it does not execute native VM faults.

use nt_address_space::copy::MemoryCopyFailure;
use nt_fs::*;
use nt_io_manager::*;

const FILE: u64 = 0xe400_0000_0000_0000;
const OUTPUT: u64 = 0x1ffc;
const IOSB: u64 = 0x9000;
const REPLY: u64 = 81;
const AV: u32 = 0xc000_0005;
const GUARD: u32 = 0x8000_0001;
const PAGE: usize = 4096;
const READ_PATH: &str = r"\??\C:\buffered-read";

fn terminal(
    id: u64,
    major: u8,
    requested: usize,
    status: u32,
    information: usize,
) -> PendingFileIo {
    PendingFileIo {
        file_id: FILE,
        irp_id: id,
        tid: 80,
        major,
        operation: PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
            status,
            information: information as u64,
        }),
        output_va: OUTPUT,
        output_len: requested as u32,
        iosb_va: IOSB,
        apc_routine: 0xa000,
        apc_context: 0xb000,
        event_obj_idx: 82,
        signal_file: true,
        reply_required: true,
        reply_cap: REPLY,
        ..PendingFileIo::default()
    }
}

struct Memory {
    bytes: Vec<u8>,
    attempts: Vec<(usize, usize)>,
}

impl Memory {
    fn new(length: usize) -> Self {
        Self {
            bytes: vec![0xcc; length],
            attempts: Vec::new(),
        }
    }

    fn copy(
        &mut self,
        table: &mut PendingFileIoTable,
        slot: usize,
        id: u64,
        failure: Option<(usize, MemoryCopyFailure)>,
    ) -> Result<(), MemoryCopyFailure> {
        loop {
            let pending = table.get(slot).unwrap();
            let terminal_length = pending.local_terminal_result().unwrap().1 as usize;
            let offset = pending.output_offset as usize;
            if offset == terminal_length {
                return Ok(());
            }
            let destination = pending.output_va + offset as u64;
            let chunk_length = (PAGE - destination as usize % PAGE).min(terminal_length - offset);
            let mut chunk = [0; PAGE];
            assert_eq!(
                table.copy_local_output_bytes_exact(slot, id, offset, &mut chunk[..chunk_length]),
                Ok(chunk_length)
            );
            self.attempts.push((offset, chunk_length));
            if let Some((failed_offset, outcome)) = failure {
                if offset == failed_offset {
                    return Err(outcome);
                }
            }
            self.bytes[offset..offset + chunk_length].copy_from_slice(&chunk[..chunk_length]);
            table
                .advance_output_exact(slot, id, chunk_length as u32, terminal_length as u32)
                .unwrap();
        }
    }
}

fn admitted_read() -> (FileSystem, u64, PendingFileIoTable, usize, u64, Vec<u8>) {
    let bytes: Vec<u8> = (0..5000).map(|index| (index % 251) as u8).collect();
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(READ_PATH, &bytes));
    let opened = fs.zw_create_file(
        READ_PATH,
        FILE_READ_DATA | SYNCHRONIZE,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    let id = table.local_operation_id(reservation).unwrap();
    table
        .reserve_local_output(reservation, bytes.len())
        .unwrap();
    fs.zw_begin_file_io(opened.handle).unwrap();
    fs.set_current_time_100ns(100);
    let (status, information) = fs.read_backing_into(
        opened.handle,
        0,
        table.reserved_local_output_mut(reservation).unwrap(),
    );
    assert_eq!((status, information), (STATUS_SUCCESS, bytes.len()));
    assert_eq!(
        fs.complete_read(opened.handle, information, Some(information as u64)),
        STATUS_SUCCESS
    );
    let slot = table
        .park_reserved(
            reservation,
            terminal(
                id,
                nt_io_abi::major::IRP_MJ_READ,
                bytes.len(),
                status,
                information,
            ),
        )
        .unwrap();
    (fs, opened.handle, table, slot, id, bytes)
}

fn finish(fs: &mut FileSystem, handle: u64, table: &mut PendingFileIoTable, slot: usize, id: u64) {
    let pending = table.get(slot).unwrap();
    assert!(!table.completion_surfaces_settled_exact(slot, id));
    assert!(table.mark_backend_acked_exact(slot, id).is_none());
    for (required, flag) in [
        (pending.iosb_va != 0, IO_DELIVERY_IOSB_PUBLISHED),
        (
            pending.event_obj_idx != u64::MAX,
            IO_DELIVERY_EVENT_PUBLISHED,
        ),
        (pending.apc_routine != 0, IO_DELIVERY_APC_PUBLISHED),
    ] {
        if required {
            let before = table.get(slot);
            assert!(table.finish_exact(slot, id).is_none());
            assert_eq!(table.get(slot), before);
            table.mark_delivery_exact(slot, id, flag).unwrap();
        }
    }
    if pending.signal_file {
        fs.zw_set_file_signaled(handle, true).unwrap();
        table
            .mark_delivery_exact(slot, id, IO_DELIVERY_FILE_PUBLISHED)
            .unwrap();
    }
    assert!(!table.completion_surfaces_settled_exact(slot, id));
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(REPLY)));
    table.restore_reply_cap_exact(slot, id, REPLY).unwrap();
    assert!(table.finish_exact(slot, id).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, id), Some(Some(REPLY)));
    table.mark_reply_published_exact(slot, id).unwrap();
    assert!(table.completion_surfaces_settled_exact(slot, id));
    table.mark_backend_acked_exact(slot, id).unwrap();
    assert!(table.finish_exact(slot, id).is_none());
    fs.zw_release_io_reference(handle).unwrap();
    table.mark_local_reference_released_exact(slot, id).unwrap();
    let retired = table.finish_exact(slot, id).unwrap();
    assert_eq!(
        retired.local_terminal_result(),
        pending.local_terminal_result()
    );
    assert!(table.get(slot).is_none());
}

#[test]
fn closed_file_read_retains_accepted_bytes_and_retries_only_the_uncopied_suffix() {
    let (mut fs, handle, mut table, slot, id, original) = admitted_read();
    let accepted = fs.query_file_object_information(handle).unwrap();
    assert_eq!(accepted.current_offset, original.len() as u64);
    assert_eq!(accepted.metadata.last_access_time, 100);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
    let mut memory = Memory::new(original.len());
    assert_eq!(
        memory.copy(
            &mut table,
            slot,
            id,
            Some((4, MemoryCopyFailure::Retry(AV)))
        ),
        Err(MemoryCopyFailure::Retry(AV))
    );
    let retry = table.get(slot).unwrap();
    assert_eq!(retry.output_offset, 4);
    assert_eq!(
        retry.local_terminal_result(),
        Some((STATUS_SUCCESS, original.len() as u64))
    );
    assert_eq!(
        retry.delivery_state & (IO_DELIVERY_BUFFER_PUBLISHED | IO_DELIVERY_OUTPUT_FAULTED),
        0
    );
    let mut retained = vec![0; original.len()];
    assert_eq!(
        table.copy_local_output_bytes_exact(slot, id, 0, &mut retained),
        Ok(original.len())
    );
    assert_eq!(retained, original);
    fs.set_current_time_100ns(999);
    assert!(table.finish_exact(slot, id).is_none());
    assert_eq!(table.get(slot), Some(retry));
    assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
    assert_eq!(memory.copy(&mut table, slot, id, None), Ok(()));
    assert_eq!(
        memory.attempts,
        [(0, 4), (4, PAGE), (4, PAGE), (PAGE + 4, 900)]
    );
    assert_eq!(memory.bytes, original);
    assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
    finish(&mut fs, handle, &mut table, slot, id);
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(fs.file_bytes(READ_PATH), Some(original.as_slice()));
}

#[test]
fn permanent_read_copy_fault_preserves_transfer_information_and_filesystem_effects() {
    for status in [AV, GUARD] {
        let (mut fs, handle, mut table, slot, id, original) = admitted_read();
        let accepted = fs.query_file_object_information(handle).unwrap();
        let mut memory = Memory::new(original.len());
        assert_eq!(
            memory.copy(
                &mut table,
                slot,
                id,
                Some((4, MemoryCopyFailure::UserFault(status)))
            ),
            Err(MemoryCopyFailure::UserFault(status))
        );
        table
            .settle_local_output_fault_exact(slot, id, OUTPUT, status)
            .unwrap();
        let faulted = table.get(slot).unwrap();
        assert_eq!(faulted.output_offset, 4);
        assert_eq!(
            faulted.local_terminal_result(),
            Some((status, original.len() as u64))
        );
        assert_eq!(faulted.delivery_state & IO_DELIVERY_BUFFER_PUBLISHED, 0);
        assert_ne!(faulted.delivery_state & IO_DELIVERY_OUTPUT_FAULTED, 0);
        assert!(table
            .advance_output_exact(slot, id, 1, original.len() as u32)
            .is_none());
        if status == AV {
            assert_eq!(
                (faulted.iosb_va, faulted.apc_routine, faulted.event_obj_idx),
                (0, 0, u64::MAX)
            );
            assert!(!faulted.signal_file);
        } else {
            assert_eq!(faulted.iosb_va, IOSB);
            assert_ne!(faulted.apc_routine, 0);
            assert_eq!(faulted.event_obj_idx, 82);
            assert!(faulted.signal_file);
        }
        assert_eq!(&memory.bytes[..4], &original[..4]);
        assert!(memory.bytes[4..].iter().all(|byte| *byte == 0xcc));
        assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
        finish(&mut fs, handle, &mut table, slot, id);
        assert_eq!(fs.zw_is_file_signaled(handle), Ok(status == GUARD));
        assert_eq!(fs.query_file_object_information(handle).unwrap(), accepted);
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    }
}

fn directory_name(bytes: &[u8], count: usize) -> String {
    let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    assert_eq!(count, 12 + length);
    String::from_utf16(
        &bytes[12..count]
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn directory_copy_retry_or_permanent_fault_never_repeats_accepted_enumeration() {
    for permanent in [false, true] {
        let mut fs = FileSystem::new(MemFs::new());
        assert!(fs.provision_file(r"\??\C:\buffered-dir\alpha.txt", b"a"));
        assert!(fs.provision_file(r"\??\C:\buffered-dir\bravo.txt", b"b"));
        let opened = fs.zw_create_file(
            r"\??\C:\buffered-dir",
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        );
        assert_eq!(opened.status, STATUS_SUCCESS);
        let handle = opened.handle;
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.local_operation_id(reservation).unwrap();
        table.reserve_local_output(reservation, 256).unwrap();
        fs.zw_begin_file_io(handle).unwrap();
        let pattern: Vec<u16> = "*.txt".encode_utf16().collect();
        let result = fs.zw_query_directory_file(
            handle,
            FILE_NAMES_INFORMATION,
            true,
            Some(&pattern),
            false,
            table.reserved_local_output_mut(reservation).unwrap(),
        );
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(
            directory_name(
                table.reserved_local_output_mut(reservation).unwrap(),
                result.information
            ),
            "alpha.txt"
        );
        let slot = table
            .park_reserved(
                reservation,
                terminal(
                    id,
                    nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
                    256,
                    result.status,
                    result.information,
                ),
            )
            .unwrap();
        let failure = if permanent {
            MemoryCopyFailure::UserFault(AV)
        } else {
            MemoryCopyFailure::Retry(AV)
        };
        let mut memory = Memory::new(256);
        assert_eq!(
            memory.copy(&mut table, slot, id, Some((4, failure))),
            Err(failure)
        );
        let stopped = table.get(slot).unwrap();
        assert_eq!(stopped.output_offset, 4);
        assert_eq!(
            stopped.local_terminal_result(),
            Some((STATUS_SUCCESS, result.information as u64))
        );
        if permanent {
            table
                .settle_local_output_fault_exact(slot, id, OUTPUT, AV)
                .unwrap();
        } else {
            assert!(table.mark_backend_acked_exact(slot, id).is_none());
            assert_eq!(table.get(slot), Some(stopped));
            assert_eq!(memory.copy(&mut table, slot, id, None), Ok(()));
            assert_eq!(
                directory_name(&memory.bytes, result.information),
                "alpha.txt"
            );
            assert_eq!(
                memory.attempts,
                [
                    (0, 4),
                    (4, result.information - 4),
                    (4, result.information - 4)
                ]
            );
        }
        assert!(memory.bytes[result.information..]
            .iter()
            .all(|byte| *byte == 0xcc));
        finish(&mut fs, handle, &mut table, slot, id);
        let mut next = [0; 256];
        let result = fs.zw_query_directory_file(
            handle,
            FILE_NAMES_INFORMATION,
            true,
            None,
            false,
            &mut next,
        );
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(directory_name(&next, result.information), "bravo.txt");
        assert_eq!(
            fs.zw_query_directory_file(
                handle,
                FILE_NAMES_INFORMATION,
                true,
                None,
                false,
                &mut next
            )
            .status,
            STATUS_NO_MORE_FILES
        );
        assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    }
}
