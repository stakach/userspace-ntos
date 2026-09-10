//! Typed IOSB publication composed with retained local I/O and a real filesystem reference.
//! The memory fixture supplies explicit copy outcomes; it does not execute native VM faults.

use nt_address_space::copy::MemoryCopyFailure;
use nt_address_space::native_output::publish_file_io_status_checked;
use nt_fs::*;
use nt_io_manager::*;

const ID: u64 = 0xf300_0000_0000_0001;
const FILE: u64 = 0xe300_0000_0000_0000;
const IOSB: u64 = 0x1000;
const REPLY: u64 = 71;
const APC: u64 = 0x2000;
const APC_CONTEXT: u64 = 0x3000;
const AV: u32 = 0xc000_0005;
const GUARD: u32 = 0x8000_0001;
const PATH: &str = r"\??\C:\iosb-owned";

struct Memory {
    bytes: [u8; 16],
    writes: Vec<(u64, usize)>,
    fail: Option<(usize, MemoryCopyFailure)>,
}

impl Memory {
    fn new(store: usize, failure: MemoryCopyFailure) -> Self {
        Self {
            bytes: [0xcc; 16],
            writes: Vec::new(),
            fail: Some((store, failure)),
        }
    }

    fn publish(&mut self, pending: PendingFileIo) -> Result<(), MemoryCopyFailure> {
        let (status, information) = pending.local_terminal_result().unwrap();
        publish_file_io_status_checked(pending.iosb_va, status, information, |address, bytes| {
            let index = self.writes.len();
            self.writes.push((address, bytes.len()));
            if let Some((store, failure)) = self.fail {
                if index == store {
                    return Err(failure);
                }
            }
            let offset = usize::try_from(address - IOSB).unwrap();
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        })
    }
}

fn fixture() -> (FileSystem, u64, PendingFileIoTable, usize) {
    let mut fs = FileSystem::new(MemFs::new());
    let opened = fs.zw_create_file(
        PATH,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    fs.zw_begin_file_io(opened.handle).unwrap();
    let result = fs.zw_write_file(opened.handle, Some(0), b"done");
    assert_eq!(result, (STATUS_SUCCESS, 4));
    let slot = table
        .park_reserved(
            reservation,
            PendingFileIo {
                file_id: FILE,
                irp_id: ID,
                tid: 70,
                major: nt_io_abi::major::IRP_MJ_WRITE,
                operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
                    status: result.0,
                    information: result.1 as u64,
                }),
                iosb_va: IOSB,
                apc_routine: APC,
                apc_context: APC_CONTEXT,
                signal_file: true,
                event_obj_idx: 72,
                reply_required: true,
                reply_cap: REPLY,
                ..PendingFileIo::default()
            },
        )
        .unwrap();
    (fs, opened.handle, table, slot)
}

fn assert_partial(memory: &Memory, failed_store: usize) {
    assert_eq!(memory.writes.first(), Some(&(IOSB + 8, 8)));
    assert_eq!(memory.writes.len(), failed_store + 1);
    assert_eq!(&memory.bytes[..8], &[0xcc; 8]);
    if failed_store == 0 {
        assert_eq!(&memory.bytes[8..], &[0xcc; 8]);
    } else {
        assert_eq!(memory.writes[1], (IOSB, 4));
        assert_eq!(&memory.bytes[8..], &4u64.to_le_bytes());
    }
}

fn finish_other_surfaces(
    fs: &mut FileSystem,
    handle: u64,
    table: &mut PendingFileIoTable,
    slot: usize,
) {
    let original = table.get(slot).unwrap();
    assert!(!table.completion_surfaces_settled_exact(slot, ID));
    assert!(table.mark_backend_acked_exact(slot, ID).is_none());
    assert!(table.finish_exact(slot, ID).is_none());
    assert_eq!(fs.zw_is_file_signaled(handle), Ok(false));
    table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_EVENT_PUBLISHED)
        .unwrap();
    assert!(!table.completion_surfaces_settled_exact(slot, ID));
    fs.zw_set_file_signaled(handle, true).unwrap();
    table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_FILE_PUBLISHED)
        .unwrap();
    assert!(!table.completion_surfaces_settled_exact(slot, ID));
    let for_apc = table.get(slot).unwrap();
    assert_eq!(
        (for_apc.apc_routine, for_apc.apc_context, for_apc.iosb_va),
        (APC, APC_CONTEXT, IOSB)
    );
    assert_eq!(for_apc.local_terminal_result(), Some((STATUS_SUCCESS, 4)));
    table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_APC_PUBLISHED)
        .unwrap();
    assert!(!table.completion_surfaces_settled_exact(slot, ID));
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(REPLY)));
    table.restore_reply_cap_exact(slot, ID, REPLY).unwrap();
    assert!(table.finish_exact(slot, ID).is_none());
    assert_eq!(table.claim_reply_cap_exact(slot, ID), Some(Some(REPLY)));
    table.mark_reply_published_exact(slot, ID).unwrap();
    assert!(table.completion_surfaces_settled_exact(slot, ID));
    table.mark_backend_acked_exact(slot, ID).unwrap();
    assert!(table.finish_exact(slot, ID).is_none());
    assert_eq!(fs.file_bytes(PATH), Some(&b"done"[..]));
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert!(fs.query_file_object_information(handle).is_ok());
    assert!(table
        .mark_local_reference_released_exact(slot, ID + 1)
        .is_none());
    assert!(table.finish_exact(slot, ID).is_none());
    fs.zw_release_io_reference(handle).unwrap();
    table.mark_local_reference_released_exact(slot, ID).unwrap();
    let retired = table.finish_exact(slot, ID).unwrap();
    assert_eq!(
        retired.local_terminal_result(),
        original.local_terminal_result()
    );
    assert_eq!(retired.iosb_va, original.iosb_va);
    assert_eq!(
        fs.query_file_object_information(handle),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(fs.file_bytes(PATH), Some(&b"done"[..]));
}

#[test]
fn same_access_violation_retries_or_settles_according_to_typed_copy_failure() {
    for failed_store in [0, 1] {
        for retryable in [true, false] {
            let (mut fs, handle, mut table, slot) = fixture();
            let before = table.get(slot).unwrap();
            let failure = if retryable {
                MemoryCopyFailure::Retry(AV)
            } else {
                MemoryCopyFailure::UserFault(AV)
            };
            let mut memory = Memory::new(failed_store, failure);
            assert_eq!(memory.publish(before), Err(failure));
            assert_partial(&memory, failed_store);
            assert_eq!(table.get(slot), Some(before));
            assert_eq!(fs.file_bytes(PATH), Some(&b"done"[..]));
            if retryable {
                // The status number cannot settle this failure: transport/admission may recover.
                assert!(!table.completion_surfaces_settled_exact(slot, ID));
                assert!(table.mark_backend_acked_exact(slot, ID).is_none());
                assert!(table.finish_exact(slot, ID).is_none());
                assert_eq!(table.get(slot), Some(before));
                memory.fail = None;
                assert_eq!(memory.publish(before), Ok(()));
                table
                    .mark_delivery_exact(slot, ID, IO_DELIVERY_IOSB_PUBLISHED)
                    .unwrap();
                assert_eq!(&memory.bytes[..4], &STATUS_SUCCESS.to_le_bytes());
                assert_eq!(&memory.bytes[4..8], &[0xcc; 4]);
                assert_eq!(&memory.bytes[8..], &4u64.to_le_bytes());
                assert_eq!(
                    table.get(slot).unwrap().delivery_state & IO_DELIVERY_IOSB_FAULTED,
                    0
                );
                assert!(table.mark_iosb_faulted_exact(slot, ID, IOSB).is_none());
            } else {
                table.mark_iosb_faulted_exact(slot, ID, IOSB).unwrap();
                let faulted = table.get(slot).unwrap();
                assert_eq!(
                    faulted.delivery_state & IO_DELIVERY_IOSB_FAULTED,
                    IO_DELIVERY_IOSB_FAULTED
                );
                assert_eq!(faulted.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
                assert_eq!(
                    faulted.local_terminal_result(),
                    before.local_terminal_result()
                );
                assert_eq!(faulted.iosb_va, IOSB);
                assert!(table
                    .mark_delivery_exact(slot, ID, IO_DELIVERY_IOSB_PUBLISHED)
                    .is_none());
                assert_partial(&memory, failed_store);
            }
            finish_other_surfaces(&mut fs, handle, &mut table, slot);
        }
    }
}

#[test]
fn permanent_guard_fault_does_not_claim_iosb_publication_or_replace_terminal_result() {
    for failed_store in [0, 1] {
        let (mut fs, handle, mut table, slot) = fixture();
        let mut memory = Memory::new(failed_store, MemoryCopyFailure::UserFault(GUARD));
        assert_eq!(
            memory.publish(table.get(slot).unwrap()),
            Err(MemoryCopyFailure::UserFault(GUARD))
        );
        assert_partial(&memory, failed_store);
        table.mark_iosb_faulted_exact(slot, ID, IOSB).unwrap();
        let faulted = table.get(slot).unwrap();
        assert_eq!(faulted.local_terminal_result(), Some((STATUS_SUCCESS, 4)));
        assert_eq!(faulted.delivery_state & IO_DELIVERY_IOSB_PUBLISHED, 0);
        assert!(table.mark_iosb_faulted_exact(slot, ID, IOSB).is_none());
        finish_other_surfaces(&mut fs, handle, &mut table, slot);
        assert_partial(&memory, failed_store);
    }
}

#[test]
fn iosb_fault_settlement_requires_exact_owner_and_destination() {
    let (mut fs, handle, mut table, slot) = fixture();
    let before = table.get(slot).unwrap();
    let mut memory = Memory::new(0, MemoryCopyFailure::UserFault(AV));
    assert_eq!(
        memory.publish(before),
        Err(MemoryCopyFailure::UserFault(AV))
    );
    for (request, destination) in [(ID + 1, IOSB), (ID, 0), (ID, IOSB + 8)] {
        assert!(table
            .mark_iosb_faulted_exact(slot, request, destination)
            .is_none());
        assert_eq!(table.get(slot), Some(before));
    }
    assert!(table
        .mark_delivery_exact(slot, ID, IO_DELIVERY_IOSB_FAULTED)
        .is_none());
    assert_eq!(table.get(slot), Some(before));
    table.mark_iosb_faulted_exact(slot, ID, IOSB).unwrap();
    finish_other_surfaces(&mut fs, handle, &mut table, slot);
}
