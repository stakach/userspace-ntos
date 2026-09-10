//! Bounded readonly source completion and retained user delivery with real FILE_OBJECT tables.
//! Source bytes and typed memory failures are explicit host fixtures, not FAT disk or boot proof.

use nt_address_space::copy::MemoryCopyFailure;
use nt_fs::*;
use nt_io_manager::*;

const OUTPUT: u64 = 0x1ffc;
const IOSB: u64 = 0x9000;
const REPLY: u64 = 91;
const FILE: u64 = 0xe500_0000_0000_0000;
const INITIAL_POSITION: u64 = 17;
const AV: u32 = 0xc000_0005;
const GUARD: u32 = 0x8000_0001;
const IO_ERROR: u32 = 0xc000_0185;

struct Source {
    bytes: Vec<u8>,
    calls: usize,
    short: bool,
}

impl Source {
    fn new(length: usize) -> Self {
        Self {
            bytes: (0..length).map(|index| (index % 251) as u8).collect(),
            calls: 0,
            short: false,
        }
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> usize {
        self.calls += 1;
        assert!(!output.is_empty());
        let count = output.len() - usize::from(self.short);
        output[..count].copy_from_slice(&self.bytes[offset as usize..offset as usize + count]);
        count
    }
}

struct Work {
    files: ReadOnlyFileOpenTable<2>,
    object: u32,
    table: PendingFileIoTable,
    slot: usize,
    id: u64,
    transfer_length: usize,
}

impl Work {
    fn prepare(source: &mut Source, offset: u64, requested: usize, synchronous: bool) -> Self {
        let mut files = ReadOnlyFileOpenTable::new();
        let object = files
            .create(
                41,
                source.bytes.len() as u32,
                b"readonly.dat",
                FILE_READ_DATA | SYNCHRONIZE,
                FILE_SHARE_READ,
                if synchronous {
                    FILE_SYNCHRONOUS_IO_NONALERT
                } else {
                    0
                },
                FileMetadata {
                    file_id: 42,
                    end_of_file: source.bytes.len() as u64,
                    ..FileMetadata::default()
                },
                FatShortName::EMPTY,
            )
            .unwrap();
        files.get_mut(object).unwrap().current_offset = INITIAL_POSITION;
        let resolved =
            resolve_regular_file_read_offset(Some(offset as i64), synchronous, INITIAL_POSITION)
                .unwrap();
        let plan =
            BoundedFileReadPlan::new(resolved, source.bytes.len() as u64, requested).unwrap();
        let transfer_length = plan.transfer_len();
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.local_operation_id(reservation).unwrap();
        table
            .reserve_local_output(reservation, transfer_length)
            .unwrap();
        files.retain_io(object).unwrap();
        files.set_signaled(object, false).unwrap();
        let source_count = if transfer_length == 0 {
            0
        } else {
            source.read(
                plan.offset(),
                table.reserved_local_output_mut(reservation).unwrap(),
            )
        };
        let completion = plan.complete(synchronous, source_count).unwrap();
        if let Some(position) = completion.position {
            files.get_mut(object).unwrap().current_offset = position;
        }
        let publish =
            nt_io_completion::file_io_status_publishes_completion(completion.status, true);
        let slot = table
            .park_reserved(
                reservation,
                PendingFileIo {
                    file_id: FILE | object as u64,
                    irp_id: id,
                    tid: 90,
                    major: nt_io_abi::major::IRP_MJ_READ,
                    operation: PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
                        status: completion.status,
                        information: completion.information as u64,
                    }),
                    output_va: OUTPUT,
                    output_len: transfer_length as u32,
                    iosb_va: if publish { IOSB } else { 0 },
                    apc_routine: if publish { 0xa000 } else { 0 },
                    event_obj_idx: if publish { 92 } else { u64::MAX },
                    signal_file: publish && synchronous,
                    reply_required: true,
                    reply_cap: REPLY,
                    ..PendingFileIo::default()
                },
            )
            .unwrap();
        Self {
            files,
            object,
            table,
            slot,
            id,
            transfer_length,
        }
    }

    fn pending(&self) -> PendingFileIo {
        self.table.get(self.slot).unwrap()
    }

    fn position(&self) -> u64 {
        self.files.get(self.object).unwrap().current_offset
    }

    fn finish(&mut self) {
        let pending = self.pending();
        if pending.local_terminal_result().unwrap().1 == 0 {
            self.table
                .advance_output_exact(self.slot, self.id, 0, 0)
                .unwrap();
        }
        for (required, flag) in [
            (pending.iosb_va != 0, IO_DELIVERY_IOSB_PUBLISHED),
            (
                pending.event_obj_idx != u64::MAX,
                IO_DELIVERY_EVENT_PUBLISHED,
            ),
            (pending.apc_routine != 0, IO_DELIVERY_APC_PUBLISHED),
        ] {
            if required {
                self.table
                    .mark_delivery_exact(self.slot, self.id, flag)
                    .unwrap();
            }
        }
        if pending.signal_file {
            self.files.set_signaled(self.object, true).unwrap();
            self.table
                .mark_delivery_exact(self.slot, self.id, IO_DELIVERY_FILE_PUBLISHED)
                .unwrap();
        }
        assert_eq!(
            self.table.claim_reply_cap_exact(self.slot, self.id),
            Some(Some(REPLY))
        );
        self.table
            .restore_reply_cap_exact(self.slot, self.id, REPLY)
            .unwrap();
        assert!(self.table.finish_exact(self.slot, self.id).is_none());
        assert_eq!(
            self.table.claim_reply_cap_exact(self.slot, self.id),
            Some(Some(REPLY))
        );
        self.table
            .mark_reply_published_exact(self.slot, self.id)
            .unwrap();
        self.table
            .mark_backend_acked_exact(self.slot, self.id)
            .unwrap();
        assert!(self.table.finish_exact(self.slot, self.id).is_none());
        self.files.release_io(self.object).unwrap();
        self.table
            .mark_local_reference_released_exact(self.slot, self.id)
            .unwrap();
        let retired = self.table.finish_exact(self.slot, self.id).unwrap();
        assert_eq!(
            retired.local_terminal_result(),
            pending.local_terminal_result()
        );
    }
}

fn copy(
    work: &mut Work,
    memory: &mut [u8],
    attempts: &mut Vec<usize>,
    failure: Option<MemoryCopyFailure>,
) -> Result<(), MemoryCopyFailure> {
    let information = work.pending().local_terminal_result().unwrap().1 as usize;
    loop {
        let offset = work.pending().output_offset as usize;
        if offset == information {
            return Ok(());
        }
        let count = (4096 - (OUTPUT as usize + offset) % 4096).min(information - offset);
        let mut bytes = [0; 4096];
        assert_eq!(
            work.table.copy_local_output_bytes_exact(
                work.slot,
                work.id,
                offset,
                &mut bytes[..count]
            ),
            Ok(count)
        );
        attempts.push(offset);
        if offset == 4 {
            if let Some(failure) = failure {
                return Err(failure);
            }
        }
        memory[offset..offset + count].copy_from_slice(&bytes[..count]);
        work.table
            .advance_output_exact(work.slot, work.id, count as u32, information as u32)
            .unwrap();
    }
}

#[test]
fn large_read_is_accepted_once_and_survives_close_and_typed_copy_retry() {
    let mut source = Source::new(128 * 1024);
    let expected = source.bytes[31..31 + 96 * 1024].to_vec();
    let mut work = Work::prepare(&mut source, 31, expected.len(), true);
    assert_eq!(source.calls, 1);
    assert_eq!(work.transfer_length, expected.len());
    assert!(work.transfer_length > 64 * 1024);
    assert_eq!(work.position(), 31 + expected.len() as u64);
    work.files.release(work.object).unwrap();
    assert!(work.files.get(work.object).is_ok());
    let mut memory = vec![0xcc; expected.len()];
    let mut attempts = Vec::new();
    assert_eq!(
        copy(
            &mut work,
            &mut memory,
            &mut attempts,
            Some(MemoryCopyFailure::Retry(AV))
        ),
        Err(MemoryCopyFailure::Retry(AV))
    );
    let retry = work.pending();
    assert_eq!(retry.output_offset, 4);
    assert_eq!(
        retry.local_terminal_result(),
        Some((STATUS_SUCCESS, expected.len() as u64))
    );
    source.bytes.fill(0xff);
    assert!(work.table.finish_exact(work.slot, work.id).is_none());
    assert_eq!(work.pending(), retry);
    assert_eq!(copy(&mut work, &mut memory, &mut attempts, None), Ok(()));
    assert_eq!(&attempts[..3], &[0, 4, 4]);
    assert_eq!(memory, expected);
    assert_eq!(source.calls, 1);
    assert_eq!(work.position(), 31 + expected.len() as u64);
    work.finish();
    assert!(work.files.get(work.object).is_err());
    assert_eq!(source.calls, 1);
}

#[test]
fn extent_truncation_and_permanent_copy_fault_preserve_sync_and_async_positions() {
    for synchronous in [false, true] {
        for failure in [None, Some(AV), Some(GUARD)] {
            let mut source = Source::new(116);
            let expected = source.bytes[100..].to_vec();
            let mut work = Work::prepare(&mut source, 100, 100 * 1024, synchronous);
            assert_eq!(work.transfer_length, 16);
            assert_eq!(
                work.pending().local_terminal_result(),
                Some((STATUS_SUCCESS, 16))
            );
            let position = if synchronous { 116 } else { INITIAL_POSITION };
            assert_eq!(work.position(), position);
            let mut memory = vec![0xcc; 100 * 1024];
            let mut attempts = Vec::new();
            let result = copy(
                &mut work,
                &mut memory,
                &mut attempts,
                failure.map(MemoryCopyFailure::UserFault),
            );
            if let Some(status) = failure {
                assert_eq!(result, Err(MemoryCopyFailure::UserFault(status)));
                work.table
                    .settle_local_output_fault_exact(work.slot, work.id, OUTPUT, status)
                    .unwrap();
                let terminal = work.pending();
                assert_eq!(terminal.local_terminal_result(), Some((status, 16)));
                assert_eq!(terminal.output_offset, 4);
                assert_eq!(terminal.delivery_state & IO_DELIVERY_BUFFER_PUBLISHED, 0);
                assert_eq!(&memory[..4], &expected[..4]);
                assert!(memory[4..].iter().all(|byte| *byte == 0xcc));
                if status == AV {
                    assert_eq!(
                        (
                            terminal.iosb_va,
                            terminal.apc_routine,
                            terminal.event_obj_idx
                        ),
                        (0, 0, u64::MAX)
                    );
                    assert!(!terminal.signal_file);
                } else {
                    assert_eq!(terminal.iosb_va, IOSB);
                    assert_ne!(terminal.apc_routine, 0);
                    assert_eq!(terminal.signal_file, synchronous);
                }
            } else {
                assert_eq!(result, Ok(()));
                assert_eq!(&memory[..16], expected.as_slice());
                assert!(memory[16..].iter().all(|byte| *byte == 0xcc));
            }
            assert_eq!(source.calls, 1);
            assert_eq!(work.position(), position);
            work.finish();
            assert_eq!(work.position(), position);
            work.files.release(work.object).unwrap();
        }
    }
}

#[test]
fn zero_length_and_nonempty_eof_never_call_the_source_or_narrow_the_offset() {
    for synchronous in [false, true] {
        for (offset, requested) in [
            (5, 0),
            (64, 8),
            (u64::from(u32::MAX) + 9, 8),
            (u64::from(u32::MAX) + 9, 0),
        ] {
            let mut source = Source::new(64);
            let mut work = Work::prepare(&mut source, offset, requested, synchronous);
            assert_eq!(source.calls, 0);
            assert_eq!(work.transfer_length, 0);
            assert_eq!(
                work.pending().local_terminal_result(),
                Some((
                    if requested == 0 {
                        STATUS_SUCCESS
                    } else {
                        STATUS_END_OF_FILE
                    },
                    0
                ))
            );
            let position = if synchronous && requested != 0 {
                offset
            } else {
                INITIAL_POSITION
            };
            assert_eq!(work.position(), position);
            work.finish();
            assert_eq!(source.calls, 0);
            assert_eq!(work.position(), position);
            work.files.release(work.object).unwrap();
        }
    }
}

#[test]
fn short_source_is_not_accepted_as_partial_success_or_a_position_update() {
    for synchronous in [false, true] {
        let mut source = Source::new(128);
        source.short = true;
        let mut work = Work::prepare(&mut source, 31, 64, synchronous);
        assert_eq!(source.calls, 1);
        assert_eq!(work.transfer_length, 64);
        assert_eq!(work.pending().local_terminal_result(), Some((IO_ERROR, 0)));
        assert_eq!(work.position(), INITIAL_POSITION);
        let mut forbidden = [0xcc; 1];
        assert!(work
            .table
            .copy_local_output_bytes_exact(work.slot, work.id, 0, &mut forbidden)
            .is_err());
        assert_eq!(forbidden, [0xcc]);
        assert_eq!(
            (
                work.pending().iosb_va,
                work.pending().apc_routine,
                work.pending().event_obj_idx
            ),
            (0, 0, u64::MAX)
        );
        assert!(!work.pending().signal_file);
        work.finish();
        assert_eq!(work.files.is_signaled(work.object), Ok(false));
        assert_eq!(work.position(), INITIAL_POSITION);
        assert_eq!(source.calls, 1);
        work.files.release(work.object).unwrap();
    }
}
