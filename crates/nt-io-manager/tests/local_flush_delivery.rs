//! Real dirty-section writeback composed with retained local flush delivery. Frames are supplied
//! by a host fixture and barrier/copy failures are injected explicitly, not native fault proof.

use nt_address_space::copy::MemoryCopyFailure;
use nt_address_space::native_output::publish_file_io_status_checked;
use nt_fs::*;
use nt_io_manager::*;
use nt_memory_manager::writeback::{SectionPageAlias, SectionWritebackIo, SectionWritebackPage};
use nt_memory_manager::{
    GenericSectionBacking, GenericSectionTable, SectionFileIdentity, SectionMountIds,
};

const PATH: &str = r"\??\C:\flush-owned";
const IOSB: u64 = 0x1000;
const REPLY: u64 = 101;
const TID: u64 = 100;
const AV: u32 = 0xc000_0005;
const GUARD: u32 = 0x8000_0001;
const IO_ERROR: u32 = 0xc000_0185;
const WARNING: u32 = 0x8000_0005;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Effects {
    writes: usize,
    persists: usize,
}

struct FsIo<'a> {
    fs: &'a mut FileSystem,
    file: u64,
    effects: &'a mut Effects,
    barrier_status: u32,
}

impl SectionWritebackIo for FsIo<'_> {
    fn rearm_alias(&mut self, _: SectionPageAlias) -> Result<(), u32> {
        panic!("fixture has no mapped aliases");
    }
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        self.effects.writes += 1;
        let frame_bytes = [page.frame as u8; 4096];
        self.fs.zw_write_file(
            self.file,
            Some(page.file_offset),
            &frame_bytes[..page.length],
        )
    }
    fn persist(&mut self) -> u32 {
        self.effects.persists += 1;
        assert_eq!(self.fs.zw_flush_buffers_file(self.file), STATUS_SUCCESS);
        // Explicit external barrier-result injection, after real in-memory filesystem writeback.
        self.barrier_status
    }
}

struct Work {
    fs: FileSystem,
    handle: u64,
    _sections: GenericSectionTable,
    effects: Effects,
    table: PendingFileIoTable,
    slot: usize,
    id: u64,
}

impl Work {
    fn new(mode: LocalFlushMode, status: u32) -> Self {
        let mut fs = FileSystem::new(MemFs::new());
        let opened = fs.zw_create_file(
            PATH,
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE
                | if mode == LocalFlushMode::SynchronousFile {
                    FILE_SYNCHRONOUS_IO_NONALERT
                } else {
                    0
                },
        );
        assert_eq!(opened.status, STATUS_SUCCESS);
        assert_eq!(
            fs.zw_set_information_file(
                opened.handle,
                FILE_END_OF_FILE_INFORMATION,
                &4096u64.to_le_bytes()
            ),
            STATUS_SUCCESS
        );
        let identity = SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id: fs.zw_query_metadata(opened.handle).unwrap().file_id,
        };
        let backing = GenericSectionBacking::overlay(opened.handle, identity, 4096);
        let mut sections = GenericSectionTable::new();
        let section = sections
            .create(
                1,
                opened.handle,
                4096,
                nt_memory_manager::PAGE_READWRITE,
                nt_memory_manager::SECTION_ATTR_SEC_COMMIT,
                backing,
            )
            .unwrap();
        assert!(sections.set_page_frame(section, 0, 0x5a));
        assert!(sections.mark_page_dirty(section, 0));
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.local_operation_id(reservation).unwrap();
        fs.zw_begin_file_io(opened.handle).unwrap();
        let mut effects = Effects::default();
        let result = sections.writeback_file(
            backing,
            &mut FsIo {
                fs: &mut fs,
                file: opened.handle,
                effects: &mut effects,
                barrier_status: status,
            },
        );
        assert_eq!(result.status, status);
        assert_eq!(result.bytes_written, 4096);
        assert_eq!(
            effects,
            Effects {
                writes: 1,
                persists: 1
            }
        );
        assert_eq!(
            fs.file_bytes_owned(PATH).as_deref(),
            Some(&[0x5a; 4096][..])
        );
        let flush = PendingLocalFlush::new(result.status, mode).unwrap();
        let slot = table
            .park_reserved(
                reservation,
                PendingFileIo {
                    route: PendingFileRoute::Local(LocalFileObject::Overlay(opened.handle)),
                    irp_id: id,
                    tid: TID,
                    major: nt_io_abi::major::IRP_MJ_FLUSH_BUFFERS,
                    operation: PendingFileIoOperation::LocalFlush(flush),
                    iosb_va: if flush.publishes_iosb() { IOSB } else { 0 },
                    signal_file: flush.signals_file(),
                    completion_port_suppressed: true,
                    event_obj_idx: u64::MAX,
                    reply_required: true,
                    reply_cap: REPLY,
                    ..PendingFileIo::default()
                },
            )
            .unwrap();
        Self {
            fs,
            handle: opened.handle,
            _sections: sections,
            effects,
            table,
            slot,
            id,
        }
    }

    fn pending(&self) -> PendingFileIo {
        self.table.get(self.slot).unwrap()
    }

    fn finish(&mut self) {
        let before = self.pending();
        if before.signal_file {
            self.fs.zw_set_file_signaled(self.handle, true).unwrap();
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
        assert_eq!(
            self.pending().local_syscall_status(),
            before.local_syscall_status()
        );
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
        self.fs.zw_release_io_reference(self.handle).unwrap();
        self.table
            .mark_local_reference_released_exact(self.slot, self.id)
            .unwrap();
        let result = self.table.finish_exact(self.slot, self.id).unwrap();
        assert_eq!(
            result.local_terminal_result(),
            before.local_terminal_result()
        );
        assert_eq!(result.local_syscall_status(), before.local_syscall_status());
        assert_eq!(
            self.effects,
            Effects {
                writes: 1,
                persists: 1
            }
        );
        assert_eq!(
            self.fs.file_bytes_owned(PATH).as_deref(),
            Some(&[0x5a; 4096][..])
        );
    }
}

struct Memory {
    bytes: [u8; 16],
    calls: usize,
}

impl Memory {
    fn new() -> Self {
        Self {
            bytes: [0xcc; 16],
            calls: 0,
        }
    }
    fn publish(
        &mut self,
        pending: PendingFileIo,
        failure: Option<(usize, MemoryCopyFailure)>,
    ) -> Result<(), MemoryCopyFailure> {
        let (status, information) = pending.local_terminal_result().unwrap();
        let mut store = 0;
        publish_file_io_status_checked(pending.iosb_va, status, information, |address, bytes| {
            let index = store;
            store += 1;
            self.calls += 1;
            if let Some((failed, failure)) = failure {
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

#[test]
fn flush_mode_status_matrix_controls_iosb_and_file_without_fake_completion_surfaces() {
    for mode in [
        LocalFlushMode::SynchronousFile,
        LocalFlushMode::SynchronousApi,
    ] {
        for status in [STATUS_SUCCESS, WARNING, IO_ERROR] {
            let mut work = Work::new(mode, status);
            let pending = work.pending();
            let publishes = mode == LocalFlushMode::SynchronousApi || status != IO_ERROR;
            assert_eq!(pending.iosb_va != 0, publishes);
            assert_eq!(
                pending.signal_file,
                mode == LocalFlushMode::SynchronousFile && publishes
            );
            assert_eq!(
                (
                    pending.apc_routine,
                    pending.apc_context,
                    pending.event_obj_idx
                ),
                (0, 0, u64::MAX)
            );
            assert!(!pending.publish_iocp);
            assert!(pending.completion_port_suppressed);
            let mut memory = Memory::new();
            if publishes {
                assert_eq!(memory.publish(pending, None), Ok(()));
                work.table
                    .mark_delivery_exact(work.slot, work.id, IO_DELIVERY_IOSB_PUBLISHED)
                    .unwrap();
                assert_eq!(&memory.bytes[..4], &status.to_le_bytes());
                assert_eq!(&memory.bytes[4..8], &[0xcc; 4]);
                assert_eq!(&memory.bytes[8..], &0u64.to_le_bytes());
            } else {
                assert_eq!(memory.calls, 0);
            }
            assert_eq!(work.pending().local_syscall_status(), Some(status));
            work.finish();
            assert_eq!(
                work.fs.zw_is_file_signaled(work.handle),
                Ok(pending.signal_file)
            );
            assert_eq!(work.fs.zw_close(work.handle), STATUS_SUCCESS);
        }
    }
}

#[test]
fn completed_writeback_survives_both_iosb_store_failures_and_closed_file_delivery() {
    for mode in [
        LocalFlushMode::SynchronousFile,
        LocalFlushMode::SynchronousApi,
    ] {
        for store in [0, 1] {
            for retry in [false, true] {
                let mut work = Work::new(mode, STATUS_SUCCESS);
                assert_eq!(work.fs.zw_close(work.handle), STATUS_SUCCESS);
                let before = work.pending();
                let failure = if retry {
                    MemoryCopyFailure::Retry(AV)
                } else {
                    MemoryCopyFailure::UserFault(AV)
                };
                let mut memory = Memory::new();
                assert_eq!(memory.publish(before, Some((store, failure))), Err(failure));
                assert_eq!(memory.calls, store + 1);
                assert_eq!(&memory.bytes[..8], &[0xcc; 8]);
                assert_eq!(
                    &memory.bytes[8..],
                    if store == 0 { &[0xcc; 8] } else { &[0; 8] }
                );
                assert_eq!(work.pending(), before);
                assert!(work.fs.query_file_object_information(work.handle).is_ok());
                assert!(work
                    .table
                    .mark_iosb_faulted_exact(work.slot, work.id, IOSB)
                    .is_none());
                if retry {
                    assert!(work
                        .table
                        .mark_backend_acked_exact(work.slot, work.id)
                        .is_none());
                    assert_eq!(work.pending(), before);
                    assert_eq!(memory.publish(before, None), Ok(()));
                    work.table
                        .mark_delivery_exact(work.slot, work.id, IO_DELIVERY_IOSB_PUBLISHED)
                        .unwrap();
                } else {
                    work.table
                        .mark_local_flush_iosb_faulted_exact(work.slot, work.id, IOSB, AV)
                        .unwrap();
                    assert_eq!(
                        work.pending().delivery_state & IO_DELIVERY_IOSB_PUBLISHED,
                        0
                    );
                    assert_ne!(work.pending().delivery_state & IO_DELIVERY_IOSB_FAULTED, 0);
                    assert_eq!(work.pending().iosb_va, IOSB);
                }
                assert_eq!(
                    work.pending().local_terminal_result(),
                    Some((STATUS_SUCCESS, 0))
                );
                assert_eq!(
                    work.pending().local_syscall_status(),
                    Some(if !retry && mode == LocalFlushMode::SynchronousApi {
                        AV
                    } else {
                        STATUS_SUCCESS
                    })
                );
                work.finish();
                assert_eq!(
                    work.fs.query_file_object_information(work.handle),
                    Err(STATUS_INVALID_HANDLE)
                );
            }
        }
    }
}

#[test]
fn async_open_final_iosb_reports_original_error_unless_its_own_store_faults() {
    for store in [0, 1] {
        let mut work = Work::new(LocalFlushMode::SynchronousApi, IO_ERROR);
        let mut memory = Memory::new();
        assert_eq!(
            memory.publish(
                work.pending(),
                Some((store, MemoryCopyFailure::UserFault(GUARD)))
            ),
            Err(MemoryCopyFailure::UserFault(GUARD))
        );
        work.table
            .mark_local_flush_iosb_faulted_exact(work.slot, work.id, IOSB, GUARD)
            .unwrap();
        assert_eq!(work.pending().local_terminal_result(), Some((IO_ERROR, 0)));
        assert_eq!(work.pending().local_syscall_status(), Some(GUARD));
        assert_eq!(&memory.bytes[..4], &[0xcc; 4]);
        assert_eq!(
            &memory.bytes[8..],
            if store == 0 { &[0xcc; 8] } else { &[0; 8] }
        );
        assert!(!work.pending().signal_file);
        work.finish();
        assert_eq!(work.fs.zw_is_file_signaled(work.handle), Ok(false));
        assert_eq!(work.fs.zw_close(work.handle), STATUS_SUCCESS);
    }
}

#[test]
fn thread_abandonment_after_iosb_retry_releases_owned_reply_and_reference_without_reflushing() {
    for mode in [
        LocalFlushMode::SynchronousFile,
        LocalFlushMode::SynchronousApi,
    ] {
        let mut work = Work::new(mode, STATUS_SUCCESS);
        let mut memory = Memory::new();
        assert_eq!(
            memory.publish(work.pending(), Some((1, MemoryCopyFailure::Retry(AV)))),
            Err(MemoryCopyFailure::Retry(AV))
        );
        let mut reply = None;
        assert_eq!(
            work.table
                .abandon_thread_transfers_with(TID, |owner| reply = Some(owner.reply_cap)),
            1
        );
        assert_eq!(reply, Some(REPLY));
        assert!(work.pending().consumer_abandoned);
        assert_eq!(
            (work.pending().iosb_va, work.pending().event_obj_idx),
            (0, u64::MAX)
        );
        assert!(!work.pending().signal_file);
        assert_eq!(work.fs.zw_close(work.handle), STATUS_SUCCESS);
        work.table
            .mark_backend_acked_exact(work.slot, work.id)
            .unwrap();
        assert!(work.table.finish_exact(work.slot, work.id).is_none());
        work.fs.zw_release_io_reference(work.handle).unwrap();
        work.table
            .mark_local_reference_released_exact(work.slot, work.id)
            .unwrap();
        let retired = work.table.finish_exact(work.slot, work.id).unwrap();
        assert_eq!(retired.local_terminal_result(), Some((STATUS_SUCCESS, 0)));
        assert_eq!(
            work.effects,
            Effects {
                writes: 1,
                persists: 1
            }
        );
        assert_eq!(
            work.fs.query_file_object_information(work.handle),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            work.fs.file_bytes_owned(PATH).as_deref(),
            Some(&[0x5a; 4096][..])
        );
    }
}
