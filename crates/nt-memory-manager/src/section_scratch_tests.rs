use super::*;
use alloc::{vec, vec::Vec};

const COPY_ERROR: u32 = 0xc000_009a;
const MAP_ERROR: u32 = 0xc000_0018;
const DELETE_ERROR: u32 = 0xc000_0001;
const RECYCLE_ERROR: u32 = 0xc000_0008;
const WRITE_ERROR: u32 = 0xc000_0185;

#[test]
fn quiescence_requires_closed_batch_and_acknowledged_slot_recycling() {
    let mut scratch = SectionScratch::new();
    let mut io = Io::default();
    assert!(scratch.is_quiescent());
    scratch.begin(&mut io).unwrap();
    assert!(!scratch.is_quiescent());
    scratch
        .prepare(10, 0x8000, SectionAliasAccess::ReadOnly, &mut io)
        .unwrap();
    io.delete_error = true;
    assert_eq!(scratch.finish(&mut io), Err(DELETE_ERROR));
    assert!(!scratch.is_quiescent());
    io.delete_error = false;
    io.recycle_error = true;
    assert_eq!(scratch.drain(&mut io), Err(RECYCLE_ERROR));
    assert!(!scratch.is_quiescent());
    io.recycle_error = false;
    scratch.drain(&mut io).unwrap();
    assert!(scratch.is_quiescent());
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Copy(u64),
    Map(u64),
    Transfer,
    Delete(u64),
    Frame(u64),
    Backing,
}

#[derive(Default)]
struct Io {
    events: Vec<Event>,
    reserved: Option<u64>,
    mapped: bool,
    populated: bool,
    copy_error: bool,
    null_copy: bool,
    failed_copy_slot: bool,
    map_error: bool,
    delete_error: bool,
    recycle_error: bool,
    recycled: Vec<u64>,
    next_alias: u64,
}

impl SectionScratchIo for Io {
    fn copy_frame(&mut self, frame: u64) -> (u64, u32) {
        self.events.push(Event::Copy(frame));
        assert!(
            self.reserved.is_none(),
            "scratch cannot be reacquired before cleanup"
        );
        if self.null_copy {
            return (0, 0);
        }
        if self.copy_error && !self.failed_copy_slot {
            return (0, COPY_ERROR);
        }
        self.next_alias += 1;
        self.reserved = Some(self.next_alias);
        self.populated = !self.copy_error;
        (
            self.next_alias,
            if self.copy_error { COPY_ERROR } else { 0 },
        )
    }

    fn map_alias(&mut self, alias: u64, _: u64, _: SectionAliasAccess) -> Result<(), u32> {
        self.events.push(Event::Map(alias));
        assert_eq!(self.reserved, Some(alias));
        assert!(self.populated);
        assert!(!self.mapped);
        if self.map_error {
            return Err(MAP_ERROR);
        }
        self.mapped = true;
        Ok(())
    }

    fn delete_alias(&mut self, alias: u64) -> Result<(), u32> {
        self.events.push(Event::Delete(alias));
        assert_eq!(self.reserved, Some(alias));
        assert!(self.populated, "never repeat acknowledged deletion");
        if self.delete_error {
            return Err(DELETE_ERROR);
        }
        self.mapped = false;
        self.populated = false;
        Ok(())
    }

    fn recycle_alias_slot(&mut self, alias: u64) -> Result<(), u32> {
        assert_eq!(self.reserved, Some(alias));
        assert!(!self.populated && !self.mapped);
        self.recycled.push(alias);
        if self.recycle_error {
            return Err(RECYCLE_ERROR);
        }
        self.reserved = None;
        Ok(())
    }
}

fn transfer(io: &mut Io) -> (u32, usize) {
    assert!(io.mapped);
    io.events.push(Event::Transfer);
    (0, 4096)
}

#[test]
fn success_deletes_mapping_and_capability_once_before_return() {
    let mut scratch = SectionScratch::new();
    let mut io = Io::default();
    assert_eq!(scratch.with_frame(50, 0x1000, &mut io, transfer), (0, 4096));
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), None);
    assert!(!io.mapped);
    scratch.drain(&mut io).unwrap();
    assert_eq!(
        io.events,
        [
            Event::Copy(50),
            Event::Map(1),
            Event::Transfer,
            Event::Delete(1)
        ]
    );
}

#[test]
fn invalid_frame_and_failed_copy_never_acquire_cleanup_ownership() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        copy_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(0, 0x1000, &mut io, transfer),
        (crate::STATUS_INVALID_HANDLE, 0)
    );
    assert!(io.events.is_empty());
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (COPY_ERROR, 0)
    );
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), None);
    scratch.drain(&mut io).unwrap();
    assert_eq!(io.events, [Event::Copy(50)]);
}

#[test]
fn failed_map_deletes_the_unmapped_copy_without_running_transfer() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        map_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (MAP_ERROR, 0)
    );
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), None);
    assert_eq!(
        io.events,
        [Event::Copy(50), Event::Map(1), Event::Delete(1)]
    );
}

#[test]
fn failed_map_and_failed_delete_retain_the_exact_copy_for_retry() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        map_error: true,
        delete_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (MAP_ERROR, 0)
    );
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), Some(1));
    assert!(!io.mapped);
    io.delete_error = false;
    scratch.drain(&mut io).unwrap();
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), None);
    assert_eq!(
        io.events,
        [
            Event::Copy(50),
            Event::Map(1),
            Event::Delete(1),
            Event::Delete(1)
        ]
    );
}

#[test]
fn failed_cleanup_retains_progress_and_blocks_scratch_reuse() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        delete_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (DELETE_ERROR, 4096)
    );
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), Some(1));
    assert!(io.mapped);
    io.events.clear();
    assert_eq!(
        scratch.with_frame(51, 0x1000, &mut io, transfer),
        (DELETE_ERROR, 0)
    );
    assert_eq!(io.events, [Event::Delete(1)]);
    io.delete_error = false;
    io.events.clear();
    assert_eq!(scratch.with_frame(51, 0x1000, &mut io, transfer), (0, 4096));
    assert_eq!(
        io.events,
        [
            Event::Delete(1),
            Event::Copy(51),
            Event::Map(2),
            Event::Transfer,
            Event::Delete(2)
        ]
    );
}

#[test]
fn backend_failure_wins_over_cleanup_failure_without_losing_accepted_bytes() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        delete_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, |_| (WRITE_ERROR, 17)),
        (WRITE_ERROR, 17)
    );
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), Some(1));
    io.delete_error = false;
    scratch.drain(&mut io).unwrap();
    assert_eq!(scratch.entries.first().map(|entry| entry.cap), None);
}

#[test]
fn revoked_mapping_still_requires_copied_slot_acknowledgement() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        delete_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer).0,
        DELETE_ERROR
    );
    // Canonical-owner revoke empties the cap but does not release executive slot ownership.
    io.mapped = false;
    io.delete_error = false;
    io.events.clear();
    scratch.drain(&mut io).unwrap();
    scratch.drain(&mut io).unwrap();
    assert_eq!(io.events, [Event::Delete(1)]);
    assert_eq!(io.reserved, None);
}

struct Writeback {
    scratch: SectionScratch,
    io: Io,
    checkpoints: usize,
}

impl crate::writeback::SectionWritebackIo for Writeback {
    fn rearm_alias(&mut self, _: crate::writeback::SectionPageAlias) -> Result<(), u32> {
        panic!("fixture has no mapped views");
    }
    fn write_page(&mut self, page: crate::writeback::SectionWritebackPage) -> (u32, usize) {
        self.scratch
            .with_frame(page.frame, 0x1000, &mut self.io, transfer)
    }
    fn persist(&mut self) -> u32 {
        if let Err(status) = self.scratch.drain(&mut self.io) {
            return status;
        }
        self.checkpoints += 1;
        0
    }
}

fn table() -> (crate::GenericSectionTable, crate::GenericSectionBacking) {
    let mut table = crate::GenericSectionTable::new();
    let backing = crate::GenericSectionBacking::overlay(
        9,
        crate::SectionFileIdentity {
            mount: crate::SectionMountIds::new().allocate().unwrap(),
            file_id: 123,
        },
        0x2000,
    );
    let index = table
        .create(
            1,
            40,
            0x2000,
            crate::PAGE_READWRITE,
            crate::SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap();
    for page in 0..2 {
        table.set_page_frame(index, page, 50 + page);
        table.mark_page_dirty(index, page);
    }
    (table, backing)
}

#[test]
fn cleanup_failure_preserves_the_full_dirty_batch_and_prevents_checkpoint() {
    let (mut table, backing) = table();
    let mut io = Writeback {
        scratch: SectionScratch::new(),
        io: Io {
            delete_error: true,
            ..Io::default()
        },
        checkpoints: 0,
    };
    let first = table.writeback_file(backing, &mut io);
    assert_eq!(first.status, DELETE_ERROR);
    assert_eq!(first.bytes_written, 4096);
    assert_eq!(io.checkpoints, 0);
    let second = table.writeback_file(backing, &mut io);
    assert_eq!(second.status, DELETE_ERROR);
    assert_eq!(second.bytes_written, 0);
    assert_eq!(io.checkpoints, 0);
    io.io.delete_error = false;
    let retry = table.writeback_file(backing, &mut io);
    assert_eq!(retry.status, 0);
    assert_eq!(retry.bytes_written, 8192);
    assert_eq!(retry.pages_written, 2);
    assert_eq!(io.checkpoints, 1);
    assert_eq!(table.writeback_file(backing, &mut io).pages_written, 0);
}

#[test]
fn clean_and_uncached_file_flushes_drain_pending_aliases_before_persistence() {
    let (mut table, backing) = table();
    let mut io = Writeback {
        scratch: SectionScratch::new(),
        io: Io::default(),
        checkpoints: 0,
    };
    assert_eq!(table.writeback_file(backing, &mut io).status, 0);
    assert_eq!(io.checkpoints, 1);
    io.io.delete_error = true;
    assert_eq!(
        io.scratch.with_frame(50, 0x1000, &mut io.io, transfer).0,
        DELETE_ERROR
    );
    let mut uncached = backing;
    uncached.file.as_mut().unwrap().file_id += 1;
    for file in [backing, uncached] {
        io.io.events.clear();
        let result = table.writeback_file(file, &mut io);
        assert_eq!(result.status, DELETE_ERROR);
        assert_eq!(result.bytes_written, 0);
        assert_eq!(io.checkpoints, 1);
        assert_eq!(io.io.events, [Event::Delete(3)]);
    }
    io.io.delete_error = false;
    assert_eq!(table.writeback_file(backing, &mut io).status, 0);
    assert_eq!(io.checkpoints, 2);
    assert_eq!(io.scratch.entries.first().map(|entry| entry.cap), None);
}

impl crate::SectionRetirementIo for Io {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        assert!(
            self.reserved.is_none(),
            "copied aliases retire before canonical frames"
        );
        self.events.push(Event::Frame(frame));
        Ok(())
    }
    fn release_backing(&mut self, _: crate::GenericSectionBacking) -> Result<(), u32> {
        self.events.push(Event::Backing);
        Ok(())
    }
}

#[test]
fn ownership_barrier_retries_copied_alias_before_frames_and_backing() {
    let (mut table, _) = table();
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        delete_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer).0,
        DELETE_ERROR
    );
    table.release_handle(0);
    let first = table.next_retirement().unwrap();
    let result = scratch
        .drain(&mut io)
        .and_then(|_| table.drain_retired(&mut io));
    assert_eq!(result, Err(DELETE_ERROR));
    assert_eq!(table.next_retirement(), Some(first));
    io.delete_error = false;
    io.events.clear();
    scratch
        .drain(&mut io)
        .and_then(|_| table.drain_retired(&mut io))
        .unwrap();
    assert_eq!(
        io.events,
        vec![
            Event::Delete(1),
            Event::Frame(50),
            Event::Frame(51),
            Event::Backing
        ]
    );
    assert_eq!(table.next_retirement(), None);
}

#[test]
fn failed_copy_empty_slot_is_retained_and_recycled_without_delete() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        copy_error: true,
        failed_copy_slot: true,
        recycle_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (COPY_ERROR, 0)
    );
    assert_eq!(io.reserved, Some(1));
    assert_eq!(io.events, [Event::Copy(50)]);
    assert_eq!(scratch.entries.len(), 1);
    assert!(!scratch.entries[0].populated && !scratch.entries[0].mapped);
    assert_eq!(scratch.begin(&mut io), Err(RECYCLE_ERROR));
    assert_eq!(io.events, [Event::Copy(50)]);
    io.recycle_error = false;
    scratch.drain(&mut io).unwrap();
    assert_eq!(io.recycled, [1, 1, 1]);
    assert!(scratch.entries.is_empty() && io.reserved.is_none());
}

#[test]
fn null_successful_copy_is_refused_without_mapping_or_cleanup() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        null_copy: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (RESOURCES, 0)
    );
    assert_eq!(io.events, [Event::Copy(50)]);
    assert!(io.recycled.is_empty() && scratch.entries.is_empty());
}

#[test]
fn successful_transfer_reports_recycle_failure_and_blocks_reuse_without_repeated_delete() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        recycle_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (RECYCLE_ERROR, 4096)
    );
    assert_eq!(scratch.entries[0].cap, 1);
    assert!(!scratch.entries[0].mapped && !scratch.entries[0].populated);
    let events = io.events.len();
    assert_eq!(
        scratch.with_frame(51, 0x1000, &mut io, transfer),
        (RECYCLE_ERROR, 0)
    );
    assert_eq!(io.events.len(), events);
    io.recycle_error = false;
    assert_eq!(scratch.with_frame(51, 0x1000, &mut io, transfer), (0, 4096));
    assert_eq!(
        io.events
            .iter()
            .filter(|event| **event == Event::Delete(1))
            .count(),
        1
    );
    assert_eq!(io.reserved, None);
}

#[test]
fn failed_map_and_transfer_preserve_their_status_and_bytes_over_recycle_failure() {
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        map_error: true,
        recycle_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer),
        (MAP_ERROR, 0)
    );
    assert!(!io.populated && !io.mapped);
    io.recycle_error = false;
    scratch.drain(&mut io).unwrap();
    io.map_error = false;
    io.recycle_error = true;
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, |_| (WRITE_ERROR, 17)),
        (WRITE_ERROR, 17)
    );
    assert_eq!(scratch.drain(&mut io), Err(RECYCLE_ERROR));
    assert_eq!(
        io.events
            .iter()
            .filter(|event| **event == Event::Delete(2))
            .count(),
        1
    );
}

#[test]
fn recycle_failure_preserves_dirty_pages_and_blocks_checkpoint_after_successful_write() {
    let (mut table, backing) = table();
    let mut io = Writeback {
        scratch: SectionScratch::new(),
        io: Io {
            recycle_error: true,
            ..Io::default()
        },
        checkpoints: 0,
    };
    let first = table.writeback_file(backing, &mut io);
    assert_eq!((first.status, first.bytes_written), (RECYCLE_ERROR, 4096));
    assert_eq!(io.checkpoints, 0);
    let second = table.writeback_file(backing, &mut io);
    assert_eq!((second.status, second.bytes_written), (RECYCLE_ERROR, 0));
    assert_eq!(
        io.io
            .events
            .iter()
            .filter(|event| **event == Event::Delete(1))
            .count(),
        1
    );
    io.io.recycle_error = false;
    let retry = table.writeback_file(backing, &mut io);
    assert_eq!(
        (retry.status, retry.bytes_written, retry.pages_written),
        (0, 8192, 2)
    );
    assert_eq!(io.checkpoints, 1);
}

#[test]
fn clean_and_uncached_flush_wait_for_pending_slot_recycling() {
    let (mut table, backing) = table();
    let mut io = Writeback {
        scratch: SectionScratch::new(),
        io: Io::default(),
        checkpoints: 0,
    };
    assert_eq!(table.writeback_file(backing, &mut io).status, 0);
    io.io.recycle_error = true;
    assert_eq!(
        io.scratch.with_frame(50, 0x1000, &mut io.io, transfer).0,
        RECYCLE_ERROR
    );
    let mut uncached = backing;
    uncached.file.as_mut().unwrap().file_id += 1;
    let events = io.io.events.len();
    for file in [backing, uncached] {
        assert_eq!(table.writeback_file(file, &mut io).status, RECYCLE_ERROR);
        assert_eq!(io.checkpoints, 1);
        assert_eq!(io.io.events.len(), events);
    }
    io.io.recycle_error = false;
    assert_eq!(table.writeback_file(backing, &mut io).status, 0);
    assert_eq!(io.checkpoints, 2);
}

#[test]
fn retained_deleted_slot_still_blocks_canonical_frame_and_backing_release() {
    let (mut table, _) = table();
    let mut scratch = SectionScratch::new();
    let mut io = Io {
        recycle_error: true,
        ..Io::default()
    };
    assert_eq!(
        scratch.with_frame(50, 0x1000, &mut io, transfer).0,
        RECYCLE_ERROR
    );
    table.release_handle(0);
    let first = table.next_retirement().unwrap();
    io.events.clear();
    assert_eq!(
        scratch
            .drain(&mut io)
            .and_then(|_| table.drain_retired(&mut io)),
        Err(RECYCLE_ERROR)
    );
    assert_eq!(table.next_retirement(), Some(first));
    assert!(io.events.is_empty());
    io.recycle_error = false;
    scratch
        .drain(&mut io)
        .and_then(|_| table.drain_retired(&mut io))
        .unwrap();
    assert_eq!(
        io.events,
        [Event::Frame(50), Event::Frame(51), Event::Backing]
    );
}
