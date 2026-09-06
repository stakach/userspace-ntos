use super::*;
use alloc::{vec, vec::Vec};

const COPY_ERROR: u32 = 0xc000_009a;
const MAP_ERROR: u32 = 0xc000_0018;
const DELETE_ERROR: u32 = 0xc000_0001;
const WRITE_ERROR: u32 = 0xc000_0185;

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
    copy_error: bool,
    map_error: bool,
    delete_error: bool,
    next_alias: u64,
}

impl SectionScratchIo for Io {
    fn copy_frame(&mut self, frame: u64) -> Result<u64, u32> {
        self.events.push(Event::Copy(frame));
        assert!(
            self.reserved.is_none(),
            "scratch cannot be reacquired before cleanup"
        );
        if self.copy_error {
            return Err(COPY_ERROR);
        }
        self.next_alias += 1;
        self.reserved = Some(self.next_alias);
        Ok(self.next_alias)
    }

    fn map_alias(&mut self, alias: u64, _: u64, _: SectionAliasAccess) -> Result<(), u32> {
        self.events.push(Event::Map(alias));
        assert_eq!(self.reserved, Some(alias));
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
        if self.delete_error {
            return Err(DELETE_ERROR);
        }
        self.mapped = false;
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
