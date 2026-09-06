use super::*;
use alloc::{collections::BTreeMap, vec};

const IO_ERROR: u32 = 0xc000_0185;
const CLEANUP_ERROR: u32 = 0xc000_0001;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Rearm(SectionPageAlias),
    Prepare(u64),
    Backing(u64, usize),
    Copy(u64, usize, usize),
    Zero(u64, usize, usize),
    Finish,
}

struct Io {
    file: Vec<u8>,
    frames: BTreeMap<u64, Vec<u8>>,
    prepared: Vec<u64>,
    events: Vec<Event>,
    fail_rearm: bool,
    fail_prepare: Option<u64>,
    accepted: usize,
    write_status: u32,
    fail_cleanup: bool,
    invalid_progress: bool,
}

impl SectionFileWriteIo for Io {
    fn begin(&mut self) -> Result<(), u32> {
        if self.prepared.is_empty() {
            Ok(())
        } else {
            self.finish()
        }
    }
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.events.push(Event::Rearm(alias));
        if self.fail_rearm {
            Err(IO_ERROR)
        } else {
            Ok(())
        }
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        self.events.push(Event::Prepare(page.frame));
        if self.fail_prepare == Some(page.frame) {
            return Err(IO_ERROR);
        }
        assert!(self.frames.contains_key(&page.frame));
        assert!(!self.prepared.contains(&page.frame));
        self.prepared.push(page.frame);
        Ok(())
    }
    fn write_backing(&mut self, offset: u64, data: &[u8]) -> (u32, usize) {
        self.events.push(Event::Backing(offset, data.len()));
        let accepted = data.len().min(self.accepted);
        if accepted != 0 {
            let end = offset as usize + accepted;
            if end > self.file.len() {
                self.file.resize(end, 0);
            }
            self.file[offset as usize..end].copy_from_slice(&data[..accepted]);
        }
        (
            self.write_status,
            accepted + usize::from(self.invalid_progress),
        )
    }
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, data: &[u8]) {
        assert!(self.prepared.contains(&page.frame));
        self.events
            .push(Event::Copy(page.frame, offset, data.len()));
        self.frames.get_mut(&page.frame).unwrap()[offset..offset + data.len()]
            .copy_from_slice(data);
    }
    fn zero_resident(&mut self, page: SectionFilePage, offset: usize, length: usize) {
        assert!(self.prepared.contains(&page.frame));
        self.events.push(Event::Zero(page.frame, offset, length));
        self.frames.get_mut(&page.frame).unwrap()[offset..offset + length].fill(0);
    }
    fn finish(&mut self) -> Result<(), u32> {
        self.events.push(Event::Finish);
        if self.fail_cleanup {
            return Err(CLEANUP_ERROR);
        }
        self.prepared.clear();
        Ok(())
    }
}

fn fixture(
    extent: u64,
    resident: &[u64],
) -> (GenericSectionTable, GenericSectionBacking, usize, Io) {
    let mut table = GenericSectionTable::new();
    let backing = GenericSectionBacking::overlay(
        7,
        SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id: 123,
        },
        extent,
    );
    let section = table
        .create(
            1,
            7,
            extent,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap();
    let mut frames = BTreeMap::new();
    for page in resident {
        assert!(table.set_page_frame(section, *page, 100 + page));
        frames.insert(100 + page, vec![0x11; 4096]);
    }
    (
        table,
        backing,
        section,
        Io {
            file: vec![0x11; extent as usize],
            frames,
            prepared: Vec::new(),
            events: Vec::new(),
            fail_rearm: false,
            fail_prepare: None,
            accepted: usize::MAX,
            write_status: 0,
            fail_cleanup: false,
            invalid_progress: false,
        },
    )
}

#[test]
fn partial_write_preserves_surrounding_dirty_bytes_and_invalidates_old_flush_ticket() {
    let (mut table, backing, section, mut io) = fixture(0x2000, &[0, 1]);
    table.map_view(1, section, 0x10000, 0x2000, 0);
    table.mark_page_dirty(section, 0);
    io.frames.get_mut(&100).unwrap()[..16].fill(0x77);
    io.frames.get_mut(&100).unwrap()[20..32].fill(0x88);
    let plan = table.plan_flush(1, 0x10000, 0).unwrap();
    let old = table.prepare_writeback(plan).unwrap()[0];
    assert_eq!(
        table.write_file_coherent(backing, 16, b"data", &mut io),
        (0, 4)
    );
    let page = &io.frames[&100];
    assert_eq!(&page[..16], &[0x77; 16]);
    assert_eq!(&page[16..20], b"data");
    assert_eq!(&page[20..32], &[0x88; 12]);
    assert_eq!(
        &io.file[..16],
        &[0x11; 16],
        "unrelated dirty bytes remain cache-owned"
    );
    assert!(!table.complete_writeback_page(old));
    assert_eq!(table.prepare_writeback(plan).unwrap().len(), 1);
}

#[test]
fn cross_page_write_prepares_all_clean_pages_before_backend_mutation() {
    let (mut table, backing, section, mut io) = fixture(0x3000, &[0, 1, 2]);
    table.map_view(1, section, 0x10000, 0x3000, 0);
    let data = vec![0x66; 0x1002];
    assert_eq!(
        table.write_file_coherent(backing, 0xfff, &data, &mut io),
        (0, data.len())
    );
    assert_eq!(
        io.events,
        vec![
            Event::Rearm(SectionPageAlias {
                pi: 1,
                page: 0x10000
            }),
            Event::Rearm(SectionPageAlias {
                pi: 1,
                page: 0x11000
            }),
            Event::Rearm(SectionPageAlias {
                pi: 1,
                page: 0x12000
            }),
            Event::Prepare(100),
            Event::Prepare(101),
            Event::Prepare(102),
            Event::Backing(0xfff, 0x1002),
            Event::Copy(100, 0xfff, 1),
            Event::Copy(101, 0, 0x1000),
            Event::Copy(102, 0, 1),
            Event::Finish,
        ]
    );
    assert_eq!(
        table
            .prepare_writeback(table.plan_flush(1, 0x10000, 0).unwrap())
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn mixed_resident_and_nonresident_write_does_not_materialize_missing_pages() {
    let (mut table, backing, section, mut io) = fixture(0x3000, &[0, 2]);
    let data = vec![0x66; 0x3000];
    assert_eq!(
        table.write_file_coherent(backing, 0, &data, &mut io),
        (0, data.len())
    );
    assert_eq!(table.page_frame(section, 1), None);
    assert_eq!(io.file, data);
    assert!(io
        .frames
        .values()
        .all(|page| page.iter().all(|b| *b == 0x66)));
}

#[test]
fn partial_acceptance_on_success_or_error_merges_only_the_accepted_prefix() {
    for status in [0, IO_ERROR] {
        let (mut table, backing, _, mut io) = fixture(0x2000, &[0, 1]);
        io.accepted = 2;
        io.write_status = status;
        assert_eq!(
            table.write_file_coherent(backing, 0xfff, b"abcd", &mut io),
            (status, 2)
        );
        assert_eq!(io.frames[&100][0xfff], b'a');
        assert_eq!(&io.frames[&101][..3], &[b'b', 0x11, 0x11]);
        assert_eq!(&io.file[0xfff..0x1003], &[b'a', b'b', 0x11, 0x11]);
    }
}

#[test]
fn eof_gap_zeroes_dirty_padding_and_extends_only_by_the_accepted_prefix() {
    let (mut table, backing, section, mut io) = fixture(0x800, &[0]);
    table.mark_page_dirty(section, 0);
    io.frames.get_mut(&100).unwrap()[0x800..].fill(0xee);
    io.accepted = 2;
    io.write_status = IO_ERROR;
    assert_eq!(
        table.write_file_coherent(backing, 0x900, b"abcd", &mut io),
        (IO_ERROR, 2)
    );
    assert!(io.frames[&100][0x800..0x900].iter().all(|b| *b == 0));
    assert_eq!(&io.frames[&100][0x900..0x904], &[b'a', b'b', 0xee, 0xee]);
    assert_eq!(table.control_area(section).unwrap().extent, 0x902);
    assert_eq!(io.file.len(), 0x902);
    assert_eq!(&io.file[0x800..], &io.frames[&100][0x800..0x902]);
    let current = GenericSectionBacking {
        file_extent: 0x902,
        ..backing
    };
    assert_eq!(
        table.write_file_coherent(current, 0x903, b"!", &mut io),
        (IO_ERROR, 1)
    );
    assert_eq!(&io.frames[&100][0x900..0x905], &[b'a', b'b', 0, b'!', 0xee]);
}

#[test]
fn extension_prepares_old_eof_tail_even_when_write_starts_on_a_later_page() {
    let (mut table, backing, section, mut io) = fixture(0x800, &[0]);
    io.frames.get_mut(&100).unwrap()[0x800..].fill(0xee);
    assert_eq!(
        table.write_file_coherent(backing, 0x3000, b"!", &mut io),
        (0, 1)
    );
    assert!(io.frames[&100][0x800..].iter().all(|b| *b == 0));
    assert_eq!(table.control_area(section).unwrap().extent, 0x3001);
    assert_eq!(
        io.events,
        [
            Event::Prepare(100),
            Event::Backing(0x3000, 1),
            Event::Zero(100, 0x800, 0x800),
            Event::Finish
        ]
    );
}

#[test]
fn zero_acceptance_never_zeroes_padding_extends_eof_or_dirties_pages() {
    let (mut table, backing, section, mut io) = fixture(0x800, &[0]);
    io.frames.get_mut(&100).unwrap()[0x800..].fill(0xee);
    io.accepted = 0;
    io.write_status = IO_ERROR;
    let epoch = table.pages[0].dirty_epoch;
    assert_eq!(
        table.write_file_coherent(backing, 0x900, b"abcd", &mut io),
        (IO_ERROR, 0)
    );
    assert!(io.frames[&100][0x800..].iter().all(|b| *b == 0xee));
    assert!(!table.pages[0].dirty);
    assert_eq!(table.pages[0].dirty_epoch, epoch);
    assert_eq!(table.control_area(section).unwrap().extent, 0x800);
    assert_eq!(io.file.len(), 0x800);
}

#[test]
fn empty_write_does_not_extend_or_prepare_an_eof_gap() {
    let (mut table, backing, section, mut io) = fixture(0x800, &[0]);
    assert_eq!(
        table.write_file_coherent(backing, 0x900, &[], &mut io),
        (0, 0)
    );
    assert!(io.events.is_empty());
    assert_eq!(table.control_area(section).unwrap().extent, 0x800);
}

#[test]
fn last_page_preparation_failure_leaves_all_data_and_versions_unchanged() {
    let (mut table, backing, _, mut io) = fixture(0x3000, &[0, 1, 2]);
    io.fail_prepare = Some(102);
    let epochs: Vec<_> = table.pages.iter().map(|p| p.dirty_epoch).collect();
    let before = io.frames.clone();
    assert_eq!(
        table.write_file_coherent(backing, 0, &vec![0x66; 0x3000], &mut io),
        (IO_ERROR, 0)
    );
    assert_eq!(io.frames, before);
    assert!(io.file.iter().all(|b| *b == 0x11));
    assert_eq!(
        table
            .pages
            .iter()
            .map(|p| p.dirty_epoch)
            .collect::<Vec<_>>(),
        epochs
    );
    assert_eq!(
        io.events,
        [
            Event::Prepare(100),
            Event::Prepare(101),
            Event::Prepare(102),
            Event::Finish
        ]
    );
    assert!(io.prepared.is_empty());
}

#[test]
fn rearm_failure_never_prepares_or_writes_and_still_finishes() {
    let (mut table, backing, section, mut io) = fixture(0x1000, &[0]);
    table.map_view(1, section, 0x10000, 0x1000, 0);
    io.fail_rearm = true;
    io.fail_cleanup = true;
    assert_eq!(
        table.write_file_coherent(backing, 0, b"x", &mut io),
        (IO_ERROR, 0)
    );
    assert_eq!(
        io.events,
        [
            Event::Rearm(SectionPageAlias {
                pi: 1,
                page: 0x10000
            }),
            Event::Finish
        ]
    );
}

#[test]
fn dirty_epoch_exhaustion_fails_before_any_io() {
    let (mut table, backing, _, mut io) = fixture(0x2000, &[0, 1]);
    table.dirty_epoch = u64::MAX - 1;
    assert_eq!(
        table.write_file_coherent(backing, 0, &vec![0x66; 0x2000], &mut io),
        (STATUS_INSUFFICIENT_RESOURCES, 0)
    );
    assert!(io.events.is_empty());
    assert_eq!(table.dirty_epoch, u64::MAX - 1);
}

#[test]
fn cleanup_failure_preserves_merged_bytes_extent_and_dirty_ownership() {
    for status in [0, IO_ERROR] {
        let (mut table, backing, section, mut io) = fixture(0x800, &[0]);
        io.fail_cleanup = true;
        io.write_status = status;
        let expected = if status == 0 { CLEANUP_ERROR } else { status };
        assert_eq!(
            table.write_file_coherent(backing, 0x800, b"x", &mut io),
            (expected, 1)
        );
        assert_eq!(io.frames[&100][0x800], b'x');
        assert_eq!(table.control_area(section).unwrap().extent, 0x801);
        assert!(table.pages[0].dirty);
        assert_eq!(io.prepared, [100]);
        let current = GenericSectionBacking {
            file_extent: 0x801,
            ..backing
        };
        io.events.clear();
        io.write_status = 0;
        assert_eq!(
            table.write_file_coherent(current, 0x801, b"y", &mut io),
            (CLEANUP_ERROR, 0)
        );
        assert_eq!(io.events, [Event::Finish]);
        assert_eq!(table.control_area(section).unwrap().extent, 0x801);
        io.fail_cleanup = false;
        assert_eq!(
            table.write_file_coherent(current, 0x801, b"y", &mut io),
            (0, 1)
        );
        assert_eq!(io.frames[&100][0x801], b'y');
        assert_eq!(table.control_area(section).unwrap().extent, 0x802);
        assert!(io.prepared.is_empty());
    }
}

#[test]
fn failed_prior_cleanup_blocks_even_uncached_backing_writes() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[0]);
    io.fail_cleanup = true;
    assert_eq!(
        table.write_file_coherent(backing, 0, b"x", &mut io),
        (CLEANUP_ERROR, 1)
    );
    let mut other = backing;
    other.file.as_mut().unwrap().file_id += 1;
    io.events.clear();
    assert_eq!(
        table.write_file_coherent(other, 0, b"y", &mut io),
        (CLEANUP_ERROR, 0)
    );
    assert_eq!(io.events, [Event::Finish]);
    assert_eq!(io.file[0], b'x');
    io.fail_cleanup = false;
    assert_eq!(table.write_file_coherent(other, 0, b"y", &mut io), (0, 1));
    assert_eq!(io.file[0], b'y');
    assert_eq!(
        io.frames[&100][0], b'x',
        "unrelated canonical frame stays independent"
    );
}

#[test]
#[should_panic(expected = "backing write violated exact-prefix contract")]
fn impossible_backend_progress_cannot_return_recoverable_zero_acceptance() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[0]);
    io.invalid_progress = true;
    table.write_file_coherent(backing, 0, b"x", &mut io);
}

#[test]
fn out_of_band_eof_changes_and_invalid_geometry_fail_without_io() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[0]);
    for extent in [0x800, 0x1800] {
        assert_eq!(
            table.write_file_coherent(
                GenericSectionBacking {
                    file_extent: extent,
                    ..backing
                },
                0,
                b"x",
                &mut io
            ),
            (STATUS_USER_MAPPED_FILE, 0)
        );
    }
    assert_eq!(
        table.write_file_coherent(backing, u64::MAX, b"x", &mut io),
        (STATUS_INVALID_PARAMETER, 0)
    );
    assert_eq!(
        table.write_file_coherent(
            backing,
            crate::data_section::MAX_DATA_SECTION_SIZE,
            b"x",
            &mut io
        ),
        (crate::STATUS_SECTION_TOO_BIG, 0)
    );
    assert_eq!(
        table.write_file_coherent(GenericSectionBacking::anonymous(), 0, b"x", &mut io),
        (STATUS_INVALID_PARAMETER, 0)
    );
    assert!(io.events.is_empty());
}

#[test]
fn sibling_sections_rearm_offset_views_but_use_only_canonical_frames() {
    let (mut table, backing, section, mut io) = fixture(0x2000, &[0, 1]);
    let sibling = table
        .create(
            2,
            8,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking {
                overlay_file_id: 8,
                ..backing
            },
        )
        .unwrap();
    table.map_view(2, sibling, 0x20000, 0x1000, 0);
    table.map_view(3, section, 0x30000, 0x1000, 0x1000);
    // An adapter-private COW frame is not a control-area resident and must remain independent.
    io.frames.insert(999, vec![0xaa; 4096]);
    assert_eq!(
        table.write_file_coherent(
            GenericSectionBacking {
                overlay_file_id: 99,
                ..backing
            },
            0xfff,
            b"xy",
            &mut io
        ),
        (0, 2)
    );
    assert_eq!(
        &io.events[..2],
        &[
            Event::Rearm(SectionPageAlias {
                pi: 2,
                page: 0x20000
            }),
            Event::Rearm(SectionPageAlias {
                pi: 3,
                page: 0x30000
            }),
        ]
    );
    assert!(io.frames[&999].iter().all(|b| *b == 0xaa));
}

#[test]
fn file_mount_backend_and_retired_area_isolation() {
    let (mut table, backing, section, mut io) = fixture(0x1000, &[0]);
    let file = backing.file.unwrap();
    let mut mounts = SectionMountIds::new();
    mounts.allocate();
    let another_mount = mounts.allocate().unwrap();
    for other in [
        GenericSectionBacking {
            file: Some(SectionFileIdentity {
                file_id: 124,
                ..file
            }),
            ..backing
        },
        GenericSectionBacking {
            file: Some(SectionFileIdentity {
                mount: another_mount,
                ..file
            }),
            ..backing
        },
        GenericSectionBacking::disk(4, 0x1000, file),
    ] {
        io.events.clear();
        assert_eq!(table.write_file_coherent(other, 0, b"x", &mut io), (0, 1));
        assert_eq!(io.events, [Event::Backing(0, 1), Event::Finish]);
        assert_eq!(io.frames[&100][0], 0x11);
    }
    table.release_handle(section);
    io.events.clear();
    assert_eq!(table.write_file_coherent(backing, 0, b"x", &mut io), (0, 1));
    assert_eq!(io.events, [Event::Backing(0, 1), Event::Finish]);
    assert_eq!(io.frames[&100][0], 0x11);
}

struct FsIo {
    memory: Io,
    fs: nt_fs::FileSystem,
    file: u64,
    snapshot: Vec<u8>,
}

impl SectionFileWriteIo for FsIo {
    fn begin(&mut self) -> Result<(), u32> {
        self.memory.begin()
    }
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.memory.rearm_alias(alias)
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        self.memory.prepare_page(page)
    }
    fn write_backing(&mut self, offset: u64, data: &[u8]) -> (u32, usize) {
        self.fs.zw_write_file(self.file, Some(offset), data)
    }
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, data: &[u8]) {
        self.memory.copy_resident(page, offset, data);
    }
    fn zero_resident(&mut self, page: SectionFilePage, offset: usize, length: usize) {
        self.memory.zero_resident(page, offset, length);
    }
    fn finish(&mut self) -> Result<(), u32> {
        self.memory.finish()
    }
}

impl crate::writeback::SectionWritebackIo for FsIo {
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.memory.rearm_alias(alias)
    }
    fn write_page(&mut self, page: crate::writeback::SectionWritebackPage) -> (u32, usize) {
        self.fs.zw_write_file(
            self.file,
            Some(page.file_offset),
            &self.memory.frames[&page.frame][..page.length],
        )
    }
    fn persist(&mut self) -> u32 {
        let status = self.fs.zw_flush_buffers_file(self.file);
        if status == 0 {
            self.snapshot = self.fs.export_volume_snapshot().unwrap();
        }
        status
    }
}

#[test]
fn real_hardlink_write_and_checkpoint_preserve_mapped_dirty_data_and_zero_eof_gap() {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let source = fs.zw_create_file(r"\??\C:\source", 3, 0, 7, nt_fs::FILE_CREATE, 0);
    assert_eq!(source.status, 0);
    assert_eq!(
        fs.zw_write_file(source.handle, Some(0), &vec![0x11; 0x800]),
        (0, 0x800)
    );
    let name: Vec<u8> = "alias".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(
        fs.zw_link_file(
            source.handle,
            nt_fs::FileRenameRoot::VolumeRoot,
            &name,
            false
        ),
        0
    );
    let caller = fs.zw_create_file(r"\??\C:\alias", 3, 0, 7, nt_fs::FILE_OPEN, 0);
    assert_eq!(caller.status, 0);
    assert_ne!(caller.handle, source.handle);
    assert_eq!(
        fs.zw_set_information_file(
            caller.handle,
            nt_fs::FILE_POSITION_INFORMATION,
            &17u64.to_le_bytes()
        ),
        0
    );
    let key = SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id: fs.zw_query_metadata(source.handle).unwrap().file_id,
    };
    let mut table = GenericSectionTable::new();
    let source_backing = GenericSectionBacking::overlay(source.handle, key, 0x800);
    let section = table
        .create(
            1,
            7,
            0x800,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            source_backing,
        )
        .unwrap();
    assert!(table.set_page_frame(section, 0, 100));
    assert!(table.mark_page_dirty(section, 0));
    let (_, _, _, mut memory) = fixture(0x800, &[0]);
    memory.frames.get_mut(&100).unwrap()[..16].fill(0x77);
    memory.frames.get_mut(&100).unwrap()[0x800..].fill(0xee);
    let mut io = FsIo {
        memory,
        fs,
        file: caller.handle,
        snapshot: Vec::new(),
    };
    let caller_key = SectionFileIdentity {
        mount: key.mount,
        file_id: io.fs.zw_query_metadata(caller.handle).unwrap().file_id,
    };
    let backing = GenericSectionBacking::overlay(caller.handle, caller_key, 0x800);
    io.fs.zw_retain_io_reference(caller.handle).unwrap();
    assert_eq!(io.fs.zw_close(caller.handle), 0);
    assert_eq!(
        table.write_file_coherent(backing, 0x900, b"data", &mut io),
        (0, 4)
    );
    assert_eq!(io.fs.current_offset(caller.handle), Some(17));
    assert_eq!(
        io.fs.zw_read_file(source.handle, Some(0), 16),
        (0, vec![0x11; 16])
    );
    assert_eq!(&io.memory.frames[&100][..16], &[0x77; 16]);
    let current = GenericSectionBacking {
        file_extent: 0x904,
        ..backing
    };
    let flushed = table.writeback_file(current, &mut io);
    assert_eq!(flushed.status, 0);
    assert_eq!(flushed.bytes_written, 0x904);
    assert_eq!(io.fs.current_offset(caller.handle), Some(17));
    let mut restored = nt_fs::FileSystem::from_volume_snapshot(&io.snapshot).unwrap();
    for path in [r"\??\C:\source", r"\??\C:\alias"] {
        let file = restored.zw_create_file(path, 1, 0, 7, nt_fs::FILE_OPEN, 0);
        assert_eq!(file.status, 0);
        let (status, bytes) = restored.zw_read_file(file.handle, Some(0), 0x1000);
        assert_eq!(status, 0);
        assert_eq!(bytes.len(), 0x904);
        assert_eq!(&bytes[..16], &[0x77; 16]);
        assert!(bytes[16..0x800].iter().all(|b| *b == 0x11));
        assert!(bytes[0x800..0x900].iter().all(|b| *b == 0));
        assert_eq!(&bytes[0x900..], b"data");
    }
    io.fs.zw_release_io_reference(caller.handle).unwrap();
    assert_eq!(io.fs.current_offset(caller.handle), None);
}
