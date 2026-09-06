use super::*;
use alloc::{collections::BTreeMap, vec};

const IO_ERROR: u32 = 0xc000_0185;
const CLEANUP_ERROR: u32 = 0xc000_0001;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Prepare(u64),
    Raw(u64, usize),
    Copy(u64, usize, usize),
    Finish,
}

struct Io {
    fs: nt_fs::FileSystem,
    file: u64,
    frames: BTreeMap<u64, Vec<u8>>,
    prepared: Vec<u64>,
    events: Vec<Event>,
    fail_prepare: Option<u64>,
    fail_cleanup: bool,
    raw_result: Option<(usize, u32)>,
    oversized: bool,
}

impl SectionFileReadIo for Io {
    fn begin(&mut self) -> Result<(), u32> {
        if self.prepared.is_empty() {
            Ok(())
        } else {
            SectionFileReadIo::finish(self)
        }
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        self.events.push(Event::Prepare(page.frame));
        if self.fail_prepare == Some(page.frame) {
            return Err(IO_ERROR);
        }
        assert!(!self.prepared.contains(&page.frame));
        assert!(self.frames.contains_key(&page.frame));
        self.prepared.push(page.frame);
        Ok(())
    }
    fn read_backing(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize) {
        self.events.push(Event::Raw(offset, output.len()));
        let length = self
            .raw_result
            .map_or(output.len(), |(n, _)| n.min(output.len()));
        let (status, count) =
            self.fs
                .zw_read_file_into(self.file, Some(offset), &mut output[..length]);
        (
            self.raw_result.map_or(status, |(_, status)| status),
            count + usize::from(self.oversized),
        )
    }
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, output: &mut [u8]) {
        assert!(self.prepared.contains(&page.frame));
        self.events
            .push(Event::Copy(page.frame, offset, output.len()));
        output.copy_from_slice(&self.frames[&page.frame][offset..offset + output.len()]);
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
    extent: usize,
    resident: &[u64],
) -> (GenericSectionTable, GenericSectionBacking, usize, Io) {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let file = fs.zw_create_file(r"\??\C:\source", 3, 0, 7, nt_fs::FILE_CREATE, 0);
    assert_eq!(file.status, 0);
    assert_eq!(
        fs.zw_write_file(file.handle, Some(0), &vec![0x11; extent]),
        (0, extent)
    );
    let backing = GenericSectionBacking::overlay(
        file.handle,
        SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id: fs.zw_query_metadata(file.handle).unwrap().file_id,
        },
        extent as u64,
    );
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            1,
            7,
            extent as u64,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap();
    let mut frames = BTreeMap::new();
    for page in resident {
        table.set_page_frame(section, *page, 100 + page);
        frames.insert(100 + page, vec![0x80 + *page as u8; 4096]);
    }
    (
        table,
        backing,
        section,
        Io {
            fs,
            file: file.handle,
            frames,
            prepared: Vec::new(),
            events: Vec::new(),
            fail_prepare: None,
            fail_cleanup: false,
            raw_result: None,
            oversized: false,
        },
    )
}

#[test]
fn mixed_read_prepares_all_pages_and_uses_backing_only_for_gaps() {
    let (mut table, backing, _, mut io) = fixture(0x5000, &[1, 3]);
    let mut output = vec![0xff; 0x4000];
    assert_eq!(
        table.read_file_coherent(backing, 0x800, &mut output, &mut io),
        (0, 0x4000)
    );
    assert_eq!(
        io.events,
        [
            Event::Prepare(101),
            Event::Prepare(103),
            Event::Raw(0x800, 0x800),
            Event::Copy(101, 0, 0x1000),
            Event::Raw(0x2000, 0x1000),
            Event::Copy(103, 0, 0x1000),
            Event::Raw(0x4000, 0x800),
            Event::Finish
        ]
    );
    for (range, value) in [
        (0..0x800, 0x11),
        (0x800..0x1800, 0x81),
        (0x1800..0x2800, 0x11),
        (0x2800..0x3800, 0x83),
        (0x3800..0x4000, 0x11),
    ] {
        assert!(output[range].iter().all(|b| *b == value));
    }
}

#[test]
fn clean_and_dirty_canonical_pages_win_without_flush_or_version_changes() {
    let (mut table, backing, section, mut io) = fixture(0x2000, &[0, 1]);
    table.mark_page_dirty(section, 0);
    let epochs: Vec<_> = table
        .pages
        .iter()
        .map(|p| (p.dirty, p.dirty_epoch))
        .collect();
    let epoch = table.dirty_epoch;
    io.frames.insert(999, vec![0x22; 4096]);
    let mut output = [0xff; 4];
    assert_eq!(
        table.read_file_coherent(backing, 0xffe, &mut output, &mut io),
        (0, 4)
    );
    assert_eq!(output, [0x80, 0x80, 0x81, 0x81]);
    assert!(!io.events.iter().any(|e| matches!(e, Event::Raw(..))));
    assert_eq!(table.dirty_epoch, epoch);
    assert_eq!(
        table
            .pages
            .iter()
            .map(|p| (p.dirty, p.dirty_epoch))
            .collect::<Vec<_>>(),
        epochs
    );
    assert!(io.frames[&999].iter().all(|b| *b == 0x22));
}

#[test]
fn eof_clipping_never_exposes_page_padding_or_modifies_output_tail() {
    let (mut table, backing, _, mut io) = fixture(0x1802, &[1]);
    let mut output = [0xff; 8];
    assert_eq!(
        table.read_file_coherent(backing, 0x1800, &mut output, &mut io),
        (0, 2)
    );
    assert_eq!(output, [0x81, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    io.events.clear();
    for offset in [0x1802, 0x9000] {
        assert_eq!(
            table.read_file_coherent(backing, offset, &mut output, &mut io),
            (STATUS_END_OF_FILE, 0)
        );
    }
    assert_eq!(
        table.read_file_coherent(backing, 0x9000, &mut [], &mut io),
        (0, 0)
    );
    assert!(io.events.is_empty());
}

#[test]
fn short_and_error_gap_reads_stop_at_contiguous_prefix_without_later_resident_copies() {
    for (limit, status) in [(2, 0), (2, IO_ERROR), (0, 0), (0, IO_ERROR)] {
        let (mut table, backing, _, mut io) = fixture(0x3000, &[0, 2]);
        io.raw_result = Some((limit, status));
        let mut output = vec![0xff; 0x1004];
        assert_eq!(
            table.read_file_coherent(backing, 0xffe, &mut output, &mut io),
            (status, 2 + limit)
        );
        assert_eq!(&output[..2], &[0x80; 2]);
        assert!(output[2..2 + limit].iter().all(|b| *b == 0x11));
        assert!(output[2 + limit..].iter().all(|b| *b == 0xff));
        assert!(!io.events.iter().any(|e| matches!(e, Event::Copy(102, ..))));
    }
}

#[test]
fn full_gap_prefix_with_error_still_stops_before_next_canonical_page() {
    let (mut table, backing, _, mut io) = fixture(0x2000, &[1]);
    io.raw_result = Some((usize::MAX, IO_ERROR));
    let mut output = [0xff; 4];
    assert_eq!(
        table.read_file_coherent(backing, 0xffe, &mut output, &mut io),
        (IO_ERROR, 2)
    );
    assert_eq!(output, [0x11, 0x11, 0xff, 0xff]);
}

#[test]
fn failed_last_page_preparation_keeps_output_and_backing_reads_untouched() {
    let (mut table, backing, _, mut io) = fixture(0x4000, &[1, 3]);
    io.fail_prepare = Some(103);
    io.fail_cleanup = true;
    let mut output = vec![0xff; 0x4000];
    assert_eq!(
        table.read_file_coherent(backing, 0, &mut output, &mut io),
        (IO_ERROR, 0)
    );
    assert!(output.iter().all(|b| *b == 0xff));
    assert_eq!(
        io.events,
        [Event::Prepare(101), Event::Prepare(103), Event::Finish]
    );
    assert_eq!(io.prepared, [101]);
}

#[test]
fn cleanup_failure_preserves_bytes_and_blocks_next_resident_or_uncached_read() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[0]);
    let mut output = [0xff; 4];
    io.fail_cleanup = true;
    assert_eq!(
        table.read_file_coherent(backing, 0, &mut output, &mut io),
        (CLEANUP_ERROR, 4)
    );
    assert_eq!(output, [0x80; 4]);
    let mut uncached = backing;
    uncached.file.as_mut().unwrap().file_id += 1;
    for target in [backing, uncached] {
        output.fill(0xff);
        io.events.clear();
        assert_eq!(
            table.read_file_coherent(target, 0, &mut output, &mut io),
            (CLEANUP_ERROR, 0)
        );
        assert_eq!(output, [0xff; 4]);
        assert_eq!(io.events, [Event::Finish]);
    }
    io.fail_cleanup = false;
    assert_eq!(
        table.read_file_coherent(backing, 0, &mut output, &mut io),
        (0, 4)
    );
    assert!(io.prepared.is_empty());
}

#[test]
fn original_raw_error_wins_over_cleanup_failure() {
    let (mut table, backing, _, mut io) = fixture(0x2000, &[1]);
    io.raw_result = Some((2, IO_ERROR));
    io.fail_cleanup = true;
    let mut output = vec![0xff; 0x2000];
    assert_eq!(
        table.read_file_coherent(backing, 0, &mut output, &mut io),
        (IO_ERROR, 2)
    );
    assert_eq!(io.prepared, [101]);
}

#[test]
fn invalid_backing_external_eof_changes_and_overflow_fail_before_io() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[0]);
    let mut output = [0xff; 4];
    for extent in [0x800, 0x1800] {
        assert_eq!(
            table.read_file_coherent(
                GenericSectionBacking {
                    file_extent: extent,
                    ..backing
                },
                0,
                &mut output,
                &mut io
            ),
            (STATUS_USER_MAPPED_FILE, 0)
        );
    }
    assert_eq!(
        table.read_file_coherent(GenericSectionBacking::anonymous(), 0, &mut output, &mut io),
        (STATUS_INVALID_PARAMETER, 0)
    );
    assert_eq!(
        table.read_file_coherent(backing, u64::MAX, &mut output, &mut io),
        (STATUS_INVALID_PARAMETER, 0)
    );
    assert!(io.events.is_empty());
    assert_eq!(output, [0xff; 4]);
}

#[test]
fn mount_file_backend_and_retired_area_isolation_use_only_raw_backing() {
    let (mut table, backing, section, mut io) = fixture(0x1000, &[0]);
    let file = backing.file.unwrap();
    let mut mounts = SectionMountIds::new();
    mounts.allocate();
    let other = mounts.allocate().unwrap();
    for target in [
        GenericSectionBacking {
            file: Some(SectionFileIdentity {
                mount: other,
                ..file
            }),
            ..backing
        },
        GenericSectionBacking {
            file: Some(SectionFileIdentity {
                file_id: file.file_id + 1,
                ..file
            }),
            ..backing
        },
        GenericSectionBacking::disk(4, 0x1000, file),
    ] {
        let mut output = [0; 4];
        io.events.clear();
        assert_eq!(
            table.read_file_coherent(target, 0, &mut output, &mut io),
            (0, 4)
        );
        assert_eq!(output, [0x11; 4]);
        assert_eq!(io.events, [Event::Raw(0, 4), Event::Finish]);
    }
    table.release_handle(section);
    let mut output = [0; 4];
    assert_eq!(
        table.read_file_coherent(backing, 0, &mut output, &mut io),
        (0, 4)
    );
    assert_eq!(output, [0x11; 4]);
}

#[test]
#[should_panic(expected = "backing read violated exact-prefix contract")]
fn impossible_backing_prefix_is_an_internal_invariant_failure() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[]);
    io.oversized = true;
    table.read_file_coherent(backing, 0, &mut [0; 4], &mut io);
}

impl SectionFileWriteIo for Io {
    fn begin(&mut self) -> Result<(), u32> {
        SectionFileReadIo::begin(self)
    }
    fn rearm_alias(&mut self, _: SectionPageAlias) -> Result<(), u32> {
        Ok(())
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        SectionFileReadIo::prepare_page(self, page)
    }
    fn write_backing(&mut self, offset: u64, data: &[u8]) -> (u32, usize) {
        self.fs.zw_write_file(self.file, Some(offset), data)
    }
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, data: &[u8]) {
        assert!(self.prepared.contains(&page.frame));
        self.frames.get_mut(&page.frame).unwrap()[offset..offset + data.len()]
            .copy_from_slice(data);
    }
    fn zero_resident(&mut self, page: SectionFilePage, offset: usize, length: usize) {
        assert!(self.prepared.contains(&page.frame));
        self.frames.get_mut(&page.frame).unwrap()[offset..offset + length].fill(0);
    }
    fn finish(&mut self) -> Result<(), u32> {
        SectionFileReadIo::finish(self)
    }
}

#[test]
fn real_hardlink_write_then_read_observes_unflushed_dirty_bytes_and_keeps_file_position() {
    let (mut table, backing, section, mut io) = fixture(0x800, &[0]);
    table.mark_page_dirty(section, 0);
    let name: Vec<u8> = "alias".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(
        io.fs
            .zw_link_file(io.file, nt_fs::FileRenameRoot::VolumeRoot, &name, false),
        0
    );
    let caller = io
        .fs
        .zw_create_file(r"\??\C:\alias", 3, 0, 7, nt_fs::FILE_OPEN, 0);
    assert_eq!(caller.status, 0);
    assert_ne!(io.file, caller.handle);
    io.file = caller.handle;
    assert_eq!(
        io.fs.zw_set_information_file(
            io.file,
            nt_fs::FILE_POSITION_INFORMATION,
            &17u64.to_le_bytes()
        ),
        0
    );
    let current = GenericSectionBacking::overlay(
        io.file,
        SectionFileIdentity {
            mount: backing.file.unwrap().mount,
            file_id: io.fs.zw_query_metadata(io.file).unwrap().file_id,
        },
        0x800,
    );
    io.fs.zw_retain_io_reference(io.file).unwrap();
    assert_eq!(io.fs.zw_close(io.file), 0);
    assert_eq!(
        table.write_file_coherent(current, 0x900, b"data", &mut io),
        (0, 4)
    );
    let current = GenericSectionBacking {
        file_extent: 0x904,
        ..current
    };
    let mut output = vec![0xff; 0x908];
    io.events.clear();
    assert_eq!(
        table.read_file_coherent(current, 0, &mut output, &mut io),
        (0, 0x904)
    );
    assert!(output[..0x800].iter().all(|b| *b == 0x80));
    assert!(output[0x800..0x900].iter().all(|b| *b == 0));
    assert_eq!(&output[0x900..0x904], b"data");
    assert_eq!(&output[0x904..], &[0xff; 4]);
    assert!(!io.events.iter().any(|e| matches!(e, Event::Raw(..))));
    assert_eq!(io.fs.zw_read_file(io.file, Some(0), 4), (0, vec![0x11; 4]));
    assert_eq!(io.fs.current_offset(io.file), Some(17));
    io.fs.zw_release_io_reference(io.file).unwrap();
}
