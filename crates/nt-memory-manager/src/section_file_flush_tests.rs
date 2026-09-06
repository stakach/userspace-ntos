use super::*;
use crate::writeback::{SectionPageAlias, SectionWritebackIo, SectionWritebackPage};
use alloc::vec;

fn backing() -> GenericSectionBacking {
    GenericSectionBacking::overlay(
        90,
        SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id: 123,
        },
        0x2800,
    )
}

fn section(table: &mut GenericSectionTable, backing: GenericSectionBacking, size: u64) -> usize {
    table
        .create(
            1,
            backing.overlay_file_id,
            size,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap()
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Rearm(SectionPageAlias),
    Write(u64, usize),
    Persist,
}

#[derive(Default)]
struct Io {
    events: Vec<Event>,
    rearm_error: bool,
    short_write: bool,
    write_error: bool,
    persist_error: bool,
}

impl SectionWritebackIo for Io {
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.events.push(Event::Rearm(alias));
        if self.rearm_error {
            Err(0xc000_009a)
        } else {
            Ok(())
        }
    }
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        self.events
            .push(Event::Write(page.file_offset, page.length));
        if self.write_error {
            return (0xc000_0185, 3);
        }
        (0, page.length - usize::from(self.short_write))
    }
    fn persist(&mut self) -> u32 {
        self.events.push(Event::Persist);
        if self.persist_error {
            0xc000_0185
        } else {
            0
        }
    }
}

#[test]
fn file_flush_covers_all_pages_and_rearms_offset_siblings_before_writing() {
    let mut table = GenericSectionTable::new();
    let source = backing();
    let a = section(&mut table, source, 0x2800);
    let b = section(
        &mut table,
        GenericSectionBacking {
            overlay_file_id: 91,
            ..source
        },
        0x1000,
    );
    assert!(table.map_view(3, a, 0x10000, 0x2000, 0x1000));
    assert!(table.map_view(4, b, 0x20000, 0x1000, 0));
    for page in [2, 0, 1] {
        assert!(table.set_page_frame(a, page, 100 + page));
        assert!(table.mark_page_dirty(a, page));
    }
    let mut io = Io::default();
    // A separately opened FILE_OBJECT, not either section's retained handle.
    let result = table.writeback_file(
        GenericSectionBacking {
            overlay_file_id: 99,
            ..source
        },
        &mut io,
    );
    assert_eq!(result.status, 0);
    assert_eq!(result.bytes_written, 0x2800);
    assert_eq!(result.pages_written, 3);
    assert_eq!(
        io.events,
        vec![
            Event::Rearm(SectionPageAlias {
                pi: 4,
                page: 0x20000
            }),
            Event::Rearm(SectionPageAlias {
                pi: 3,
                page: 0x10000
            }),
            Event::Rearm(SectionPageAlias {
                pi: 3,
                page: 0x11000
            }),
            Event::Write(0, 0x1000),
            Event::Write(0x1000, 0x1000),
            Event::Write(0x2000, 0x800),
            Event::Persist,
        ]
    );
    io.events.clear();
    assert_eq!(table.writeback_file(source, &mut io).pages_written, 0);
    assert_eq!(io.events, [Event::Persist]);
}

#[test]
fn uncached_file_still_persists_and_reports_failure() {
    let mut table = GenericSectionTable::new();
    let mut io = Io {
        persist_error: true,
        ..Io::default()
    };
    assert_eq!(table.writeback_file(backing(), &mut io).status, 0xc000_0185);
    assert_eq!(io.events, [Event::Persist]);
}

#[test]
fn nonfile_backing_is_rejected_without_io() {
    let mut table = GenericSectionTable::new();
    for invalid in [
        GenericSectionBacking::anonymous(),
        GenericSectionBacking {
            file: None,
            ..backing()
        },
        GenericSectionBacking {
            kind: GENERIC_SECTION_BACKING_NONE,
            ..backing()
        },
    ] {
        let mut io = Io::default();
        assert_eq!(table.writeback_file(invalid, &mut io).status, 0xc000_000d);
        assert!(io.events.is_empty());
    }
}

#[test]
fn file_mount_and_backend_kind_isolate_flushes() {
    let mut table = GenericSectionTable::new();
    let source = backing();
    let a = section(&mut table, source, 0x1000);
    table.set_page_frame(a, 0, 100);
    table.mark_page_dirty(a, 0);
    let file = source.file.unwrap();
    let mut mounts = SectionMountIds::new();
    mounts.allocate();
    let other_mount = mounts.allocate().unwrap();
    for other in [
        GenericSectionBacking {
            file: Some(SectionFileIdentity {
                file_id: 124,
                ..file
            }),
            ..source
        },
        GenericSectionBacking {
            file: Some(SectionFileIdentity {
                mount: other_mount,
                ..file
            }),
            ..source
        },
        GenericSectionBacking::disk(4, 0x2800, file),
    ] {
        let mut io = Io::default();
        assert_eq!(table.writeback_file(other, &mut io).status, 0);
        assert_eq!(io.events, [Event::Persist]);
    }
    assert_eq!(
        table
            .writeback_file(source, &mut Io::default())
            .pages_written,
        1
    );
}

#[test]
fn retired_area_is_excluded_even_if_replacement_has_the_same_file_identity() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, backing(), 0x1000);
    table.set_page_frame(a, 0, 100);
    table.mark_page_dirty(a, 0);
    table.release_handle(a);
    let mut io = Io::default();
    assert_eq!(table.writeback_file(backing(), &mut io).pages_written, 0);
    assert_eq!(io.events, [Event::Persist]);
    let b = section(&mut table, backing(), 0x2800);
    table.set_page_frame(b, 2, 102);
    table.mark_page_dirty(b, 2);
    io.events.clear();
    assert_eq!(table.writeback_file(backing(), &mut io).pages_written, 1);
    assert_eq!(io.events, [Event::Write(0x2000, 0x800), Event::Persist]);
    assert_eq!(
        table.stats().live_pages,
        2,
        "retirement still owns the old frame"
    );
}

#[test]
fn unsafe_extent_changes_fail_before_io_and_leave_extent_and_dirty_pages_intact() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, backing(), 0x2800);
    table.set_page_frame(a, 2, 100);
    table.mark_page_dirty(a, 2);
    for (extent, error) in [
        (0x2000, 0xc000_0011),
        (0x3000, 0xc000_0243),
        (
            crate::data_section::MAX_DATA_SECTION_SIZE + 1,
            crate::STATUS_SECTION_TOO_BIG,
        ),
    ] {
        let mut io = Io::default();
        assert_eq!(
            table
                .writeback_file(
                    GenericSectionBacking {
                        file_extent: extent,
                        ..backing()
                    },
                    &mut io
                )
                .status,
            error
        );
        assert!(io.events.is_empty());
        assert_eq!(table.control_area(a).unwrap().extent, 0x2800);
    }
    assert_eq!(
        table
            .writeback_file(backing(), &mut Io::default())
            .pages_written,
        1
    );
}

#[test]
fn safe_growth_updates_area_extent_and_invalidates_old_tickets() {
    let mut table = GenericSectionTable::new();
    let source = GenericSectionBacking {
        file_extent: 0x2000,
        ..backing()
    };
    let a = section(&mut table, source, 0x1000);
    table.set_page_frame(a, 0, 100);
    table.mark_page_dirty(a, 0);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    let old = table
        .prepare_writeback(table.plan_flush(3, 0x10000, 0).unwrap())
        .unwrap()[0];
    let mut io = Io {
        persist_error: true,
        ..Io::default()
    };
    assert_eq!(table.writeback_file(backing(), &mut io).status, 0xc000_0185);
    assert!(!table.complete_writeback_page(old));
    assert_eq!(table.control_area(a).unwrap().extent, 0x2800);
    assert_eq!(
        table
            .writeback_file(backing(), &mut Io::default())
            .pages_written,
        1
    );
}

#[test]
fn every_io_failure_preserves_the_whole_dirty_batch_for_retry() {
    for fail in 0..4 {
        let mut table = GenericSectionTable::new();
        let a = section(&mut table, backing(), 0x2800);
        table.map_view(3, a, 0x10000, 0x3000, 0);
        for page in 0..3 {
            table.set_page_frame(a, page, 100 + page);
            table.mark_page_dirty(a, page);
        }
        let mut io = Io {
            rearm_error: fail == 0,
            short_write: fail == 1,
            write_error: fail == 2,
            persist_error: fail == 3,
            ..Io::default()
        };
        let result = table.writeback_file(backing(), &mut io);
        assert_ne!(result.status, 0);
        if fail == 0 {
            assert_eq!(io.events.len(), 1);
        }
        if fail < 3 {
            assert!(!io.events.contains(&Event::Persist));
        }
        if fail == 2 {
            assert_eq!(result.bytes_written, 3);
        }
        let retry = table.writeback_file(backing(), &mut Io::default());
        assert_eq!(retry.status, 0);
        assert_eq!(retry.bytes_written, 0x2800);
        assert_eq!(retry.pages_written, 3);
    }
}

struct FsIo<'a> {
    fs: &'a mut nt_fs::FileSystem,
    file: u64,
    snapshot: Vec<u8>,
}

impl SectionWritebackIo for FsIo<'_> {
    fn rearm_alias(&mut self, _: SectionPageAlias) -> Result<(), u32> {
        panic!("this fixture has no mapped views");
    }

    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        let data = [page.frame as u8; 0x1000];
        self.fs
            .zw_write_file(self.file, Some(page.file_offset), &data[..page.length])
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
fn separate_hardlink_file_object_flushes_real_bytes_without_changing_its_position() {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let source = fs.zw_create_file(r"\??\C:\source", 3, 0, 7, nt_fs::FILE_CREATE, 0);
    assert_eq!(source.status, 0);
    assert_eq!(
        fs.zw_set_information_file(
            source.handle,
            nt_fs::FILE_END_OF_FILE_INFORMATION,
            &0x2800u64.to_le_bytes()
        ),
        0
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
    assert_ne!(source.handle, caller.handle);
    assert_eq!(
        fs.zw_set_information_file(
            caller.handle,
            nt_fs::FILE_POSITION_INFORMATION,
            &17u64.to_le_bytes()
        ),
        0
    );
    let mount = SectionMountIds::new().allocate().unwrap();
    let identity = SectionFileIdentity {
        mount,
        file_id: fs.zw_query_metadata(source.handle).unwrap().file_id,
    };
    let source_backing = GenericSectionBacking::overlay(source.handle, identity, 0x2800);
    let caller_info = fs.zw_query_metadata(caller.handle).unwrap();
    let caller_backing = GenericSectionBacking::overlay(
        caller.handle,
        SectionFileIdentity {
            mount,
            file_id: caller_info.file_id,
        },
        caller_info.end_of_file,
    );
    let mut table = GenericSectionTable::new();
    let section = section(&mut table, source_backing, 0x2800);
    for page in 0..3 {
        table.set_page_frame(section, page, page + 1);
        table.mark_page_dirty(section, page);
    }
    // The I/O reference, not a remaining handle, keeps this distinct FILE_OBJECT alive.
    fs.zw_retain_io_reference(caller.handle).unwrap();
    assert_eq!(fs.zw_close(caller.handle), 0);
    let snapshot = {
        let mut io = FsIo {
            fs: &mut fs,
            file: caller.handle,
            snapshot: Vec::new(),
        };
        let result = table.writeback_file(caller_backing, &mut io);
        assert_eq!(result.status, 0);
        assert_eq!(result.bytes_written, 0x2800);
        io.snapshot
    };
    assert_eq!(fs.current_offset(caller.handle), Some(17));
    fs.zw_release_io_reference(caller.handle).unwrap();
    assert_eq!(fs.current_offset(caller.handle), None);
    let mut restored = nt_fs::FileSystem::from_volume_snapshot(&snapshot).unwrap();
    for path in [r"\??\C:\source", r"\??\C:\alias"] {
        let file = restored.zw_create_file(path, 1, 0, 7, nt_fs::FILE_OPEN, 0);
        assert_eq!(file.status, 0);
        assert_eq!(
            restored.zw_query_metadata(file.handle).unwrap().end_of_file,
            0x2800
        );
        let (status, data) = restored.zw_read_file(file.handle, Some(0), 0x3000);
        assert_eq!(status, 0);
        assert_eq!(data.len(), 0x2800);
        assert!(data[..0x1000].iter().all(|b| *b == 1));
        assert!(data[0x1000..0x2000].iter().all(|b| *b == 2));
        assert!(data[0x2000..].iter().all(|b| *b == 3));
    }
}
