use super::*;
use crate::writeback::{SectionPageAlias, SectionWritebackIo, SectionWritebackPage};
use alloc::vec;

fn key(file_id: u64) -> SectionFileIdentity {
    SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id,
    }
}

fn section(
    table: &mut GenericSectionTable,
    handle: u64,
    file: SectionFileIdentity,
    size: u64,
    extent: u64,
) -> usize {
    table
        .create(
            2,
            handle,
            size,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(handle, file, extent),
        )
        .unwrap()
}

#[derive(Default)]
struct Release {
    frames: Vec<u64>,
    files: Vec<u64>,
    fail: bool,
}
impl SectionRetirementIo for Release {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        if self.fail {
            return Err(0xc000_009a);
        }
        self.frames.push(frame);
        Ok(())
    }
    fn release_backing(&mut self, backing: GenericSectionBacking) -> Result<(), u32> {
        self.files.push(backing.overlay_file_id);
        Ok(())
    }
}

#[derive(Default)]
struct Write {
    aliases: Vec<SectionPageAlias>,
    pages: Vec<SectionWritebackPage>,
    fail: bool,
}
impl SectionWritebackIo for Write {
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.aliases.push(alias);
        Ok(())
    }
    fn write_page(&mut self, page: SectionWritebackPage) -> (u32, usize) {
        self.pages.push(page);
        (0, page.length)
    }
    fn persist(&mut self) -> u32 {
        if self.fail {
            0xc000_0185
        } else {
            0
        }
    }
}

#[test]
fn mount_ids_are_unique_and_exhaustion_never_reuses_an_identity() {
    let mut ids = SectionMountIds::new();
    assert_ne!(ids.allocate(), ids.allocate());
    ids.next = u64::MAX - 1;
    assert_eq!(ids.allocate(), Some(SectionMountId(u64::MAX)));
    assert_eq!(ids.allocate(), None);
    assert_eq!(ids.allocate(), None);
}

#[test]
fn independently_created_sections_share_canonical_frames_and_dirty_state() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x2000, 0x2000);
    let b = section(&mut table, 8, key(100), 0x1000, 0x2000);
    assert_ne!(a, b);
    assert!(table.set_page_frame(a, 0, 1000));
    assert_eq!(table.page_frame(b, 0), Some(1000));
    assert!(table.mark_page_dirty(b, 0));
    table.map_view(4, a, 0x10000, 0x2000, 0);
    table.map_view(5, b, 0x20000, 0x1000, 0);
    let from_a = table
        .prepare_writeback(table.plan_flush(4, 0x10000, 0).unwrap())
        .unwrap();
    let from_b = table
        .prepare_writeback(table.plan_flush(5, 0x20000, 0).unwrap())
        .unwrap();
    assert_eq!(from_a, from_b);
    assert_eq!(table.stats().live_pages, 1);
}

#[test]
fn file_and_mount_identity_isolate_pages_and_anonymous_sections_never_join() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    let b = section(&mut table, 8, key(101), 0x1000, 0x1000);
    let mut ids = SectionMountIds::new();
    ids.allocate();
    let c = section(
        &mut table,
        9,
        SectionFileIdentity {
            mount: ids.allocate().unwrap(),
            file_id: 100,
        },
        0x1000,
        0x1000,
    );
    let d = table
        .create(
            2,
            10,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap();
    let e = table
        .create(
            2,
            11,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap();
    table.set_page_frame(a, 0, 1000);
    table.set_page_frame(d, 0, 1001);
    for index in [b, c, e] {
        assert_eq!(table.page_frame(index, 0), None);
    }
}

#[test]
fn canonical_frame_publication_is_idempotent_but_cannot_replace_ownership() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    table.set_page_frame(a, 0, 1000);
    assert!(table.set_page_frame(b, 0, 1000));
    assert!(!table.set_page_frame(b, 0, 1001));
    assert_eq!(table.page_frame(a, 0), Some(1000));
    assert_eq!(table.stats().live_pages, 1);
}

#[test]
fn short_sibling_flushes_the_full_file_page_and_rearms_all_sibling_aliases() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x100, 0x1800);
    let b = section(&mut table, 8, key(100), 0x1800, 0x1800);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    table.map_view(4, b, 0x20000, 0x2000, 0);
    table.set_page_frame(b, 0, 1000);
    table.mark_page_dirty(b, 0);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let mut io = Write::default();
    assert_eq!(table.writeback(plan, &mut io).bytes_written, 0x1000);
    assert_eq!(io.pages[0].length, 0x1000);
    assert_eq!(
        io.aliases,
        vec![
            SectionPageAlias {
                pi: 3,
                page: 0x10000
            },
            SectionPageAlias {
                pi: 4,
                page: 0x20000
            }
        ]
    );
    assert!(table
        .prepare_writeback(table.plan_flush(4, 0x20000, 0).unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn final_partial_file_page_is_not_clipped_to_a_short_sibling() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1100, 0x1800);
    let b = section(&mut table, 8, key(100), 0x1800, 0x1800);
    table.map_view(3, a, 0x10000, 0x2000, 0);
    table.set_page_frame(b, 1, 1000);
    table.mark_page_dirty(b, 1);
    let plan = table.plan_flush(3, 0x11000, 0x100).unwrap();
    assert_eq!(table.prepare_writeback(plan).unwrap()[0].length, 0x800);
}

#[test]
fn closing_first_section_releases_its_file_but_not_shared_frames() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    table.set_page_frame(a, 0, 1000);
    table.release_handle(a);
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert!(io.frames.is_empty());
    assert_eq!(io.files, [7]);
    assert_eq!(table.page_frame(b, 0), Some(1000));
    let c = section(&mut table, 9, key(100), 0x1000, 0x1000);
    assert_eq!(
        a, c,
        "section slot may be reused without changing control ownership"
    );
    assert_eq!(table.page_frame(c, 0), Some(1000));
    table.release_handle(b);
    table.drain_retired(&mut io).unwrap();
    assert!(io.frames.is_empty());
    table.release_handle(c);
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, [1000]);
    assert_eq!(io.files, [7, 8, 9]);
    assert!(table.reset());
}

#[test]
fn last_view_keeps_shared_area_alive_after_both_handles_close() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    table.map_view(3, b, 0x10000, 0x1000, 0);
    table.set_page_frame(a, 0, 1000);
    table.release_handle(a);
    table.release_handle(b);
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert!(io.frames.is_empty());
    assert_eq!(table.page_frame(b, 0), Some(1000));
    table.unmap_view(3, 0x10000);
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, [1000]);
}

#[test]
fn retiring_area_is_not_revived_and_failed_release_cannot_touch_replacement() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    table.set_page_frame(a, 0, 1000);
    table.release_handle(a);
    let ticket = table.next_retirement().unwrap();
    let mut io = Release {
        fail: true,
        ..Release::default()
    };
    assert!(table.drain_retired(&mut io).is_err());
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    assert_eq!(table.page_frame(b, 0), None);
    table.set_page_frame(b, 0, 1001);
    io.fail = false;
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, [1000]);
    assert_eq!(table.page_frame(b, 0), Some(1001));
    assert!(!table.complete_retirement(ticket));
}

#[test]
fn dirty_tickets_follow_area_not_originating_section_and_sibling_marks_invalidate() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    table.map_view(4, b, 0x20000, 0x1000, 0);
    table.set_page_frame(a, 0, 1000);
    table.mark_page_dirty(a, 0);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let old = table.prepare_writeback(plan).unwrap()[0];
    table.mark_page_dirty(b, 0);
    assert!(!table.complete_writeback_page(old));
    let current = table.prepare_writeback(plan).unwrap()[0];
    table.release_handle(a);
    table.unmap_view(3, 0x10000);
    table.drain_retired(&mut Release::default()).unwrap();
    assert!(table.complete_writeback_page(current));
    assert!(
        table.prepare_writeback(plan).is_err(),
        "stale caller plans still fail"
    );
}

#[test]
fn shrink_is_refused_without_clearing_dirty_ownership_or_reextending_file() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x2000, 0x2000);
    table.map_view(3, a, 0x10000, 0x2000, 0);
    table.set_page_frame(a, 1, 1000);
    table.mark_page_dirty(a, 1);
    assert_eq!(table.refresh_file_extent(a, 0x1000), Err(0xc000_0011));
    assert_eq!(
        table.validate_backing_extent(GenericSectionBacking::overlay(8, key(100), 0x1000)),
        Err(0xc000_0011)
    );
    assert_eq!(
        table
            .prepare_writeback(table.plan_flush(3, 0x10000, 0).unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn failed_checkpoint_keeps_shared_dirty_version_for_either_sibling_to_retry() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    table.map_view(4, b, 0x20000, 0x1000, 0);
    table.set_page_frame(a, 0, 1000);
    table.mark_page_dirty(a, 0);
    let mut io = Write {
        fail: true,
        ..Write::default()
    };
    assert_ne!(
        table
            .writeback(table.plan_flush(3, 0x10000, 0).unwrap(), &mut io)
            .status,
        0
    );
    io.fail = false;
    assert_eq!(
        table
            .writeback(table.plan_flush(4, 0x20000, 0).unwrap(), &mut io)
            .status,
        0
    );
    assert_eq!(io.pages.len(), 2);
}

#[test]
fn cached_eof_tail_cannot_be_flushed_over_newly_appended_file_bytes() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x100, 0x100);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    table.set_page_frame(a, 0, 1000);
    table.mark_page_dirty(a, 0);
    assert_eq!(table.refresh_file_extent(a, 0x200), Err(0xc000_0243));
    let grown = GenericSectionBacking::overlay(8, key(100), 0x200);
    assert_eq!(table.validate_backing_extent(grown), Err(0xc000_0243));
    assert_eq!(
        table.create(
            2,
            8,
            0x200,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            grown
        ),
        None
    );
    assert_eq!(
        table
            .prepare_writeback(table.plan_flush(3, 0x10000, 0).unwrap())
            .unwrap()[0]
            .length,
        0x100
    );
}

#[test]
fn creation_checks_observed_extent_and_cached_tail_before_extension() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x4000, 0x4000);
    table.set_page_frame(a, 0, 1000);
    let truncated = GenericSectionBacking::overlay(8, key(100), 0x1000);
    assert_eq!(
        table.validate_file_creation(truncated, 0x4000),
        Err(0xc000_0011)
    );
    let b = section(&mut table, 9, key(101), 0x100, 0x100);
    table.set_page_frame(b, 0, 1001);
    let old = table.section(b).unwrap().backing;
    assert_eq!(table.validate_file_creation(old, 0x200), Err(0xc000_0243));
}

#[test]
fn page_aligned_growth_invalidates_old_flush_extent_without_replacing_pages() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    table.set_page_frame(a, 0, 1000);
    table.mark_page_dirty(a, 0);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    let plan = table.plan_flush(3, 0x10000, 0).unwrap();
    let old = table.prepare_writeback(plan).unwrap()[0];
    table.refresh_file_extent(a, 0x2000).unwrap();
    assert!(!table.complete_writeback_page(old));
    assert!(table.writeback_aliases(old).is_err());
    let current = table.prepare_writeback(plan).unwrap()[0];
    assert_eq!(current.frame, old.frame);
    assert!(table.complete_writeback_page(current));
}

#[test]
fn nonresident_eof_growth_can_join_and_data_pages_require_a_file_key() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x100, 0x100);
    let b = section(&mut table, 8, key(100), 0x200, 0x200);
    table.set_page_frame(b, 0, 1000);
    assert_eq!(table.page_frame(a, 0), Some(1000));
    let missing = GenericSectionBacking {
        file: None,
        ..table.section(a).unwrap().backing
    };
    assert_eq!(
        table.create(
            2,
            9,
            0x100,
            crate::PAGE_READONLY,
            SECTION_ATTR_SEC_COMMIT,
            missing
        ),
        None
    );
}

#[test]
fn retired_control_slots_and_reused_frames_cannot_revive_a_dirty_ticket() {
    let mut table = GenericSectionTable::new();
    let a = section(&mut table, 7, key(100), 0x1000, 0x1000);
    table.map_view(3, a, 0x10000, 0x1000, 0);
    table.set_page_frame(a, 0, 1000);
    table.mark_page_dirty(a, 0);
    let old = table
        .prepare_writeback(table.plan_flush(3, 0x10000, 0).unwrap())
        .unwrap()[0];
    table.release_handle(a);
    table.unmap_view(3, 0x10000);
    table.drain_retired(&mut Release::default()).unwrap();
    let b = section(&mut table, 8, key(100), 0x1000, 0x1000);
    assert_eq!(a, b);
    table.set_page_frame(b, 0, 1000);
    table.mark_page_dirty(b, 0);
    assert!(!table.complete_writeback_page(old));
    assert_eq!(table.control_areas.len(), 1);
}

struct FsRelease<'a> {
    fs: &'a mut nt_fs::FileSystem,
    frames: Vec<u64>,
}
impl SectionRetirementIo for FsRelease<'_> {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        self.frames.push(frame);
        Ok(())
    }
    fn release_backing(&mut self, backing: GenericSectionBacking) -> Result<(), u32> {
        self.fs.zw_release_io_reference(backing.overlay_file_id)
    }
}

#[test]
fn real_hardlink_siblings_keep_backing_after_first_file_object_slot_is_reused() {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let first = fs.zw_create_file(r"\??\C:\source", 3, 0, 7, nt_fs::FILE_CREATE, 0);
    assert_eq!(first.status, 0);
    assert_eq!(
        fs.zw_set_information_file(
            first.handle,
            nt_fs::FILE_END_OF_FILE_INFORMATION,
            &0x2000u64.to_le_bytes()
        ),
        0
    );
    let name: Vec<u8> = "alias".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(
        fs.zw_link_file(
            first.handle,
            nt_fs::FileRenameRoot::VolumeRoot,
            &name,
            false
        ),
        0
    );
    let second = fs.zw_create_file(r"\??\C:\alias", 3, 0, 7, nt_fs::FILE_OPEN, 0);
    assert_eq!(second.status, 0);
    let identity = key(fs.zw_query_metadata(first.handle).unwrap().file_id);
    assert_eq!(
        fs.zw_query_metadata(second.handle).unwrap().file_id,
        identity.file_id
    );
    assert_ne!(first.handle, second.handle);
    fs.zw_retain_io_reference(first.handle).unwrap();
    fs.zw_retain_io_reference(second.handle).unwrap();
    let mut table = GenericSectionTable::new();
    let a = table
        .create(
            2,
            7,
            0x2000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(first.handle, identity, 0x2000),
        )
        .unwrap();
    let b = table
        .create(
            3,
            8,
            0x2000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(second.handle, identity, 0x2000),
        )
        .unwrap();
    table.set_page_frame(a, 0, 1000);
    assert_eq!(fs.zw_close(first.handle), 0);
    assert_eq!(fs.zw_close(second.handle), 0);
    table.release_handle(a);
    {
        let mut io = FsRelease {
            fs: &mut fs,
            frames: Vec::new(),
        };
        table.drain_retired(&mut io).unwrap();
        assert!(io.frames.is_empty());
    }
    let unrelated = fs.zw_create_file(r"\??\C:\unrelated", 3, 0, 7, nt_fs::FILE_CREATE, 0);
    assert_eq!(unrelated.status, 0);
    assert_eq!(unrelated.handle, first.handle);
    assert_ne!(
        fs.zw_query_metadata(unrelated.handle).unwrap().file_id,
        identity.file_id
    );
    let backing = table.section(b).unwrap().backing;
    assert_eq!(table.page_frame(b, 0), Some(1000));
    assert_eq!(
        fs.zw_write_file(backing.overlay_file_id, Some(0), b"mapped"),
        (0, 6)
    );
    assert_eq!(
        fs.zw_read_file(backing.overlay_file_id, Some(0), 6),
        (0, b"mapped".to_vec())
    );
    assert_eq!(
        fs.zw_query_metadata(unrelated.handle).unwrap().end_of_file,
        0
    );
    table.release_handle(b);
    {
        let mut io = FsRelease {
            fs: &mut fs,
            frames: Vec::new(),
        };
        table.drain_retired(&mut io).unwrap();
        assert_eq!(io.frames, [1000]);
    }
    assert!(fs.zw_query_metadata(second.handle).is_none());
    assert!(fs.zw_query_metadata(unrelated.handle).is_some());
}
