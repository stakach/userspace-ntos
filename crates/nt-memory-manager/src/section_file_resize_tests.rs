use super::*;

impl SectionFileResizeIo for Io {
    fn resize_backing(&mut self, new_eof: u64) -> u32 {
        self.events.push(Event::Resize(new_eof));
        if self.write_status == 0 {
            self.file.resize(new_eof as usize, 0);
        }
        self.write_status
    }
}

fn resized(backing: GenericSectionBacking, file_extent: u64) -> GenericSectionBacking {
    GenericSectionBacking {
        file_extent,
        ..backing
    }
}

#[test]
fn growth_zeroes_only_newly_valid_tail_and_preserves_dirty_prefix() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    table.map_view(1, section, 0x10000, 0x2000, 0);
    table.mark_page_dirty(section, 1);
    io.frames.get_mut(&101).unwrap()[..0x800].fill(0x77);
    let plan = table.plan_flush(1, 0x10000, 0).unwrap();
    let ticket = table.prepare_writeback(plan).unwrap()[0];
    assert_eq!(table.resize_file_coherent(backing, 0x1a00, &mut io), 0);
    assert_eq!(&io.frames[&101][..0x800], &[0x77; 0x800]);
    assert_eq!(&io.frames[&101][0x800..0xa00], &[0; 0x200]);
    assert_eq!(&io.frames[&101][0xa00..], &[0x11; 0x600]);
    assert_eq!(&io.file[0x1800..], &[0; 0x200]);
    assert!(!table.complete_writeback_page(ticket));
    assert_eq!(table.control_area(section).unwrap().extent, 0x1a00);
    assert_eq!(
        io.events,
        [
            Event::Rearm(SectionPageAlias {
                pi: 1,
                page: 0x11000
            }),
            Event::Prepare(101),
            Event::Resize(0x1a00),
            Event::Zero(101, 0x800, 0x200),
            Event::Finish
        ]
    );
}

#[test]
fn large_growth_does_not_materialize_missing_canonical_pages() {
    let (mut table, backing, section, mut io) = fixture(0x1000, &[0]);
    assert_eq!(table.resize_file_coherent(backing, 0x100000, &mut io), 0);
    assert_eq!(io.events, [Event::Resize(0x100000), Event::Finish]);
    assert_eq!(table.page_frame(section, 1), None);
    assert_eq!(io.frames.len(), 1);
}

#[test]
fn unreferenced_files_resize_without_section_state() {
    let (_, backing, _, mut io) = fixture(0x1000, &[]);
    let mut table = GenericSectionTable::new();
    assert_eq!(table.resize_file_coherent(backing, 0, &mut io), 0);
    assert!(io.file.is_empty());
    assert_eq!(io.events, [Event::Resize(0), Event::Finish]);
}

#[test]
fn initial_segment_protects_file_extent_even_for_a_small_handle_only_section() {
    let (_, backing, _, mut io) = fixture(0x1800, &[]);
    let mut table = GenericSectionTable::new();
    table
        .create(
            1,
            7,
            0x100,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap();
    assert_eq!(
        table.resize_file_coherent(backing, 0x1000, &mut io),
        STATUS_USER_MAPPED_FILE
    );
    assert!(io.events.is_empty());
}

#[test]
fn shrink_above_segment_floor_zeroes_padding_without_discarding_dirty_prefix() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    assert_eq!(table.resize_file_coherent(backing, 0x1c00, &mut io), 0);
    io.frames.get_mut(&101).unwrap().fill(0x77);
    table.mark_page_dirty(section, 1);
    io.events.clear();
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x1c00), 0x1900, &mut io),
        0
    );
    assert_eq!(&io.frames[&101][..0x900], &[0x77; 0x900]);
    assert_eq!(&io.frames[&101][0x900..], &[0; 0x700]);
    assert_eq!(io.file.len(), 0x1900);
    assert_eq!(table.control_area(section).unwrap().segment_extent, 0x1800);
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x1900), 0x1800, &mut io),
        0
    );
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x1800), 0x17ff, &mut io),
        STATUS_USER_MAPPED_FILE
    );
}

#[test]
fn closing_larger_sibling_does_not_contract_segment_floor() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[]);
    assert_eq!(table.resize_file_coherent(backing, 0x3000, &mut io), 0);
    let larger = table
        .create(
            1,
            9,
            0x2800,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            resized(backing, 0x3000),
        )
        .unwrap();
    table.release_handle(larger);
    io.events.clear();
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x3000), 0x2400, &mut io),
        STATUS_USER_MAPPED_FILE
    );
    assert!(io.events.is_empty());
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x3000), 0x2800, &mut io),
        0
    );
}

#[test]
fn rearm_and_preparation_fail_before_any_backing_or_canonical_mutation() {
    for fail_rearm in [false, true] {
        let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
        table.map_view(1, section, 0x10000, 0x2000, 0);
        io.fail_rearm = fail_rearm;
        io.fail_prepare = (!fail_rearm).then_some(101);
        assert_eq!(
            table.resize_file_coherent(backing, 0x2000, &mut io),
            IO_ERROR
        );
        assert_eq!(io.file.len(), 0x1800);
        assert_eq!(&io.frames[&101][..], &[0x11; 4096]);
        assert_eq!(table.control_area(section).unwrap().extent, 0x1800);
        assert!(!io
            .events
            .iter()
            .any(|event| matches!(event, Event::Resize(_))));
        assert!(io.prepared.is_empty());
    }
}

#[test]
fn backend_failure_preserves_state_and_outranks_cleanup_error() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    io.write_status = IO_ERROR;
    io.fail_cleanup = true;
    assert_eq!(
        table.resize_file_coherent(backing, 0x2000, &mut io),
        IO_ERROR
    );
    assert_eq!(io.file.len(), 0x1800);
    assert_eq!(&io.frames[&101][..], &[0x11; 4096]);
    assert_eq!(table.control_area(section).unwrap().extent, 0x1800);
    assert_eq!(io.prepared, [101]);
}

#[test]
fn cleanup_failure_retains_accepted_eof_and_blocks_new_backing_work_until_retry() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    io.fail_cleanup = true;
    assert_eq!(
        table.resize_file_coherent(backing, 0x1c00, &mut io),
        CLEANUP_ERROR
    );
    assert_eq!(table.control_area(section).unwrap().extent, 0x1c00);
    assert_eq!(io.file.len(), 0x1c00);
    io.events.clear();
    let updated = resized(backing, 0x1c00);
    assert_eq!(
        table.resize_file_coherent(updated, 0x2000, &mut io),
        CLEANUP_ERROR
    );
    assert_eq!(io.events, [Event::Finish]);
    io.fail_cleanup = false;
    assert_eq!(table.resize_file_coherent(updated, 0x2000, &mut io), 0);
    assert!(io.prepared.is_empty());
    assert_eq!(&io.frames[&101][0x800..], &[0; 0x800]);
}

#[test]
fn retirement_ownership_blocks_resize_even_after_last_user_handle_closes() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    table.release_handle(section);
    assert_eq!(
        table.resize_file_coherent(backing, 0, &mut io),
        STATUS_USER_MAPPED_FILE
    );
    assert!(io.events.is_empty());
}

#[test]
fn recreated_section_cannot_bypass_older_retirement_for_the_same_file() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    table.release_handle(section);
    table
        .create(
            2,
            8,
            0x1800,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap();
    assert_eq!(
        table.resize_file_coherent(backing, 0x2000, &mut io),
        STATUS_USER_MAPPED_FILE
    );
    assert!(io.events.is_empty());
}

#[test]
fn unchanged_eof_retries_cleanup_without_touching_canonical_bytes_or_epochs() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    table.mark_page_dirty(section, 1);
    let epoch = table.dirty_epoch;
    io.prepared.push(101);
    assert_eq!(table.resize_file_coherent(backing, 0x1800, &mut io), 0);
    assert_eq!(
        io.events,
        [Event::Finish, Event::Resize(0x1800), Event::Finish]
    );
    assert_eq!(table.dirty_epoch, epoch);
    assert_eq!(&io.frames[&101][..], &[0x11; 4096]);
}

#[test]
fn whole_resident_pages_outside_retained_segment_require_retirement_not_discard() {
    let (mut table, backing, _, mut io) = fixture(0x1000, &[1]);
    assert_eq!(table.resize_file_coherent(backing, 0x3000, &mut io), 0);
    io.events.clear();
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x3000), 0x1000, &mut io),
        STATUS_USER_MAPPED_FILE
    );
    assert_eq!(io.file.len(), 0x3000);
    assert!(io.events.is_empty());
}

#[test]
fn other_file_identity_does_not_borrow_or_zero_this_files_canonical_pages() {
    let (mut table, backing, section, mut io) = fixture(0x1800, &[1]);
    let mut other = backing;
    other.file.as_mut().unwrap().file_id += 1;
    assert_eq!(table.resize_file_coherent(other, 0, &mut io), 0);
    assert_eq!(io.events, [Event::Resize(0), Event::Finish]);
    assert_eq!(&io.frames[&101][..], &[0x11; 4096]);
    assert_eq!(table.control_area(section).unwrap().extent, 0x1800);
}

#[test]
fn malformed_extent_identity_and_epoch_overflow_have_no_io_effects() {
    let (mut table, backing, _, mut io) = fixture(0x1800, &[1]);
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x1700), 0x2000, &mut io),
        STATUS_USER_MAPPED_FILE
    );
    assert_eq!(
        table.resize_file_coherent(GenericSectionBacking::anonymous(), 0, &mut io),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        table.resize_file_coherent(backing, u64::MAX, &mut io),
        STATUS_INVALID_PARAMETER
    );
    table.dirty_epoch = u64::MAX;
    assert_eq!(
        table.resize_file_coherent(backing, 0x2000, &mut io),
        STATUS_INSUFFICIENT_RESOURCES
    );
    assert!(io.events.is_empty());
}

struct FsIo {
    maps: Io,
    fs: nt_fs::FileSystem,
    handle: u64,
}
impl SectionFileWriteIo for FsIo {
    fn begin(&mut self) -> Result<(), u32> {
        self.maps.begin()
    }
    fn rearm_alias(&mut self, alias: SectionPageAlias) -> Result<(), u32> {
        self.maps.rearm_alias(alias)
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        self.maps.prepare_page(page)
    }
    fn write_backing(&mut self, _: u64, _: &[u8]) -> (u32, usize) {
        panic!("resize does not write a data buffer");
    }
    fn copy_resident(&mut self, _: SectionFilePage, _: usize, _: &[u8]) {
        panic!("resize only zeroes changed extents");
    }
    fn zero_resident(&mut self, page: SectionFilePage, offset: usize, length: usize) {
        self.maps.zero_resident(page, offset, length);
    }
    fn finish(&mut self) -> Result<(), u32> {
        self.maps.finish()
    }
}
impl SectionFileResizeIo for FsIo {
    fn resize_backing(&mut self, new_eof: u64) -> u32 {
        self.fs.zw_set_information_file(
            self.handle,
            nt_fs::FILE_END_OF_FILE_INFORMATION,
            &new_eof.to_le_bytes(),
        )
    }
}

#[test]
fn real_memfs_resize_preserves_position_and_unflushed_canonical_prefix() {
    use nt_fs::*;
    let (_, _, _, maps) = fixture(0x1800, &[1]);
    let mut fs = FileSystem::new(MemFs::with_fixture());
    let file = fs.zw_create_file(
        r"\??\C:\Temp\resize",
        FILE_WRITE_DATA | FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        0,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(file.handle, None, &vec![0x11; 0x1800]),
        (STATUS_SUCCESS, 0x1800)
    );
    let backing = GenericSectionBacking::overlay(
        file.handle,
        SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id: fs.zw_query_metadata(file.handle).unwrap().file_id,
        },
        0x1800,
    );
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            1,
            7,
            0x1800,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            backing,
        )
        .unwrap();
    table.set_page_frame(section, 1, 101);
    table.mark_page_dirty(section, 1);
    let mut io = FsIo {
        maps,
        fs,
        handle: file.handle,
    };
    io.maps.frames.get_mut(&101).unwrap()[..0x800].fill(0x77);
    assert_eq!(
        table.resize_file_coherent(backing, 0x2100, &mut io),
        STATUS_SUCCESS
    );
    assert_eq!(io.fs.current_offset(file.handle), Some(0x1800));
    assert_eq!(&io.maps.frames[&101][..0x800], &[0x77; 0x800]);
    assert_eq!(&io.maps.frames[&101][0x800..], &[0; 0x800]);
    let raw = io.fs.file_bytes_owned(r"\??\C:\Temp\resize").unwrap();
    assert_eq!(&raw[..0x1800], &[0x11; 0x1800]);
    assert_eq!(&raw[0x1800..], &[0; 0x900]);
    assert_eq!(
        table.resize_file_coherent(resized(backing, 0x2100), 0x1a00, &mut io),
        STATUS_SUCCESS
    );
    assert_eq!(io.fs.current_offset(file.handle), Some(0x1800));
    assert_eq!(
        io.fs.zw_query_metadata(file.handle).unwrap().end_of_file,
        0x1a00
    );
    let snapshot = io.fs.export_volume_snapshot().unwrap();
    let restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert_eq!(
        restored.file_bytes_owned(r"\??\C:\Temp\resize").unwrap(),
        raw[..0x1a00]
    );
}
