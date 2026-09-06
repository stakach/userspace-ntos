use super::*;
use alloc::vec;

fn file_identity(file_id: u64) -> SectionFileIdentity {
    SectionFileIdentity {
        mount: SectionMountIds::new().allocate().unwrap(),
        file_id,
    }
}

#[derive(Default)]
struct Release {
    frames: Vec<u64>,
    files: Vec<u64>,
    fail_frame: Option<u64>,
    fail_file: bool,
}

impl SectionRetirementIo for Release {
    fn release_frame(&mut self, frame: u64) -> Result<(), u32> {
        if self.fail_frame == Some(frame) {
            return Err(0xc000_009a);
        }
        self.frames.push(frame);
        Ok(())
    }
    fn release_backing(&mut self, backing: GenericSectionBacking) -> Result<(), u32> {
        if self.fail_file {
            return Err(0xc000_0008);
        }
        self.files.push(backing.overlay_file_id);
        Ok(())
    }
}

#[test]
fn failed_unpublished_frames_remain_owned_until_checked_retry() {
    let mut pending = PendingSectionFrames::new();
    let mut io = Release {
        fail_frame: Some(100),
        ..Release::default()
    };
    assert!(pending.reserve());
    pending.release_or_defer(100, &mut io);
    assert!(pending.reserve());
    pending.release_or_defer(101, &mut io);
    assert_eq!(io.frames, [101]);
    assert_eq!(pending.drain(&mut io), Err(0xc000_009a));
    assert_eq!(io.frames, [101]);
    io.fail_frame = None;
    pending.drain(&mut io).unwrap();
    pending.drain(&mut io).unwrap();
    assert_eq!(io.frames, [101, 100]);
    assert!(io.files.is_empty());
}

fn section(table: &mut GenericSectionTable) -> usize {
    table
        .create(
            2,
            0x40,
            0x2000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7, file_identity(7), 0x2000),
        )
        .unwrap()
}

#[test]
fn final_handle_waits_for_every_cross_process_view() {
    let mut table = GenericSectionTable::new();
    let section = section(&mut table);
    table.map_view(3, section, 0x10000, 0x2000, 0);
    table.map_view(4, section, 0x20000, 0x1000, 0x1000);
    table.set_page_frame(section, 0, 100);
    assert!(table.release_handle(section));
    table.unmap_view(3, 0x10000).unwrap();
    assert!(table.next_retirement().is_none());
    table.unmap_view(4, 0x20000).unwrap();
    assert!(table.section(section).is_none());
    assert_eq!(table.page_frame(section, 0), None);
    assert_eq!(table.stats().live_pages, 1, "retired frame remains owned");
    let mut io = Release::default();
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, vec![100]);
    assert_eq!(io.files, vec![7]);
    assert_eq!(table.stats().live_pages, 0);
}

#[test]
fn failed_frame_revoke_preserves_later_frames_and_file() {
    let mut table = GenericSectionTable::new();
    let section = section(&mut table);
    table.set_page_frame(section, 0, 100);
    table.set_page_frame(section, 1, 101);
    table.release_handle(section);
    let mut io = Release {
        fail_frame: Some(101),
        ..Release::default()
    };
    assert_eq!(table.drain_retired(&mut io), Err(0xc000_009a));
    assert_eq!(io.frames, vec![100]);
    assert!(io.files.is_empty());
    assert_eq!(table.stats().live_pages, 1);
    io.fail_frame = None;
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.frames, vec![100, 101]);
    assert_eq!(io.files, vec![7]);
}

#[test]
fn failed_backing_release_is_not_acknowledged_or_reused() {
    let mut table = GenericSectionTable::new();
    let first = section(&mut table);
    table.release_handle(first);
    let mut io = Release {
        fail_file: true,
        ..Release::default()
    };
    assert_eq!(table.drain_retired(&mut io), Err(0xc000_0008));
    let second = section(&mut table);
    assert_ne!(first, second);
    io.fail_file = false;
    table.drain_retired(&mut io).unwrap();
    assert_eq!(io.files, vec![7]);
    assert!(table.section(second).is_some());
}

#[test]
fn stale_handoff_cannot_release_a_reused_section() {
    let mut table = GenericSectionTable::new();
    let first = section(&mut table);
    table.release_handle(first);
    let ticket = table.next_retirement().unwrap();
    assert!(table.complete_retirement(ticket));
    assert_eq!(section(&mut table), first);
    table.release_handle(first);
    assert!(!table.complete_retirement(ticket));
    assert!(table.next_retirement().is_some());
}

#[test]
fn reset_refuses_to_discard_live_or_retired_resources() {
    let mut table = GenericSectionTable::new();
    let section = section(&mut table);
    assert!(!table.reset());
    table.release_handle(section);
    assert!(!table.reset());
    table.drain_retired(&mut Release::default()).unwrap();
    assert!(table.reset());
}

#[test]
fn existing_handle_cannot_replace_owned_backing() {
    let mut table = GenericSectionTable::new();
    let first = section(&mut table);
    table.set_page_frame(first, 0, 100);
    assert_eq!(
        table.create(
            2,
            0x40,
            0x1000,
            crate::PAGE_READONLY,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(99, file_identity(99), 0x2000)
        ),
        None
    );
    assert_eq!(table.section(first).unwrap().backing.overlay_file_id, 7);
    assert_eq!(table.page_frame(first, 0), Some(100));
}

#[test]
fn section_generation_exhaustion_does_not_reuse_identity() {
    let mut table = GenericSectionTable::new();
    table.section_generation = u64::MAX;
    assert_eq!(
        table.create(
            2,
            0x40,
            0x1000,
            crate::PAGE_READONLY,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(7, file_identity(7), 0x2000)
        ),
        None
    );
    assert!(table.next_retirement().is_none());
    assert!(table.reset());
    assert_eq!(table.section_generation, u64::MAX);
}

#[test]
fn delete_on_close_unlinks_name_but_preserves_retained_section_storage() {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let path = r"\??\C:\backing";
    let file = fs.zw_create_file(
        path,
        nt_fs::FILE_READ_DATA | nt_fs::FILE_WRITE_DATA | nt_fs::DELETE,
        0,
        0,
        nt_fs::FILE_CREATE,
        nt_fs::FILE_DELETE_ON_CLOSE,
    );
    assert_eq!(file.status, 0);
    fs.zw_retain_io_reference(file.handle).unwrap();
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            2,
            0x40,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(
                file.handle,
                file_identity(fs.zw_query_metadata(file.handle).unwrap().file_id),
                0x1000,
            ),
        )
        .unwrap();
    assert_eq!(fs.zw_close(file.handle), 0);
    assert!(fs.query_attributes(path).is_none());
    assert_eq!(fs.zw_write_file(file.handle, Some(0), b"mapped"), (0, 6));
    assert_eq!(
        fs.zw_read_file(file.handle, Some(0), 6),
        (0, b"mapped".to_vec())
    );
    table.release_handle(section);
    let ticket = table.next_retirement().unwrap();
    assert_eq!(
        ticket.resource,
        SectionRetirementResource::Backing(GenericSectionBacking::overlay(
            file.handle,
            file_identity(fs.zw_query_metadata(file.handle).unwrap().file_id),
            0x1000
        ))
    );
    fs.zw_release_io_reference(file.handle).unwrap();
    assert!(table.complete_retirement(ticket));
    assert!(fs.zw_query_metadata(file.handle).is_none());
    assert!(fs.zw_release_io_reference(file.handle).is_err());
}

#[test]
fn retained_section_backing_survives_file_close_and_reopen_without_holding_share_access() {
    let mut fs = nt_fs::FileSystem::new(nt_fs::MemFs::new());
    let file = fs.zw_create_file(
        r"\??\C:\backing",
        nt_fs::FILE_READ_DATA | nt_fs::FILE_WRITE_DATA,
        0,
        0,
        nt_fs::FILE_CREATE,
        0,
    );
    assert_eq!(file.status, 0);
    assert_eq!(fs.zw_write_file(file.handle, Some(0), b"source"), (0, 6));
    let identity = fs.zw_query_metadata(file.handle).unwrap().file_id;
    fs.zw_retain_io_reference(file.handle).unwrap();
    let mut table = GenericSectionTable::new();
    let section = table
        .create(
            2,
            0x40,
            0x1000,
            crate::PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::overlay(
                file.handle,
                file_identity(fs.zw_query_metadata(file.handle).unwrap().file_id),
                0x1000,
            ),
        )
        .unwrap();
    table.map_view(3, section, 0x10000, 0x1000, 0);
    table.release_handle(section);
    assert_eq!(fs.zw_close(file.handle), 0);
    let reopened = fs.zw_create_file(
        r"\??\C:\backing",
        nt_fs::FILE_READ_DATA | nt_fs::FILE_WRITE_DATA,
        0,
        0,
        nt_fs::FILE_OPEN,
        0,
    );
    assert_eq!(
        reopened.status, 0,
        "section reference must not prolong share access"
    );
    assert_ne!(
        reopened.handle, file.handle,
        "referenced FILE_OBJECT slot cannot be reused"
    );
    assert_eq!(
        fs.zw_query_metadata(reopened.handle).unwrap().file_id,
        identity
    );
    let backing = table.section(section).unwrap().backing.overlay_file_id;
    assert_eq!(
        fs.zw_read_file(backing, Some(0), 6),
        (0, b"source".to_vec())
    );
    assert_eq!(fs.zw_write_file(backing, Some(0), b"mapped"), (0, 6));
    assert_eq!(fs.zw_flush_buffers_file(backing), 0);
    assert_eq!(
        fs.zw_read_file(reopened.handle, Some(0), 6),
        (0, b"mapped".to_vec())
    );
    table.unmap_view(3, 0x10000).unwrap();
    let ticket = table.next_retirement().unwrap();
    assert_eq!(
        ticket.resource,
        SectionRetirementResource::Backing(GenericSectionBacking::overlay(
            backing,
            file_identity(identity),
            0x1000
        ))
    );
    fs.zw_release_io_reference(backing).unwrap();
    assert!(table.complete_retirement(ticket));
    assert!(fs.zw_query_metadata(backing).is_none());
    assert!(fs.zw_release_io_reference(backing).is_err());
    assert!(fs.zw_query_metadata(reopened.handle).is_some());
}
