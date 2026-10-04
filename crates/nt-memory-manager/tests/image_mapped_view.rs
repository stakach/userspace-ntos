use nt_memory_manager::image_section::{
    ImageAcquire, ImageAreaId, ImageFlushError, ImageMappedViewPhase, ImageSectionError,
    ImageSectionPurge, ImageSectionRef, ImageSectionTable,
};
use nt_memory_manager::{ProcessGeneration, ProcessIdentity, SectionFileIdentity, SectionMountIds};

fn process(generation: u64) -> ProcessIdentity {
    ProcessIdentity { pid: 304, generation: ProcessGeneration::Hosted(generation) }
}

fn section(table: &mut ImageSectionTable, file: SectionFileIdentity) -> ImageSectionRef {
    match table.acquire(file).unwrap() {
        ImageAcquire::Create(creation) => table.publish(creation).unwrap(),
        ImageAcquire::Section(section) => section,
    }
}

#[derive(Default)]
struct Purge(usize);
impl ImageSectionPurge for Purge {
    fn purge_image(&mut self, _: ImageAreaId, _: SectionFileIdentity) -> Result<(), u32> {
        self.0 += 1;
        Ok(())
    }
}

fn file() -> SectionFileIdentity {
    SectionFileIdentity { mount: SectionMountIds::new().allocate().unwrap(), file_id: 91 }
}

#[test]
fn published_mapping_survives_handle_close_and_output_fault_until_cleanup_ack() {
    let mut table = ImageSectionTable::new();
    let file = file();
    let section = section(&mut table, file);
    let view = table.reserve_mapped_view(section, process(2), 0x1000_8000_0000, 0x12000).unwrap();
    let prepared = table.mapped_view(view).unwrap();
    assert_eq!(prepared.process, process(2));
    assert_eq!(prepared.base, 0x1000_8000_0000);
    assert_eq!(prepared.size, 0x12000);
    assert_eq!(prepared.phase, ImageMappedViewPhase::Prepared);
    table.begin_mapped_view_mapping(view, process(2)).unwrap();
    table.publish_mapped_view(view).unwrap();
    table.close_section(section).unwrap();
    // A failed user output store does not withdraw a committed view or its backing reference.
    assert_eq!(table.mapped_view(view).unwrap().phase, ImageMappedViewPhase::Mapped);
    assert_eq!(table.release_view(view), Err(ImageSectionError::InvalidReference));
    let mut purge = Purge::default();
    assert_eq!(table.flush_for_write(file, &mut purge), Err(ImageFlushError::InUse));
    let receipt = table.begin_mapped_view_retirement(view, process(2)).unwrap();
    assert_eq!(table.mapped_view(view).unwrap().phase, ImageMappedViewPhase::Retiring);
    // A refused cleanup has no ACK: the same owner and receipt remain retained.
    assert_eq!(table.flush_for_write(file, &mut purge), Err(ImageFlushError::InUse));
    assert_eq!(purge.0, 0);
    table.acknowledge_mapped_view_retirement(receipt).unwrap();
    assert_eq!(table.acknowledge_mapped_view_retirement(receipt), Err(ImageSectionError::InvalidReference));
    assert!(table.mapped_view(view).is_none());
    assert_eq!(table.flush_for_write(file, &mut purge), Ok(()));
    assert_eq!(purge.0, 1);
}

#[test]
fn mapped_view_identity_rejects_foreign_authority_stale_process_and_duplicate_publication() {
    let mut table = ImageSectionTable::new();
    let mut foreign = ImageSectionTable::new();
    let file = file();
    let own = section(&mut table, file);
    let other = section(&mut foreign, file);
    assert_eq!(table.reserve_mapped_view(other, process(2), 0x10000, 0x1000),
        Err(ImageSectionError::InvalidReference));
    assert_eq!(table.reserve_mapped_view(own, process(0), 0x10000, 0x1000),
        Err(ImageSectionError::InvalidReference));
    assert_eq!(table.reserve_mapped_view(own, process(2), u64::MAX - 0xfff, 0x2000),
        Err(ImageSectionError::InvalidReference));
    let view = table.reserve_mapped_view(own, process(2), 0x10000, 0x2000).unwrap();
    assert_eq!(foreign.publish_mapped_view(view), Err(ImageSectionError::InvalidReference));
    table.begin_mapped_view_mapping(view, process(2)).unwrap();
    table.publish_mapped_view(view).unwrap();
    assert_eq!(table.publish_mapped_view(view), Err(ImageSectionError::InvalidReference));
    assert_eq!(table.begin_mapped_view_retirement(view, process(3)),
        Err(ImageSectionError::InvalidReference));
    assert_eq!(table.mapped_view(view).unwrap().phase, ImageMappedViewPhase::Mapped);
    let receipt = table.begin_mapped_view_retirement(view, process(2)).unwrap();
    assert_eq!(foreign.acknowledge_mapped_view_retirement(receipt),
        Err(ImageSectionError::InvalidReference));
    table.acknowledge_mapped_view_retirement(receipt).unwrap();
    let replacement = table.reserve_mapped_view(own, process(3), 0x10000, 0x2000).unwrap();
    assert_ne!(replacement, view);
    assert_eq!(table.acknowledge_mapped_view_retirement(receipt), Err(ImageSectionError::InvalidReference));
    assert_eq!(table.mapped_view(replacement).unwrap().phase, ImageMappedViewPhase::Prepared);
}

#[test]
fn distinct_views_share_only_exact_image_area_and_uncertain_mapping_blocks_reuse() {
    let mut table = ImageSectionTable::new();
    let file = file();
    let first_section = section(&mut table, file);
    let second_section = section(&mut table, file);
    let first = table.reserve_mapped_view(first_section, process(2), 0x10000, 0x2000).unwrap();
    let second = table.reserve_mapped_view(second_section, process(3), 0x10000, 0x2000).unwrap();
    assert_ne!(first, second);
    assert_eq!(first.area(), second.area());
    table.begin_mapped_view_mapping(second, process(3)).unwrap();
    table.publish_mapped_view(second).unwrap();
    table.begin_mapped_view_mapping(first, process(2)).unwrap();
    table.quarantine_mapped_view(first).unwrap();
    assert_eq!(table.mapped_view(first).unwrap().phase, ImageMappedViewPhase::Quarantined);
    assert_eq!(table.publish_mapped_view(first), Err(ImageSectionError::InvalidReference));
    assert_eq!(table.begin_mapped_view_retirement(first, process(2)),
        Err(ImageSectionError::InvalidReference));
    assert_eq!(table.release_view(first), Err(ImageSectionError::InvalidReference));
    table.close_section(first_section).unwrap();
    table.close_section(second_section).unwrap();
    let receipt = table.begin_mapped_view_retirement(second, process(3)).unwrap();
    table.acknowledge_mapped_view_retirement(receipt).unwrap();
    assert_eq!(table.flush_for_write(file, &mut Purge::default()), Err(ImageFlushError::InUse));
}

#[test]
fn only_known_unentered_mapping_can_abort_without_cleanup_ack() {
    let mut table = ImageSectionTable::new();
    let file = file();
    let section = section(&mut table, file);
    let prepared = table.reserve_mapped_view(section, process(2), 0x10000, 0x2000).unwrap();
    assert_eq!(table.publish_mapped_view(prepared), Err(ImageSectionError::InvalidReference));
    assert_eq!(table.abort_prepared_mapped_view(prepared, process(3)), Err(ImageSectionError::InvalidReference));
    table.abort_prepared_mapped_view(prepared, process(2)).unwrap();
    assert_eq!(table.abort_prepared_mapped_view(prepared, process(2)), Err(ImageSectionError::InvalidReference));
    let entered = table.reserve_mapped_view(section, process(2), 0x10000, 0x2000).unwrap();
    table.begin_mapped_view_mapping(entered, process(2)).unwrap();
    assert_eq!(table.begin_mapped_view_mapping(entered, process(2)), Err(ImageSectionError::InvalidReference));
    assert_eq!(table.abort_prepared_mapped_view(entered, process(2)), Err(ImageSectionError::InvalidReference));
    let receipt = table.begin_mapped_view_retirement(entered, process(2)).unwrap();
    assert_eq!(table.begin_mapped_view_retirement(entered, process(2)), Ok(receipt));
    table.quarantine_mapped_view(entered).unwrap();
    assert_eq!(table.acknowledge_mapped_view_retirement(receipt), Err(ImageSectionError::InvalidReference));
    table.close_section(section).unwrap();
    assert_eq!(table.flush_for_write(file, &mut Purge::default()), Err(ImageFlushError::InUse));
}
