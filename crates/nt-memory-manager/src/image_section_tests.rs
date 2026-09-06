use super::*;
use crate::SectionMountIds;

fn file() -> SectionFileIdentity {
    let mut mounts = SectionMountIds::new();
    SectionFileIdentity {
        mount: mounts.allocate().unwrap(),
        file_id: 37,
    }
}

fn creation(table: &mut ImageSectionTable, file: SectionFileIdentity) -> ImageCreation {
    match table.acquire(file).unwrap() {
        ImageAcquire::Create(creation) => creation,
        ImageAcquire::Section(_) => panic!("expected new image"),
    }
}

fn section(table: &mut ImageSectionTable, file: SectionFileIdentity) -> ImageSectionRef {
    match table.acquire(file).unwrap() {
        ImageAcquire::Create(creation) => table.publish(creation).unwrap(),
        ImageAcquire::Section(section) => section,
    }
}

#[derive(Default)]
struct Purge {
    calls: Vec<(ImageAreaId, SectionFileIdentity)>,
    failure: Option<u32>,
}

impl ImageSectionPurge for Purge {
    fn purge_image(&mut self, area: ImageAreaId, file: SectionFileIdentity) -> Result<(), u32> {
        self.calls.push((area, file));
        self.failure.map_or(Ok(()), Err)
    }
}

#[test]
fn absent_image_needs_no_purge() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    assert_eq!(table.flush_for_write(file(), &mut io), Ok(()));
    assert!(io.calls.is_empty());
    assert_eq!(table.generation, 0);
}

#[test]
fn creation_is_exclusive_and_blocks_write_admission() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    let create = creation(&mut table, file());
    assert_eq!(table.file_identity(create.area()), Some(file()));
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::CreationInProgress)
    );
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    assert!(io.calls.is_empty());
    let section = table.publish(create).unwrap();
    assert_eq!(section.area(), create.area());
    assert_eq!(
        table.publish(create),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.abort(create),
        Err(ImageSectionError::InvalidReference)
    );
}

#[test]
fn handle_only_image_blocks_until_close_then_requires_real_purge() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    let section = section(&mut table, file());
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    assert!(io.calls.is_empty());
    table.close_section(section).unwrap();
    assert_eq!(table.file_identity(section.area()), Some(file()));
    assert_eq!(table.flush_for_write(file(), &mut io), Ok(()));
    assert_eq!(io.calls, [(section.area(), file())]);
    assert_eq!(table.file_identity(section.area()), None);
    assert_eq!(table.flush_for_write(file(), &mut io), Ok(()));
    assert_eq!(io.calls.len(), 1);
}

#[test]
fn each_section_and_view_owns_an_independent_reference() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    let first = section(&mut table, file());
    let second = section(&mut table, file());
    let duplicate = table.duplicate_section(first).unwrap();
    assert_ne!(first, second);
    assert_ne!(first, duplicate);
    assert_eq!(first.area(), second.area());
    let view = table.reference_view(second).unwrap();
    let other_view = table.reference_view(first).unwrap();
    assert_eq!(view.area(), first.area());
    for handle in [second, first, duplicate] {
        table.close_section(handle).unwrap();
        assert_eq!(
            table.flush_for_write(file(), &mut io),
            Err(ImageFlushError::InUse)
        );
    }
    table.release_view(view).unwrap();
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    table.release_view(other_view).unwrap();
    assert_eq!(table.flush_for_write(file(), &mut io), Ok(()));
    assert_eq!(io.calls, [(first.area(), file())]);
}

#[test]
fn idle_cache_can_be_reused_before_purge_but_not_without_a_reference() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    let original = section(&mut table, file());
    table.close_section(original).unwrap();
    let reopened = match table.acquire(file()).unwrap() {
        ImageAcquire::Section(handle) => handle,
        ImageAcquire::Create(_) => panic!("idle image cache was lost"),
    };
    assert_eq!(original.area(), reopened.area());
    assert_ne!(original, reopened);
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    assert_eq!(
        table.reference_view(original),
        Err(ImageSectionError::InvalidReference)
    );
    assert!(io.calls.is_empty());
}

#[test]
fn aborted_creation_retains_identity_until_checked_cleanup() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    let create = creation(&mut table, file());
    table.abort(create).unwrap();
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::CleanupPending)
    );
    assert_eq!(
        table.publish(create),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.abort(create),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(table.file_identity(create.area()), Some(file()));
    table.flush_for_write(file(), &mut io).unwrap();
    assert_eq!(io.calls, [(create.area(), file())]);
    assert_eq!(table.file_identity(create.area()), None);
    let replacement = creation(&mut table, file());
    assert_ne!(replacement, create);
}

#[test]
fn failed_purge_keeps_exact_owner_and_blocks_cache_reuse_until_retry() {
    let mut table = ImageSectionTable::new();
    let section = section(&mut table, file());
    table.close_section(section).unwrap();
    let mut io = Purge {
        failure: Some(0xc000_0001),
        ..Purge::default()
    };
    for _ in 0..3 {
        assert_eq!(
            table.flush_for_write(file(), &mut io),
            Err(ImageFlushError::PurgeFailed(0xc000_0001))
        );
        assert_eq!(table.file_identity(section.area()), Some(file()));
        assert_eq!(
            table.acquire(file()),
            Err(ImageSectionError::CleanupPending)
        );
    }
    io.failure = None;
    table.flush_for_write(file(), &mut io).unwrap();
    assert_eq!(io.calls, [(section.area(), file()); 4]);
    assert_eq!(table.file_identity(section.area()), None);
    assert_ne!(creation(&mut table, file()).area(), section.area());
}

#[test]
fn abort_cleanup_failure_cannot_publish_the_old_creation() {
    let mut table = ImageSectionTable::new();
    let create = creation(&mut table, file());
    table.abort(create).unwrap();
    let mut io = Purge {
        failure: Some(9),
        ..Purge::default()
    };
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::PurgeFailed(9))
    );
    assert_eq!(
        table.publish(create),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::CleanupPending)
    );
    io.failure = None;
    table.flush_for_write(file(), &mut io).unwrap();
}

#[test]
fn partial_resource_purge_retries_only_retained_resources_without_writeback() {
    struct Resources {
        owner: ImageAreaId,
        file: SectionFileIdentity,
        aliases: usize,
        frames: usize,
        parsed_cache: bool,
        backing: bool,
        fail_frame: bool,
    }
    impl ImageSectionPurge for Resources {
        fn purge_image(&mut self, area: ImageAreaId, file: SectionFileIdentity) -> Result<(), u32> {
            assert_eq!((area, file), (self.owner, self.file));
            self.aliases = 0;
            if self.fail_frame {
                return Err(17);
            }
            self.frames = 0;
            self.parsed_cache = false;
            self.backing = false;
            Ok(())
        }
    }
    let mut table = ImageSectionTable::new();
    let section = section(&mut table, file());
    let mut io = Resources {
        owner: section.area(),
        file: file(),
        aliases: 2,
        frames: 3,
        parsed_cache: true,
        backing: true,
        fail_frame: true,
    };
    table.close_section(section).unwrap();
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::PurgeFailed(17))
    );
    assert_eq!(
        (io.aliases, io.frames, io.parsed_cache, io.backing),
        (0, 3, true, true)
    );
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::CleanupPending)
    );
    io.fail_frame = false;
    table.flush_for_write(file(), &mut io).unwrap();
    assert_eq!(
        (io.aliases, io.frames, io.parsed_cache, io.backing),
        (0, 0, false, false)
    );
}

#[test]
fn mounts_and_file_ids_are_both_part_of_identity() {
    let mut mounts = SectionMountIds::new();
    let first = file();
    assert_eq!(mounts.allocate(), Some(first.mount));
    let second = SectionFileIdentity {
        mount: mounts.allocate().unwrap(),
        ..first
    };
    let third = SectionFileIdentity {
        file_id: first.file_id + 1,
        ..first
    };
    let mut table = ImageSectionTable::new();
    let a = section(&mut table, first);
    let b = section(&mut table, second);
    let c = section(&mut table, third);
    assert_ne!(a.area(), b.area());
    assert_ne!(a.area(), c.area());
    table.close_section(b).unwrap();
    let mut io = Purge::default();
    table.flush_for_write(second, &mut io).unwrap();
    assert_eq!(io.calls, [(b.area(), second)]);
    for file in [first, third] {
        assert_eq!(
            table.flush_for_write(file, &mut io),
            Err(ImageFlushError::InUse)
        );
    }
}

#[test]
fn foreign_table_tokens_cannot_publish_close_map_or_release() {
    let mut a = ImageSectionTable::new();
    let mut b = ImageSectionTable::new();
    let ca = creation(&mut a, file());
    let cb = creation(&mut b, file());
    assert_ne!(ca, cb);
    assert_eq!(b.publish(ca), Err(ImageSectionError::InvalidReference));
    assert_eq!(b.abort(ca), Err(ImageSectionError::InvalidReference));
    let sa = a.publish(ca).unwrap();
    let sb = b.publish(cb).unwrap();
    let va = a.reference_view(sa).unwrap();
    let _vb = b.reference_view(sb).unwrap();
    assert_eq!(
        b.close_section(sa),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        b.duplicate_section(sa),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        b.reference_view(sa),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(b.release_view(va), Err(ImageSectionError::InvalidReference));
    assert_eq!(b.file_identity(sa.area()), None);
}

#[test]
fn recycled_slots_reject_stale_creation_section_and_view_tokens() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    let old_creation = creation(&mut table, file());
    let old_section = table.publish(old_creation).unwrap();
    let old_view = table.reference_view(old_section).unwrap();
    table.close_section(old_section).unwrap();
    table.release_view(old_view).unwrap();
    table.flush_for_write(file(), &mut io).unwrap();
    let new_creation = creation(&mut table, file());
    assert_eq!(
        table.publish(old_creation),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.abort(old_creation),
        Err(ImageSectionError::InvalidReference)
    );
    let new_section = table.publish(new_creation).unwrap();
    let _new_view = table.reference_view(new_section).unwrap();
    assert_eq!(
        table.close_section(old_section),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.duplicate_section(old_section),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.reference_view(old_section),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(
        table.release_view(old_view),
        Err(ImageSectionError::InvalidReference)
    );
    assert_eq!(table.file_identity(old_creation.area()), None);
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    assert_eq!(table.areas.len(), 1);
    assert_eq!(table.references.len(), 2);
}

#[test]
fn double_close_does_not_release_a_different_reference_in_the_same_area() {
    let mut table = ImageSectionTable::new();
    let original = section(&mut table, file());
    table.close_section(original).unwrap();
    let sibling = section(&mut table, file());
    assert_eq!(
        table.close_section(original),
        Err(ImageSectionError::InvalidReference)
    );
    let view = table.reference_view(sibling).unwrap();
    table.release_view(view).unwrap();
    let other_view = table.reference_view(sibling).unwrap();
    assert_eq!(
        table.release_view(view),
        Err(ImageSectionError::InvalidReference)
    );
    table.close_section(sibling).unwrap();
    let mut io = Purge::default();
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    table.release_view(other_view).unwrap();
    table.flush_for_write(file(), &mut io).unwrap();
}

#[test]
fn publication_exhaustion_keeps_creation_owned_and_abortable() {
    let mut table = ImageSectionTable::new();
    let create = creation(&mut table, file());
    table.generation = u64::MAX;
    assert_eq!(
        table.publish(create),
        Err(ImageSectionError::InsufficientResources)
    );
    assert!(table.references.is_empty());
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::CreationInProgress)
    );
    let mut io = Purge::default();
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    table.abort(create).unwrap();
    table.flush_for_write(file(), &mut io).unwrap();
    assert_eq!(io.calls, [(create.area(), file())]);
}

#[test]
fn reference_exhaustion_does_not_publish_or_drop_owners() {
    let mut table = ImageSectionTable::new();
    let section = section(&mut table, file());
    table.generation = u64::MAX;
    assert_eq!(
        table.duplicate_section(section),
        Err(ImageSectionError::InsufficientResources)
    );
    assert_eq!(
        table.reference_view(section),
        Err(ImageSectionError::InsufficientResources)
    );
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::InsufficientResources)
    );
    assert_eq!(table.references.len(), 1);
    let mut io = Purge::default();
    assert_eq!(
        table.flush_for_write(file(), &mut io),
        Err(ImageFlushError::InUse)
    );
    table.close_section(section).unwrap();
    table.flush_for_write(file(), &mut io).unwrap();
}

#[test]
fn creation_exhaustion_does_not_publish_an_area_or_wrap_ids() {
    let mut table = ImageSectionTable::new();
    table.generation = u64::MAX;
    assert_eq!(
        table.acquire(file()),
        Err(ImageSectionError::InsufficientResources)
    );
    assert!(table.areas.is_empty());
    assert_eq!(table.generation, u64::MAX);
    let mut io = Purge::default();
    table.flush_for_write(file(), &mut io).unwrap();
    assert!(io.calls.is_empty());
}

#[test]
fn repeated_lifetimes_reuse_storage_without_reusing_ids() {
    let mut table = ImageSectionTable::new();
    let mut io = Purge::default();
    for _ in 0..1000 {
        let a = section(&mut table, file());
        let b = table.duplicate_section(a).unwrap();
        let view = table.reference_view(b).unwrap();
        table.close_section(a).unwrap();
        table.close_section(b).unwrap();
        table.release_view(view).unwrap();
        table.flush_for_write(file(), &mut io).unwrap();
    }
    assert_eq!(table.areas.len(), 1);
    assert_eq!(table.references.len(), 3);
    assert!(io.calls.windows(2).all(|calls| calls[0].0 != calls[1].0));
}
