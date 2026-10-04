//! Actual store behavior with host-only type/cleanup ports. These tests do not prove native
//! File pinning, frame retirement, or heap admission under a running guest.
extern crate alloc;

#[allow(dead_code)]
mod file_image_section {
    pub struct LocalImageFile;
}

mod native_image_residency {
    pub unsafe fn purge_area(_: nt_memory_manager::image_section::ImageAreaId) -> Result<(), u32> {
        // No native frames are created by this harness.
        Ok(())
    }
}

#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/native_image_sections.rs"]
mod native_image_sections;

use native_image_sections::{NativeImageError, NativeImageSource, NativeImageStore};
use nt_memory_manager::image_section::{ImageAreaId, ImageFlushError, ImageSectionPurge};
use nt_memory_manager::{GenericSectionBacking, SectionFileIdentity, SectionMountIds};

fn files() -> [SectionFileIdentity; 3] {
    let mut mounts = SectionMountIds::new();
    let a = mounts.allocate().unwrap();
    let b = mounts.allocate().unwrap();
    [
        SectionFileIdentity {
            mount: a,
            file_id: 1,
        },
        SectionFileIdentity {
            mount: a,
            file_id: 2,
        },
        SectionFileIdentity {
            mount: b,
            file_id: 1,
        },
    ]
}

fn publish(
    store: &mut NativeImageStore,
    file: SectionFileIdentity,
) -> native_image_sections::NativeImageSectionId {
    let mut reservation = store.reserve(file).unwrap();
    assert!(reservation.needs_source());
    let mut source = Some(NativeImageSource {
        backing: GenericSectionBacking::disk(7, 4, file),
        pe_header: vec![1, 2, 3, 4],
        local_file: None,
        image_path: Some(b"exact-opened-path".to_vec()),
        observation_target: None,
    });
    let id = store.publish(&mut reservation, &mut source).unwrap();
    assert!(source.is_none() && !reservation.is_pending());
    id
}

struct Purge(usize);
impl ImageSectionPurge for Purge {
    fn purge_image(&mut self, _: ImageAreaId, _: SectionFileIdentity) -> Result<(), u32> {
        self.0 += 1;
        Ok(())
    }
}

#[test]
fn cached_source_rejects_another_stores_live_reservation() {
    let file = files()[0];
    let mut a = NativeImageStore::new();
    let mut b = NativeImageStore::new();
    let a_id = publish(&mut a, file);
    let b_id = publish(&mut b, file);
    let mut reservation = a.reserve(file).unwrap();
    assert!(a.cached_source_for_reservation(&reservation, 4).is_ok());
    assert_eq!(
        b.cached_source_for_reservation(&reservation, 4).err(),
        Some(NativeImageError::InvalidSource)
    );
    assert!(reservation.is_pending());
    a.abort(&mut reservation).unwrap();
    assert!(!reservation.is_pending());
    a.close_handle_group(a_id).unwrap();
    b.close_handle_group(b_id).unwrap();
}

#[test]
fn existing_reservation_borrows_original_source_without_replacing_metadata() {
    let file = files()[0];
    let mut store = NativeImageStore::new();
    let id = publish(&mut store, file);
    let original = store.source(id).unwrap().pe_header.as_ptr();
    let mut reservation = store.reserve(file).unwrap();
    assert!(!reservation.needs_source() && reservation.is_pending());
    let cached = store
        .cached_source_for_reservation(&reservation, 4)
        .unwrap();
    assert_eq!(cached.pe_header.as_ptr(), original);
    assert_eq!(cached.pe_header, [1, 2, 3, 4]);
    assert_eq!(
        cached.image_path.as_deref(),
        Some(&b"exact-opened-path"[..])
    );
    assert_eq!(cached.backing.file, Some(file));
    let mut no_source = None;
    let second = store.publish(&mut reservation, &mut no_source).unwrap();
    assert_eq!(store.source(second).unwrap().pe_header.as_ptr(), original);
    assert_eq!(
        store.cached_source_for_reservation(&reservation, 4).err(),
        Some(NativeImageError::InvalidSource)
    );
    store.close_handle_group(second).unwrap();
    store.close_handle_group(id).unwrap();
}

#[test]
fn distinct_file_or_mount_requires_a_new_source_and_wrong_extent_is_denied() {
    let identities = files();
    let mut store = NativeImageStore::new();
    let id = publish(&mut store, identities[0]);
    let mut existing = store.reserve(identities[0]).unwrap();
    assert!(store.cached_source_for_reservation(&existing, 3).is_err());
    assert!(store.cached_source_for_reservation(&existing, 5).is_err());
    store.abort(&mut existing).unwrap();
    for file in &identities[1..] {
        let mut fresh = store.reserve(*file).unwrap();
        assert!(fresh.needs_source());
        assert!(store.cached_source_for_reservation(&fresh, 4).is_err());
        store.abort(&mut fresh).unwrap();
    }
    store.close_handle_group(id).unwrap();
}

#[test]
fn held_existing_reservation_blocks_purge_until_exact_abort_once() {
    let file = files()[0];
    let mut store = NativeImageStore::new();
    let id = publish(&mut store, file);
    let mut reservation = store.reserve(file).unwrap();
    store.close_handle_group(id).unwrap();
    let mut purge = Purge(0);
    assert!(matches!(
        store.flush_for_write(file, &mut purge),
        Err(ImageFlushError::InUse)
    ));
    assert_eq!(purge.0, 0);
    assert_eq!(
        store
            .cached_source_for_reservation(&reservation, 4)
            .unwrap()
            .pe_header,
        [1, 2, 3, 4]
    );
    store.abort(&mut reservation).unwrap();
    assert!(!reservation.is_pending());
    assert_eq!(
        store.abort(&mut reservation),
        Err(NativeImageError::InvalidSection)
    );
    assert!(store
        .cached_source_for_reservation(&reservation, 4)
        .is_err());
    let retired = store.flush_for_write(file, &mut purge).unwrap().unwrap();
    assert_eq!(retired.pe_header, [1, 2, 3, 4]);
    assert_eq!(purge.0, 1);
    let mut next = store.reserve(file).unwrap();
    assert!(next.needs_source());
    assert!(store.cached_source_for_reservation(&next, 4).is_err());
    store.abort(&mut next).unwrap();
}
