//! Actual store behavior with host-only type/cleanup ports. These tests do not prove native
//! File pinning, frame retirement, or heap admission under a running guest.
extern crate alloc;

#[allow(dead_code)]
mod file_image_section {
    pub struct LocalImageFile;
    impl LocalImageFile {
        pub fn read_exact(
            &self,
            _: &crate::ExecNtHandler,
            _: nt_memory_manager::GenericSectionBacking,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), u32> {
            Err(nt_fs::STATUS_INVALID_HANDLE)
        }
    }
}

struct ExecNtHandler;

mod hosted_routed_image_capture {
    use nt_memory_manager::image_section::ImageAreaId;
    use nt_memory_manager::RoutedSectionLease;
    use std::sync::Mutex;

    static ROUTES: Mutex<Vec<(RoutedSectionLease, ImageAreaId)>> = Mutex::new(Vec::new());

    pub fn bind(lease: RoutedSectionLease, area: ImageAreaId) {
        ROUTES.lock().unwrap().push((lease, area));
    }

    pub fn release(lease: RoutedSectionLease, area: ImageAreaId) {
        let mut routes = ROUTES.lock().unwrap();
        let index = routes.iter().position(|route| *route == (lease, area)).unwrap();
        routes.swap_remove(index);
    }

    pub unsafe fn route(
        lease: RoutedSectionLease,
        area: ImageAreaId,
    ) -> Option<(u64, u64, u64, u32)> {
        ROUTES
            .lock()
            .unwrap()
            .contains(&(lease, area))
            .then_some((lease.value(), 1, lease.value(), nt_fs::FILE_READ_DATA))
    }
}

mod routed_section_io {
    pub fn read_retained(
        file_id: u64,
        device_id: u64,
        file_context: u64,
        offset: u64,
        output: &mut [u8],
    ) -> (u32, usize) {
        if device_id != 1 || file_context != file_id {
            return (nt_fs::STATUS_INVALID_HANDLE, 0);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = (file_id.wrapping_add(offset).wrapping_add(index as u64) & 0xff) as u8;
        }
        (0, output.len())
    }
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

#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/native_image_source_io.rs"]
mod native_image_source_io;

use native_image_sections::{NativeImageContents, NativeImageError, NativeImageSource, NativeImageStore};
use nt_memory_manager::image_section::{ImageAreaId, ImageFlushError, ImageSectionPurge};
use nt_memory_manager::{GenericSectionBacking, SectionFileIdentity, SectionMountIds};
use nt_memory_manager::RoutedSectionLease;

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

const FILE_EXTENT: u64 = 512;

fn image_bytes() -> Vec<u8> {
    let mut bytes = vec![0; FILE_EXTENT as usize];
    bytes[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
    bytes[64..68].copy_from_slice(&0x4550u32.to_le_bytes());
    bytes[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[84..86].copy_from_slice(&112u16.to_le_bytes());
    bytes[86..88].copy_from_slice(&2u16.to_le_bytes());
    bytes[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x180000000u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&4096u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&512u32.to_le_bytes());
    bytes[144..148].copy_from_slice(&4096u32.to_le_bytes());
    bytes[148..152].copy_from_slice(&512u32.to_le_bytes());
    bytes
}

fn snapshot(source: &NativeImageSource) -> &[u8] {
    match &source.contents {
        NativeImageContents::Snapshot(bytes) => bytes,
        NativeImageContents::RetainedDisk | NativeImageContents::RetainedRouted => {
            panic!("host fixture owns an explicit snapshot")
        }
    }
}

fn publish(
    store: &mut NativeImageStore,
    file: SectionFileIdentity,
) -> native_image_sections::NativeImageSectionId {
    let mut reservation = store.reserve(file).unwrap();
    assert!(reservation.needs_source());
    let bytes = image_bytes();
    let mut source = Some(NativeImageSource {
        backing: GenericSectionBacking::disk(7, FILE_EXTENT as u32, file),
        layout: nt_pe_loader::PeLayout::parse(&bytes).unwrap(),
        contents: NativeImageContents::Snapshot(bytes),
        local_file: None,
        image_path: Some(b"exact-opened-path".to_vec()),
        registered_file: None,
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
fn retained_disk_source_needs_its_file_pin_not_a_complete_payload_vec() {
    let file = files()[0];
    let mut store = NativeImageStore::new();
    let mut reservation = store.reserve(file).unwrap();
    let mut source = Some(NativeImageSource {
        backing: GenericSectionBacking::disk(7, FILE_EXTENT as u32, file),
        layout: nt_pe_loader::PeLayout::parse(&image_bytes()).unwrap(),
        contents: NativeImageContents::RetainedDisk,
        local_file: None,
        image_path: Some(b"exact-opened-path".to_vec()),
        registered_file: None,
        observation_target: None,
    });
    assert_eq!(store.publish(&mut reservation, &mut source), Err(NativeImageError::InvalidSource));
    assert!(reservation.is_pending() && source.is_some());
    source.as_mut().unwrap().local_file = Some(file_image_section::LocalImageFile);
    let id = store.publish(&mut reservation, &mut source).unwrap();
    let mut cached = store.reserve(file).unwrap();
    let exact = store.cached_source_for_reservation(&cached, FILE_EXTENT).unwrap();
    assert!(matches!(exact.contents, NativeImageContents::RetainedDisk));
    assert_eq!(exact.layout.headers().size_of_image, 4096);
    store.abort(&mut cached).unwrap();
    store.close_handle_group(id).unwrap();
}

#[test]
fn cached_source_rejects_another_stores_live_reservation() {
    let file = files()[0];
    let mut a = NativeImageStore::new();
    let mut b = NativeImageStore::new();
    let a_id = publish(&mut a, file);
    let b_id = publish(&mut b, file);
    let mut reservation = a.reserve(file).unwrap();
    assert!(a.cached_source_for_reservation(&reservation, FILE_EXTENT).is_ok());
    assert_eq!(
        b.cached_source_for_reservation(&reservation, FILE_EXTENT).err(),
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
    let original = snapshot(store.source(id).unwrap()).as_ptr();
    let mut reservation = store.reserve(file).unwrap();
    assert!(!reservation.needs_source() && reservation.is_pending());
    let cached = store
        .cached_source_for_reservation(&reservation, FILE_EXTENT)
        .unwrap();
    assert_eq!(snapshot(cached).as_ptr(), original);
    assert_eq!(snapshot(cached), image_bytes());
    assert_eq!(
        cached.image_path.as_deref(),
        Some(&b"exact-opened-path"[..])
    );
    assert_eq!(cached.backing.file, Some(file));
    let mut no_source = None;
    let second = store.publish(&mut reservation, &mut no_source).unwrap();
    assert_eq!(snapshot(store.source(second).unwrap()).as_ptr(), original);
    assert_eq!(
        store.cached_source_for_reservation(&reservation, FILE_EXTENT).err(),
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
    assert!(store.cached_source_for_reservation(&existing, FILE_EXTENT - 1).is_err());
    assert!(store.cached_source_for_reservation(&existing, FILE_EXTENT + 1).is_err());
    store.abort(&mut existing).unwrap();
    for file in &identities[1..] {
        let mut fresh = store.reserve(*file).unwrap();
        assert!(fresh.needs_source());
        assert!(store.cached_source_for_reservation(&fresh, FILE_EXTENT).is_err());
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
        snapshot(store.cached_source_for_reservation(&reservation, FILE_EXTENT).unwrap()),
        image_bytes()
    );
    store.abort(&mut reservation).unwrap();
    assert!(!reservation.is_pending());
    assert_eq!(
        store.abort(&mut reservation),
        Err(NativeImageError::InvalidSection)
    );
    assert!(store
        .cached_source_for_reservation(&reservation, FILE_EXTENT)
        .is_err());
    let retired = store.flush_for_write(file, &mut purge).unwrap().unwrap();
    assert_eq!(snapshot(&retired), image_bytes());
    assert_eq!(purge.0, 1);
    let mut next = store.reserve(file).unwrap();
    assert!(next.needs_source());
    assert!(store.cached_source_for_reservation(&next, FILE_EXTENT).is_err());
    store.abort(&mut next).unwrap();
}

#[test]
fn permanent_immutable_routed_images_keep_file_owners_without_heap_sized_snapshots() {
    const IMAGE_COUNT: usize = 10;
    const IMAGE_EXTENT: u64 = 8 * 1024 * 1024;
    assert!(IMAGE_COUNT as u64 * IMAGE_EXTENT > 64 * 1024 * 1024);

    let mount = SectionMountIds::new().allocate().unwrap();
    let mut store = NativeImageStore::new();
    let mut ids = Vec::new();
    let mut file_ids = Vec::new();
    let mut areas = Vec::new();
    for index in 0..IMAGE_COUNT {
        let file = SectionFileIdentity {
            mount,
            file_id: index as u64 + 1,
        };
        let lease = RoutedSectionLease::new(index as u64 + 1).unwrap();
        let mut reservation = store.reserve(file).unwrap();
        let mut source = Some(NativeImageSource {
            backing: GenericSectionBacking::routed(lease, file, IMAGE_EXTENT),
            layout: nt_pe_loader::PeLayout::parse(&image_bytes()).unwrap(),
            contents: NativeImageContents::RetainedRouted,
            local_file: None,
            image_path: None,
            registered_file: None,
            observation_target: None,
        });
        let id = store.publish(&mut reservation, &mut source).unwrap();
        assert!(source.is_none());
        let area = store.area(id).unwrap();
        hosted_routed_image_capture::bind(lease, area);
        store.make_permanent(id).unwrap();
        store.close_handle_group(id).unwrap();
        let retained = store.source(id).unwrap();
        assert!(retained.has_readable_image());
        assert_eq!(retained.backing.routed_lease, Some(lease));
        assert!(matches!(retained.contents, NativeImageContents::RetainedRouted));
        let mut page_tail = [0u8; 17];
        retained
            .read_exact(&ExecNtHandler, area, IMAGE_EXTENT - 17, &mut page_tail)
            .unwrap();
        assert!(page_tail.iter().enumerate().all(|(byte, value)| {
            *value == ((index as u64 + 1 + IMAGE_EXTENT - 17 + byte as u64) & 0xff) as u8
        }));
        ids.push(id);
        file_ids.push(file);
        areas.push(area);
    }

    // A permanent namespace reference keeps each exact File owner until withdrawal and purge.
    let mut purge = Purge(0);
    for file in &file_ids {
        assert!(store.flush_for_write(*file, &mut purge).is_err());
    }
    assert_eq!(purge.0, 0);
    for ((id, file), area) in ids.into_iter().zip(file_ids).zip(areas) {
        store.withdraw_permanent(id).unwrap();
        let retired = store.flush_for_write(file, &mut purge).unwrap().unwrap();
        assert!(matches!(retired.contents, NativeImageContents::RetainedRouted));
        assert_eq!(retired.backing.file, Some(file));
        let lease = retired.backing.routed_lease.unwrap();
        hosted_routed_image_capture::release(lease, area);
        assert_eq!(
            retired.read_exact(&ExecNtHandler, area, 0, &mut [0u8; 1]),
            Err(nt_fs::STATUS_INVALID_HANDLE)
        );
    }
    assert_eq!(purge.0, IMAGE_COUNT);
}
