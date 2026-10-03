use nt_exe_image::{
    HostedImageRoot, HostedProcessRole, ImageError, ImageMetadata, ImageState, ImageTable,
    OwnedHostedImageCatalog, SpawnTarget,
};

const METADATA: ImageMetadata = ImageMetadata {
    pool_va: 0x1000_0100_0000,
    file_size: 0x2400,
    image_size: 0x5000,
    entry_rva: 0x1000,
    subsystem: 1,
    subsystem_major: 5,
    subsystem_minor: 2,
};

fn admit<const N: usize>(catalog: &mut OwnedHostedImageCatalog<N>) -> SpawnTarget {
    let pi = catalog.admit_dynamic_executable(
        b"ordinary.exe", HostedProcessRole::NativeApplication,
        b"\\SystemRoot\\System32\\ordinary.exe", b"ordinary.exe",
        HostedImageRoot::System32, 64,
    ).unwrap();
    SpawnTarget::from_image(catalog.get_by_pi(pi).unwrap())
}

#[test]
fn native_section_spawn_needs_no_fabricated_file_handle() {
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let target = admit(&mut catalog);
    let mut table = ImageTable::<2>::new();
    let request = table.reserve_spawn_from_native_section(
        &catalog, target, 0, 0x44, METADATA, 0x1fffff, 0x2000,
    ).unwrap();
    let row = table.get(request.slot).unwrap();
    assert_eq!(row.file_handle, 0);
    assert_eq!(row.section_handle, 0x44);
    assert_eq!(row.metadata, METADATA);
    assert_eq!(row.state, ImageState::SpawnReserved);
    assert_eq!(request.target, Some(target));
    assert_eq!(request.creator_pi, 0);
    assert_eq!(request.process_handle_out, 0x2000);
}

#[test]
fn native_section_spawn_rejects_stale_target_before_reserving() {
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let mut target = admit(&mut catalog);
    target.generation += 1;
    let mut table = ImageTable::<1>::new();
    assert_eq!(table.reserve_spawn_from_native_section(
        &catalog, target, 0, 0x44, METADATA, 0x1fffff, 0x2000,
    ), Err(ImageError::InvalidPath));
    assert_eq!(table.active_len(), 0);
}

#[test]
fn same_leaf_and_section_handle_do_not_replace_exact_process_or_bytes() {
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let first = admit(&mut catalog);
    let second = admit(&mut catalog);
    assert_ne!(first, second);
    let mut table = ImageTable::<2>::new();
    let a = table.reserve_spawn_from_native_section(
        &catalog, first, 0, 0x44, METADATA, 0x1fffff, 0x2000,
    ).unwrap();
    table.publish(a, 0x60).unwrap();
    let mut other = METADATA;
    other.pool_va += 0x10000;
    let b = table.reserve_spawn_from_native_section(
        &catalog, second, 0, 0x44, other, 0x1fffff, 0x3000,
    ).unwrap();
    assert_ne!(a.slot, b.slot);
    assert_eq!(a.target, Some(first));
    assert_eq!(b.target, Some(second));
    assert_eq!(table.get(a.slot).unwrap().metadata, METADATA);
    assert_eq!(table.get(b.slot).unwrap().metadata, other);
}

#[test]
fn native_section_spawn_validates_inputs_before_mutation() {
    let mut catalog = OwnedHostedImageCatalog::<1>::new();
    let target = admit(&mut catalog);
    let mut table = ImageTable::<1>::new();
    for (section, out) in [(0, 0x2000), (0x44, 0)] {
        assert_eq!(table.reserve_spawn_from_native_section(
            &catalog, target, 0, section, METADATA, 0x1fffff, out,
        ), Err(ImageError::InvalidHandle));
        assert_eq!(table.active_len(), 0);
    }
    let mut invalid = METADATA;
    invalid.pool_va = 0;
    assert_eq!(table.reserve_spawn_from_native_section(
        &catalog, target, 0, 0x44, invalid, 0x1fffff, 0x2000,
    ), Err(ImageError::InvalidMetadata));
    assert_eq!(table.active_len(), 0);
}

#[test]
fn unentered_native_reservation_discards_only_its_exact_slot() {
    let mut catalog = OwnedHostedImageCatalog::<1>::new();
    let target = admit(&mut catalog);
    let mut table = ImageTable::<1>::new();
    let request = table.reserve_spawn_from_native_section(
        &catalog, target, 0, 0x44, METADATA, 0x1fffff, 0x2000,
    ).unwrap();
    let mut stale = request;
    stale.target.as_mut().unwrap().generation += 1;
    assert_eq!(table.discard_native_section_spawn(stale), Err(ImageError::InvalidState));
    assert_eq!(table.active_len(), 1);
    table.discard_native_section_spawn(request).unwrap();
    assert_eq!(table.active_len(), 0);
    assert_eq!(table.discard_native_section_spawn(request), Err(ImageError::InvalidState));
}

#[test]
fn pe_subsystem_selects_generic_observation_not_creator_or_filename() {
    assert_eq!(HostedProcessRole::for_image_subsystem(1), Some(HostedProcessRole::NativeApplication));
    for subsystem in [2, 3] {
        assert_eq!(HostedProcessRole::for_image_subsystem(subsystem), Some(HostedProcessRole::Application));
    }
    assert_eq!(HostedProcessRole::for_image_subsystem(0), None);
    assert!(HostedProcessRole::Application.uses_win32_client_gdi());
    assert!(!HostedProcessRole::NativeApplication.uses_win32_client_gdi());
    assert!(!HostedProcessRole::Application.is_noninteractive_service_class());
}
