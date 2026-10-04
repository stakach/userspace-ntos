use nt_exe_image::{
    HostedImageRoot, HostedProcessRole, ImageError, ImageMetadata, ImageTable,
    OwnedHostedImageCatalog, ProcessImageLayout, SpawnTarget,
};

#[test]
fn preferred_native_image_layout_drives_entry_and_exact_rva_bounds() {
    let layout = ProcessImageLayout::checked(0x140000000, 0x5000, 0x12b0).unwrap();
    assert_eq!(layout.base(), 0x140000000);
    assert_eq!(layout.size(), 0x5000);
    assert_eq!(layout.entry_rva(), 0x12b0);
    assert_eq!(layout.entry(), 0x1400012b0);
    assert_eq!(layout.end(), 0x140005000);
    assert_eq!(layout.rva(0x140000000), Some(0));
    assert_eq!(layout.rva(0x140004fff), Some(0x4fff));
    assert_eq!(layout.rva(0x13fffffff), None);
    assert_eq!(layout.rva(0x140005000), None);
    assert_eq!(layout.address_for_rva(0x12b0), Some(layout.entry()));
    assert_eq!(layout.address_for_rva(0x5000), None);
    assert_eq!(layout.address_for_rva(u64::MAX), None);
}

#[test]
fn invalid_or_overflowing_layout_cannot_publish_an_entry_address() {
    for (base, size, entry) in [
        (0, 0x5000, 0x12b0),
        (0x140000000, 0, 0),
        (0x140000000, 0x5000, 0x5000),
        (u64::MAX - 0xfff, 0x2000, 0),
        (u64::MAX - 1, 2, 1),
    ] {
        assert_eq!(
            ProcessImageLayout::checked(base, size, entry),
            Err(ImageError::InvalidMetadata)
        );
    }
    // Placement/protection policy is separate; an RVA of zero is arithmetically valid.
    assert_eq!(
        ProcessImageLayout::checked(0x140000000, 1, 0)
            .unwrap()
            .entry(),
        0x140000000
    );
}

#[test]
fn distinct_process_layouts_do_not_rewrite_shared_section_metadata() {
    let metadata = ImageMetadata {
        pool_va: 0x100001000000,
        file_size: 0x2400,
        image_size: 0x5000,
        entry_rva: 0x12b0,
        subsystem: 1,
        subsystem_major: 5,
        subsystem_minor: 2,
    };
    let mut catalog = OwnedHostedImageCatalog::<2>::new();
    let mut table = ImageTable::<2>::new();
    let mut slots = [0; 2];
    let layouts = [
        ProcessImageLayout::checked(0x140000000, metadata.image_size, metadata.entry_rva).unwrap(),
        ProcessImageLayout::checked(0x180000000, metadata.image_size, metadata.entry_rva).unwrap(),
    ];
    for (index, slot) in slots.iter_mut().enumerate() {
        let pi = catalog
            .admit_dynamic_executable(
                b"ordinary.exe",
                HostedProcessRole::NativeApplication,
                b"\\SystemRoot\\System32\\ordinary.exe",
                b"ordinary.exe",
                HostedImageRoot::System32,
                64,
            )
            .unwrap();
        let target = SpawnTarget::from_image(catalog.get_by_pi(pi).unwrap());
        let request = table
            .reserve_spawn_from_native_section(
                &catalog,
                target,
                0,
                0x44,
                metadata,
                0x1fffff,
                0x2000 + index as u64 * 8,
            )
            .unwrap();
        *slot = request.slot;
        table.publish(request, 0x60 + index as u64 * 4).unwrap();
    }
    assert_ne!(slots[0], slots[1]);
    assert_ne!(layouts[0], layouts[1]);
    for (slot, layout) in slots.into_iter().zip(layouts) {
        assert_eq!(table.get(slot).unwrap().metadata, metadata);
        assert_eq!(layout.entry_rva(), metadata.entry_rva);
        assert_eq!(layout.size(), metadata.image_size);
    }
}
