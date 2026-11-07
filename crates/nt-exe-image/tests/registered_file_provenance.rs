use nt_exe_image::{HostedImageRoot, HostedProcessRole, ImageMetadata, ImageTable,
    OwnedHostedImageCatalog, OwnedHostedProcessImage, ProcessImageSourceEvidence, SpawnTarget};
use nt_memory_manager::{SectionFileIdentity, SectionMountIds};

const META: ImageMetadata = ImageMetadata {
    pool_va: 0x1_0000_0000, file_size: 0x2000, image_size: 0x4000,
    entry_rva: 0x1000, subsystem: 2, subsystem_major: 6, subsystem_minor: 0,
};

fn registered() -> (OwnedHostedImageCatalog<8>, SpawnTarget, SectionFileIdentity,
    SectionFileIdentity, SectionFileIdentity) {
    let mut catalog = OwnedHostedImageCatalog::new();
    let image = OwnedHostedProcessImage::new(3, 6, 1, b"services.exe", b"services.exe",
        HostedProcessRole::ServiceControlManager, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, b"services.exe").unwrap();
    catalog.register(image).unwrap();
    let target = SpawnTarget::from_image(catalog.get_by_pi(3).unwrap());
    let mut mounts = SectionMountIds::new();
    let mount = mounts.allocate().unwrap();
    let other_mount = mounts.allocate().unwrap();
    let exact = SectionFileIdentity { mount, file_id: 700 };
    let other_file = SectionFileIdentity { mount, file_id: 701 };
    let other_mount = SectionFileIdentity { mount: other_mount, file_id: 700 };
    (catalog, target, exact, other_file, other_mount)
}

#[test]
fn exact_registered_file_survives_file_close_in_retained_section_and_process() {
    let (mut catalog, target, exact, _, _) = registered();
    catalog.bind_registered_backing(target, exact).unwrap();
    let observation = catalog.observation_for_backing(exact).unwrap();
    assert_eq!(observation.target(), target);
    let mut files = ImageTable::<2>::new();
    let slot = files.open_with_target(8, b"services.exe", 0x40, META, Some(target)).unwrap();
    files.create_section(8, 0x40, 0x44).unwrap();
    files.close(8, 0x40);
    assert_eq!(files.get(slot).unwrap().target, Some(target));
    let child_pi = catalog.admit_dynamic_executable_observed(b"services.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, Some(observation), 64).unwrap();
    let child = catalog.get_by_pi(child_pi).unwrap();
    assert_eq!(child.observation_target(), Some(target));
    assert_eq!(child.role, HostedProcessRole::Application);
}

#[test]
fn same_leaf_other_file_or_mount_cannot_supply_registered_observation() {
    let (mut catalog, target, exact, other_file, other_mount) = registered();
    catalog.bind_registered_backing(target, exact).unwrap();
    assert_eq!(catalog.observation_for_backing(other_file), None);
    assert_eq!(catalog.observation_for_backing(other_mount), None);
    assert_eq!(catalog.observation_for_backing(SectionFileIdentity {
        file_id: (1 << 63) | exact.file_id, ..exact
    }), None);
    assert_eq!(catalog.observation_for_backing(exact).unwrap().target(), target);
}

#[test]
fn stale_target_and_reused_dynamic_process_identity_do_not_inherit_binding() {
    let (mut catalog, target, exact, _, _) = registered();
    let stale = SpawnTarget { generation: target.generation + 1, ..target };
    assert!(catalog.bind_registered_backing(stale, exact).is_err());
    catalog.bind_registered_backing(target, exact).unwrap();
    let observed = catalog.observation_for_backing(exact).unwrap();
    let first_pi = catalog.admit_dynamic_executable_observed(b"services.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, Some(observed), 64).unwrap();
    let first = SpawnTarget::from_image(catalog.get_by_pi(first_pi).unwrap());
    catalog.retire_dynamic_target(first).unwrap();
    let replacement_pi = catalog.admit_dynamic_executable_observed(b"services.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, None, 64).unwrap();
    assert_eq!(replacement_pi, first_pi);
    assert_ne!(SpawnTarget::from_image(catalog.get_by_pi(replacement_pi).unwrap()), first);
    assert_eq!(catalog.get_by_pi(replacement_pi).unwrap().observation_target(), None);
}

#[test]
fn retained_process_source_keeps_exact_file_and_observation_across_registration_reuse() {
    let (mut catalog, registered_target, exact_file, other_file, _) = registered();
    catalog.bind_registered_backing(registered_target, exact_file).unwrap();
    catalog.bind_registered_launch_policy(registered_target,
        HostedProcessRole::NativeSession).unwrap();
    let observed = catalog.observation_for_backing(exact_file).unwrap();
    let first_pi = catalog.admit_dynamic_executable_observed(b"services.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, Some(observed), 64).unwrap();
    let first_image = catalog.get_by_pi(first_pi).unwrap();
    let first_target = SpawnTarget::from_image(first_image);
    let source = ProcessImageSourceEvidence::capture(first_image, exact_file, Some(observed)).unwrap();
    assert_eq!(source.file(), exact_file);
    assert_eq!(source.observation(), Some(registered_target));
    assert!(source.matches_target(first_target));
    assert_eq!(source.registered_target_for_role(&catalog), Some(registered_target));
    let wrong_file = ProcessImageSourceEvidence::capture(first_image, other_file, Some(observed)).unwrap();
    assert_eq!(wrong_file.registered_target_for_role(&catalog), None,
        "a different File cannot transfer the registered execution role");

    catalog.retire_dynamic_target(first_target).unwrap();
    let replacement_pi = catalog.admit_dynamic_executable_observed(b"services.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, None, 64).unwrap();
    let replacement = SpawnTarget::from_image(catalog.get_by_pi(replacement_pi).unwrap());
    assert_eq!(replacement_pi, first_pi);
    assert!(!source.matches_target(replacement));
    assert_eq!(source.observation(), Some(registered_target));
    assert_eq!(source.registered_target_for_role(&catalog), None);
    assert!(ProcessImageSourceEvidence::capture(catalog.get_by_pi(replacement_pi).unwrap(),
        exact_file, Some(observed)).is_err(), "old generation cannot attach to the replacement");
}

#[test]
fn routed_section_keeps_io_file_but_role_requires_authenticated_physical_alias() {
    let (mut catalog, registered_target, physical_file, wrong_physical, routed_file) = registered();
    catalog.bind_registered_backing(registered_target, physical_file).unwrap();
    catalog.bind_registered_launch_policy(registered_target,
        HostedProcessRole::NativeSession).unwrap();
    let observed = catalog.observation_for_backing(physical_file).unwrap();
    let pi = catalog.admit_dynamic_executable_observed(b"services.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\System32\\services.exe",
        b"services.exe", HostedImageRoot::System32, Some(observed), 64).unwrap();
    let image = catalog.get_by_pi(pi).unwrap();
    assert_ne!(routed_file.mount, physical_file.mount);
    let exact = ProcessImageSourceEvidence::capture_with_registered_file(
        image, routed_file, Some(physical_file), Some(observed)).unwrap();
    assert_eq!(exact.file(), routed_file, "ordinary Section lineage retains routed I/O identity");
    assert_eq!(exact.registered_file(), Some(physical_file));
    assert_eq!(exact.registered_target_for_role(&catalog), Some(registered_target));
    for alias in [None, Some(wrong_physical), Some(routed_file)] {
        let source = ProcessImageSourceEvidence::capture_with_registered_file(
            image, routed_file, alias, Some(observed)).unwrap();
        assert_eq!(source.registered_target_for_role(&catalog), None);
    }
    let target = SpawnTarget::from_image(image);
    catalog.retire_dynamic_target(target).unwrap();
    assert_eq!(exact.registered_target_for_role(&catalog), None);
}
