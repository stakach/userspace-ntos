//! A mounted File device has a logical mount distinct from its physical FAT source.

#[path = "../../../components/ntos-executive/src/exec_volume_mount_pair.rs"]
mod exec_volume_mount_pair;

use exec_volume_mount_pair::ExecVolumeDevice;
use nt_memory_manager::{SectionMountBindings, SectionMountIds};

#[test]
fn exact_physical_and_logical_mount_pair_admits_only_its_live_device() {
    let mut ids = SectionMountIds::new();
    let physical = ids.allocate().unwrap();
    let logical = ids.allocate().unwrap();
    let stale_physical = ids.allocate().unwrap();
    let stale_logical = ids.allocate().unwrap();
    assert_ne!(physical, logical);

    let device = 0x0100_0000_0041u64;
    let replacement = 0x0200_0000_0041u64;
    let published = ExecVolumeDevice { physical_mount: physical, logical_mount: logical, device_id: device };
    let mut bindings = SectionMountBindings::new();
    bindings.reserve(logical).unwrap();
    bindings.publish(logical, device).unwrap();

    assert_eq!(published.exact_device(physical, bindings.lookup(device)), Some(device),
        "a live logical binding must serve its distinct physical FAT mount");
    assert_eq!(published.exact_device(stale_physical, bindings.lookup(device)), None);
    assert_eq!(published.exact_device(physical, Some(stale_logical)), None);
    assert_eq!(bindings.retire(device), Some(logical));
    assert_eq!(published.exact_device(physical, bindings.lookup(device)), None);

    bindings.reserve(stale_logical).unwrap();
    bindings.publish(stale_logical, replacement).unwrap();
    assert_eq!(published.exact_device(physical, bindings.lookup(replacement)), None,
        "reused numeric device slot has a different generation and logical binding");
    assert_eq!(published.exact_device(physical, bindings.lookup(device)), None);
}

#[test]
fn production_publication_checks_both_mount_owners_and_keeps_file_aliasing() {
    let source = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
    let selector = source.split("fn exec_volume_device_for_mount(").nth(1)
        .expect("exact executive mounted File selector")
        .split("\n}").next().unwrap();
    assert!(selector.contains("mount_id_for_live_device(device_id)"),
        "registered Device must still be checked against the live binding");
    assert!(selector.contains("exact_device(physical"),
        "physical and logical identities must be compared to their own owners");
    let publication = source.split("pub(crate) fn register_mounted_volume(").nth(1).unwrap();
    assert!(publication.contains("physical_mount") && publication.contains("logical_mount")
        && publication.contains("EXEC_VOLUME_DEVICE"),
        "publication must retain both identities and the device id");
    assert!(source.contains("MOUNT_BINDINGS)).physical_file_alias("),
        "routed File-to-physical section aliasing remains generation-bound");
}
