//! A hosted driver must resolve a registered interface to the instance key that owns its
//! `Device Parameters` child. A link's spelling alone is never proof of a live registration.

use nt_io_manager::{DeviceId, HostedDomainId, HostedDomainIdentity};
use nt_io_manager::hosted_interface_registry::{
    HostedInterfaceRegistration, resolve_interface_instance_key,
    revalidate_interface_registration_revision,
};
use nt_status::NtStatus;

const GUID: &str = "{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}";
const LINK: &str = r"\??\PCI#VEN_1234&DEV_5678#0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}\Disk0";
const KEY: &str = r"\Registry\Machine\System\CurrentControlSet\Control\DeviceClasses\{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}\##?#PCI#VEN_1234&DEV_5678#0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}\#Disk0";

fn owner() -> HostedDomainIdentity {
    HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 0x1_0000_0007 }
}

fn registration() -> HostedInterfaceRegistration {
    HostedInterfaceRegistration {
        owner: owner(),
        pdo: DeviceId(0x2_0000_0005),
        devnode_generation: 41,
        instance_path: r"PCI\VEN_1234&DEV_5678\0".into(),
        class_guid: GUID.into(),
        reference: "Disk0".into(),
        symbolic_link: LINK.into(),
    }
}

#[test]
fn exact_registered_link_resolves_to_its_canonical_instance_key_for_another_driver() {
    let registered = registration();
    let caller = HostedDomainIdentity { domain_id: HostedDomainId(8), cookie: 0x1_0000_0008 };
    assert_ne!(caller, registered.owner);
    assert_eq!(
        resolve_interface_instance_key(
            &[registered.clone()],
            &LINK.to_ascii_lowercase(),
            |owner, pdo, generation| {
                assert_ne!(caller, owner);
                assert_eq!((owner, pdo, generation), (registered.owner, registered.pdo, 41));
                true
            },
        ),
        Ok(KEY.into()),
    );
}

#[test]
fn stale_generation_or_unknown_link_cannot_authorize_registry_key_open() {
    let registered = registration();
    assert_eq!(
        resolve_interface_instance_key(&[registered.clone()], LINK, |_, _, generation| {
            generation == 42
        }),
        Err(NtStatus::INVALID_DEVICE_REQUEST),
    );
    assert_eq!(
        resolve_interface_instance_key(
            &[registered],
            r"\??\PCI#VEN_1234&DEV_5678#0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}\Disk1",
            |_, _, _| true,
        ),
        Err(NtStatus::OBJECT_NAME_NOT_FOUND),
    );
}

#[test]
fn revision_retry_requires_the_same_mount_and_exact_live_pdo_devnode_and_path() {
    let registration = registration();
    let check = |mount, generation, path: &str, live: bool| {
        revalidate_interface_registration_revision(
            &registration, KEY, 7, mount, 21, generation, path,
            |owner, pdo, devnode_generation| {
                assert_eq!((owner, pdo, devnode_generation),
                    (registration.owner, registration.pdo, registration.devnode_generation));
                live
            },
        )
    };
    assert_eq!(check(7, 22, &registration.instance_path, true), Ok(()));
    assert_eq!(check(8, 22, &registration.instance_path, true), Err(NtStatus::DEVICE_NOT_READY));
    assert_eq!(check(7, 21, &registration.instance_path, true), Err(NtStatus::DEVICE_BUSY));
    assert_eq!(check(7, 22, &registration.instance_path, false), Err(NtStatus::INVALID_DEVICE_REQUEST));
    assert_eq!(check(7, 22, r"PCI\VEN_1234&DEV_5678\1", true),
        Err(NtStatus::INVALID_DEVICE_REQUEST));
    assert_eq!(
        revalidate_interface_registration_revision(
            &registration, r"\Registry\Machine\System\CurrentControlSet\Control\DeviceClasses\Other",
            7, 7, 21, 22, &registration.instance_path, |_, _, _| true,
        ),
        Err(NtStatus::INVALID_DEVICE_REQUEST),
    );
}
