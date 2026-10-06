use crate::ObjectManager;
use nt_status::NtStatus;
use nt_types::{CaseSensitivity, NtPath, UnicodeString};

const CI: CaseSensitivity = CaseSensitivity::CaseInsensitive;

fn path(name: &str) -> NtPath {
    NtPath::parse_str(name).unwrap()
}

fn bootstrapped() -> ObjectManager {
    let mut manager = ObjectManager::new();
    manager.bootstrap_namespace().unwrap();
    manager
}

#[test]
fn kernel_bootstrap_does_not_publish_basesrv_owned_links() {
    // ReactOS subsystems/win/basesrv/init.c:584-623 creates these via real NtCreateSymbolicLinkObject.
    let manager = bootstrapped();
    for name in [
        "\\BaseNamedObjects\\Global",
        "\\BaseNamedObjects\\Local",
        "\\BaseNamedObjects\\Session",
    ] {
        assert_eq!(
            manager.lookup_link(&path(name), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND,
            "USER-owned name {name} must remain available for its creator"
        );
    }
}

#[test]
fn real_basesrv_creator_publishes_links_and_strict_duplicate_is_preserved() {
    let mut manager = bootstrapped();
    let parent = manager.lookup_path(&path("\\BaseNamedObjects"), CI).unwrap();
    for (leaf, target) in [
        ("Global", "\\BaseNamedObjects"),
        ("Local", "\\BaseNamedObjects"),
        ("Session", "\\Sessions\\BnoLinks"),
    ] {
        let name = UnicodeString::from_str(leaf);
        let created = manager
            .create_symbolic_link(&parent, &name, path(target), true)
            .unwrap();
        assert!(created.is_permanent());
        let full_name = alloc::format!("\\BaseNamedObjects\\{leaf}");
        assert_eq!(manager.lookup_link(&path(&full_name), CI).unwrap().id(), created.id());
        assert_eq!(manager.query_symbolic_link(&created).unwrap(), UnicodeString::from_str(target));
        assert_eq!(
            manager.lookup_path(&path(&full_name), CI).unwrap().id(),
            manager.lookup_path(&path(target), CI).unwrap().id()
        );
        assert_eq!(
            manager.create_symbolic_link(&parent, &name, path(target), true).unwrap_err(),
            NtStatus::OBJECT_NAME_COLLISION
        );
        assert_eq!(manager.lookup_link(&path(&full_name), CI).unwrap().id(), created.id());
    }
}

#[test]
fn user_owned_link_removal_does_not_remove_existing_core_directories() {
    let mut manager = bootstrapped();
    manager.bootstrap_namespace().unwrap();
    for name in [
        "\\", "\\??", "\\Device", "\\Global??", "\\ObjectTypes", "\\Driver",
        "\\FileSystem", "\\FileSystem\\Filters", "\\Security", "\\KnownDlls",
        "\\BaseNamedObjects", "\\BaseNamedObjects\\Restricted", "\\Sessions",
        "\\Sessions\\BnoLinks", "\\Sessions\\0", "\\Windows", "\\Windows\\WindowStations",
    ] {
        let directory = manager.lookup_path(&path(name), CI).unwrap();
        assert!(directory.is_permanent(), "{name}");
    }
    assert_eq!(
        manager.lookup_path(&path("\\DosDevices"), CI).unwrap().id(),
        manager.lookup_path(&path("\\??"), CI).unwrap().id()
    );
}
