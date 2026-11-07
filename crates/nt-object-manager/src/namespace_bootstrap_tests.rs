use crate::ObjectManager;
use crate::{session_namespace_ownership, SessionNamespaceOwnership};
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
fn global_named_notification_event_opens_in_distinct_client_tables() {
    use crate::{ClientKind, EventBody, ObjectBody, ObjectTypeDef};
    use nt_types::{AccessMask, AccessMode, GenericMapping, ObjAttrFlags};
    use nt_types::rights::event as ev;

    let mut manager = bootstrapped();
    let base = manager.lookup_path(&path("\\BaseNamedObjects"), CI).unwrap();
    manager.create_symbolic_link(&base, &UnicodeString::from_str("Global"),
        path("\\BaseNamedObjects"), true).unwrap();
    let event_type = manager.register_type(ObjectTypeDef {
        name: "Event", valid_access: ev::ALL_ACCESS,
        generic_mapping: GenericMapping {
            generic_read: AccessMask::STANDARD_RIGHTS_READ | AccessMask::SYNCHRONIZE | ev::QUERY_STATE,
            generic_write: AccessMask::STANDARD_RIGHTS_WRITE | AccessMask::SYNCHRONIZE | ev::MODIFY_STATE,
            generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE | AccessMask::SYNCHRONIZE,
            generic_all: ev::ALL_ACCESS,
        },
        delete: None,
    }).unwrap();
    let event = manager.create_named_object(event_type,
        ObjectBody::Event(EventBody { signaled: false, manual_reset: true }),
        &base, &UnicodeString::from_str("PnPReady"), true).unwrap();

    let creator = manager.register_client(ClientKind::NativeUser, AccessMode::UserMode);
    let opener = manager.register_client(ClientKind::NativeUser, AccessMode::UserMode);
    let first = manager.open(creator, &event, AccessMask::SYNCHRONIZE,
        ObjAttrFlags::empty()).unwrap();
    let alias = manager.lookup_path(&path("\\BaseNamedObjects\\Global\\PnPReady"), CI).unwrap();
    assert_eq!(alias.id(), event.id());
    let second = manager.open(opener, &alias, AccessMask::SYNCHRONIZE,
        ObjAttrFlags::empty()).unwrap();
    let opened = manager.reference_by_handle(opener, second, Some(event_type),
        AccessMask::SYNCHRONIZE).unwrap();
    assert_eq!(opened.id(), manager.reference_by_handle(creator, first,
        Some(event_type), AccessMask::SYNCHRONIZE).unwrap().id());
    opened.with_body(|body| assert!(matches!(body, ObjectBody::Event(state)
        if state.manual_reset && !state.signaled)));
    event.with_body_mut(|body| match body {
        ObjectBody::Event(state) => state.signaled = true,
        _ => panic!("named object type changed"),
    });
    opened.with_body(|body| assert!(matches!(body, ObjectBody::Event(state)
        if state.manual_reset && state.signaled)));
}

#[test]
fn smss_reserves_bootstrap_session_zero_before_numbered_sessions() {
    // Pinned LiberNT SMSS calls SystemSessionCreate/Detach to reserve ID 0
    // before it launches the first GUI session. The kernel already owns this
    // namespace, including the BaseNamedObjects link.
    let mut manager = bootstrapped();
    let session_zero = manager.lookup_path(&path("\\Sessions\\0"), CI).unwrap().id();
    let bno = manager.lookup_link(&path("\\Sessions\\0\\BaseNamedObjects"), CI).unwrap().id();
    assert_eq!(session_namespace_ownership(0), SessionNamespaceOwnership::Bootstrap);
    assert_eq!(manager.lookup_path(&path("\\Sessions\\0"), CI).unwrap().id(), session_zero);
    assert_eq!(manager.lookup_link(&path("\\Sessions\\0\\BaseNamedObjects"), CI).unwrap().id(), bno);
    assert_eq!(session_namespace_ownership(1), SessionNamespaceOwnership::Numbered);
    let (session_one, windows_one, bno_one) = manager.create_session_namespace(1).unwrap();
    assert_eq!(manager.lookup_path(&path("\\Sessions\\1"), CI).unwrap().id(), session_one);
    assert_eq!(manager.lookup_path(&path("\\Sessions\\1\\Windows"), CI).unwrap().id(), windows_one);
    assert_eq!(manager.lookup_path(&path("\\Sessions\\1\\BaseNamedObjects"), CI).unwrap().id(), bno_one,
        "new GUI session needs the named-object parent before win32k creates its desktop-switch event");
    assert_eq!(manager.lookup_path(&path("\\Sessions\\0"), CI).unwrap().id(), session_zero);
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
