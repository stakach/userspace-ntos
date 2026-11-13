use nt_object_manager::{ClientKind, ObjectManager};
use nt_status::NtStatus;
use nt_types::{rights, AccessMode, ObjAttrFlags, UnicodeString};

fn session_one() -> (ObjectManager, nt_types::ClientId) {
    let mut objects = ObjectManager::new();
    objects.bootstrap_namespace().unwrap();
    objects.create_session_namespace(1).unwrap();
    let client = objects.register_client(ClientKind::ExecutiveService, AccessMode::KernelMode);
    (objects, client)
}

#[test]
fn kernel_handle_directory_creation_requires_the_original_parent_case() {
    let (mut objects, client) = session_one();
    let lowercase = UnicodeString::from_str("\\sessions\\1\\windows\\WindowStations");
    assert_eq!(
        objects.create_directory_handle(
            client, None, &lowercase, rights::directory::ALL_ACCESS,
            ObjAttrFlags::KERNEL_HANDLE,
        ),
        Err(NtStatus::OBJECT_PATH_NOT_FOUND),
    );

    let exact = UnicodeString::from_str("\\Sessions\\1\\Windows\\WindowStations");
    assert!(objects.create_directory_handle(
        client, None, &exact, rights::directory::ALL_ACCESS,
        ObjAttrFlags::KERNEL_HANDLE,
    ).unwrap().created);

    // OPEN_IF cannot reuse a differently cased leaf for a case-sensitive request.
    let other_leaf = UnicodeString::from_str("\\Sessions\\1\\Windows\\windowstations");
    assert!(objects.create_directory_handle(
        client, None, &other_leaf, rights::directory::ALL_ACCESS,
        ObjAttrFlags::KERNEL_HANDLE | ObjAttrFlags::OPEN_IF,
    ).unwrap().created);
}

#[test]
fn kernel_handle_root_relative_creation_uses_the_root_object_identity() {
    let (mut objects, client) = session_one();
    let parent = objects.open_directory_handle(
        client, None, &UnicodeString::from_str("\\Sessions\\1\\Windows"),
        rights::directory::ALL_ACCESS, ObjAttrFlags::KERNEL_HANDLE,
    ).unwrap();
    let leaf = UnicodeString::from_str("WindowStations");
    assert!(objects.create_directory_handle(
        client, Some(parent), &leaf, rights::directory::ALL_ACCESS,
        ObjAttrFlags::KERNEL_HANDLE,
    ).unwrap().created);
    assert!(objects.create_directory_handle(
        client, Some(parent), &UnicodeString::from_str("windowstations"),
        rights::directory::ALL_ACCESS, ObjAttrFlags::KERNEL_HANDLE | ObjAttrFlags::OPEN_IF,
    ).unwrap().created);
}

#[test]
fn native_provider_preserves_input_case_through_canonical_and_local_admission() {
    let source = include_str!("../../../components/ntos-executive/src/exec_directory_object.rs");
    let reserve = source.split("pub(crate) fn reserve_provider_directory_object(")
        .nth(1).expect("provider directory admission").split("pub(crate) fn reserve_native_directory_object_open(")
        .next().unwrap();
    assert!(reserve.contains("captured.original_path[index] = unit as u8;"),
        "the provider upload must retain exact spelling alongside its local lookup key");

    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let capture = handler.split("unsafe fn capture_named_object_attributes(")
        .nth(1).expect("native object name capture").split("unsafe fn read_unicode_string16(")
        .next().unwrap();
    assert!(capture.contains("original_path[index] = unit as u8;"),
        "native capture must retain exact spelling before local folding");

    let security = include_str!("../../../components/ntos-executive/src/exec_directory_security.rs");
    assert!(security.contains("captured.original_path()"));
    assert!(security.contains("self.obj_resolve_authorized_case(parent_path, root, true, case_insensitive, check)?"));
    assert!(security.contains("self.obj_resolve_authorized_case(path, root, true, case_insensitive, check)?"));
    assert!(!security.contains("self.obj_resolve_authorized(parent_path, root, true, check)?"),
        "directory parent admission must use the request's case-sensitivity policy");
    assert!(!security.contains("self.obj_resolve_authorized(path, root, true, check)?"),
        "OPEN_IF must not select a differently cased local leaf");
}
